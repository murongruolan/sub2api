package service

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/guard"
)

const (
	openAIAccountStateUpdateTimeout    = 5 * time.Second
	openAIOAuth429FallbackCooldown     = 5 * time.Second
	openAIStopSchedulingBridgeCooldown = 2 * time.Minute
	openAIOAuth429StormWindow          = 10 * time.Second
	openAIOAuth429StormThreshold       = 20
	openAIOAuth429StormMaxAccountSwitches = 1

	// openAICFChallengeCooldown is the base cooldown for Cloudflare challenges.
	// Shorter than 429 cooldowns to allow quick retry with other accounts.
	openAICFChallengeInitialCooldown = 10 * time.Second
	openAICFChallengeMaxCooldown     = 120 * time.Second
	openAICFChallengeBackoffFactor   = 3
)

// openAICFBackoffLevels tracks progressive backoff levels per account for
// Cloudflare challenge cooldowns. Level 0 = first challenge, level 1 = second, etc.
var openAICFBackoffLevels sync.Map

func openAICFBackoffLevel(accountID int64) int {
	v, ok := openAICFBackoffLevels.Load(accountID)
	if !ok {
		return 0
	}
	level, _ := v.(int)
	return level
}

func setOpenAICFBackoffLevel(accountID int64, level int) {
	openAICFBackoffLevels.Store(accountID, level)
}

func resetOpenAICFBackoffLevel(accountID int64) {
	openAICFBackoffLevels.Delete(accountID)
}

func openAIAccountStateContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(base, openAIAccountStateUpdateTimeout)
}

func isOpenAIOAuthAccount(account *Account) bool {
	return account != nil && account.Platform == PlatformOpenAI && account.Type == AccountTypeOAuth
}

func isOpenAIAccount(account *Account) bool {
	return account != nil && account.Platform == PlatformOpenAI
}

func (s *OpenAIGatewayService) handleOpenAIAccountUpstreamError(ctx context.Context, account *Account, statusCode int, headers http.Header, responseBody []byte, requestedModel ...string) bool {
	stateCtx, cancel := openAIAccountStateContext(ctx)
	defer cancel()

	if statusCode == http.StatusTooManyRequests {
		s.markOpenAIOAuth429RateLimited(stateCtx, account, headers, responseBody)
	}
	if s == nil || account == nil || s.rateLimitService == nil {
		return false
	}
	if len(requestedModel) > 0 && s.rateLimitService.HandleUpstreamModelNotFound(stateCtx, account, requestedModel[0], statusCode, responseBody) {
		return true
	}

	// Cloudflare challenge detection with progressive backoff.
	// Unlike 429/other errors that use a fixed 2-minute cooldown, CF challenges
	// get an exponentially-increasing backoff (10s, 30s, 90s, 120s max) so the
	// account can be retried quickly while still avoiding hammering.
	if guard.IsCloudflareChallengeCode(statusCode, responseBody) {
		s.markOpenAICloudflareChallenge(stateCtx, account)
		// Return false: we want the conductor to try another account, not
		// permanently disable this one after a CF challenge.
		return false
	}

	shouldDisable := s.rateLimitService.HandleUpstreamError(stateCtx, account, statusCode, headers, responseBody)
	if shouldDisable {
		s.BlockAccountScheduling(account, time.Time{}, "upstream_disable")
	}
	return shouldDisable
}

// markOpenAICloudflareChallenge applies a progressive exponential backoff for
// Cloudflare challenge responses. The account is temporarily unschedulable but
// recovers quickly so other accounts can be tried immediately.
func (s *OpenAIGatewayService) markOpenAICloudflareChallenge(ctx context.Context, account *Account) {
	if s == nil || !isOpenAIOAuthAccount(account) {
		return
	}
	level := openAICFBackoffLevel(account.ID)
	cfg := guard.CloudflareBackoffConfig{
		Enabled:         true,
		InitialCooldown: openAICFChallengeInitialCooldown,
		MaxCooldown:     openAICFChallengeMaxCooldown,
		BackoffFactor:   openAICFChallengeBackoffFactor,
	}
	cooldown := guard.CloudflareBackoff(level, &cfg)
	if cooldown > 0 {
		setOpenAICFBackoffLevel(account.ID, level+1)
		s.BlockAccountScheduling(account, time.Now().Add(cooldown), "cloudflare_challenge")
	}
}

func (s *OpenAIGatewayService) markOpenAIOAuth429RateLimited(ctx context.Context, account *Account, headers http.Header, responseBody []byte) {
	if s == nil || !isOpenAIOAuthAccount(account) {
		return
	}
	s.recordOpenAIOAuth429()

	cooldownUntil := time.Now().Add(openAIOAuth429FallbackCooldown)
	if s.rateLimitService != nil {
		if resetAt := s.rateLimitService.calculateOpenAI429ResetTime(headers); resetAt != nil && resetAt.After(time.Now()) {
			cooldownUntil = *resetAt
		} else if resetUnix := parseOpenAIRateLimitResetTime(responseBody); resetUnix != nil {
			if resetAt := time.Unix(*resetUnix, 0); resetAt.After(time.Now()) {
				cooldownUntil = resetAt
			}
		} else if cooldown, ok := s.rateLimitService.get429FallbackCooldown(ctx, account); ok && cooldown > 0 {
			cooldownUntil = time.Now().Add(cooldown)
		}
	}
	s.BlockAccountScheduling(account, cooldownUntil, "429")
}

func (s *OpenAIGatewayService) BlockAccountScheduling(account *Account, until time.Time, reason string) {
	if s == nil || !isOpenAIAccount(account) {
		return
	}
	now := time.Now()
	blockUntil := until
	if blockUntil.IsZero() || !blockUntil.After(now) {
		blockUntil = now.Add(openAIStopSchedulingBridgeCooldown)
	}

	for {
		current, loaded := s.openaiAccountRuntimeBlockUntil.Load(account.ID)
		if !loaded {
			actual, stored := s.openaiAccountRuntimeBlockUntil.LoadOrStore(account.ID, blockUntil)
			if !stored {
				return
			}
			current = actual
		}

		currentUntil, ok := current.(time.Time)
		if !ok || currentUntil.IsZero() {
			if s.openaiAccountRuntimeBlockUntil.CompareAndSwap(account.ID, current, blockUntil) {
				return
			}
			continue
		}
		if currentUntil.After(blockUntil) {
			return
		}
		if s.openaiAccountRuntimeBlockUntil.CompareAndSwap(account.ID, current, blockUntil) {
			return
		}
	}
}

func (s *OpenAIGatewayService) ClearAccountSchedulingBlock(accountID int64) {
	if s == nil || accountID <= 0 {
		return
	}
	s.openaiAccountRuntimeBlockUntil.Delete(accountID)
}

func (s *OpenAIGatewayService) isOpenAIAccountRuntimeBlocked(account *Account) bool {
	if s == nil || !isOpenAIAccount(account) {
		return false
	}
	value, ok := s.openaiAccountRuntimeBlockUntil.Load(account.ID)
	if !ok {
		return false
	}
	cooldownUntil, ok := value.(time.Time)
	if !ok || cooldownUntil.IsZero() {
		s.openaiAccountRuntimeBlockUntil.Delete(account.ID)
		return false
	}
	if time.Now().Before(cooldownUntil) {
		return true
	}
	s.openaiAccountRuntimeBlockUntil.Delete(account.ID)
	return false
}

func (s *OpenAIGatewayService) recordOpenAIOAuth429() {
	if s == nil {
		return
	}
	now := time.Now()
	windowStart := s.openaiOAuth429WindowStartUnixNano.Load()
	if windowStart == 0 || now.Sub(time.Unix(0, windowStart)) >= openAIOAuth429StormWindow {
		if s.openaiOAuth429WindowStartUnixNano.CompareAndSwap(windowStart, now.UnixNano()) {
			s.openaiOAuth429WindowCount.Store(1)
			return
		}
	}
	s.openaiOAuth429WindowCount.Add(1)
}

func (s *OpenAIGatewayService) isOpenAIOAuth429Storm() bool {
	if s == nil {
		return false
	}
	windowStart := s.openaiOAuth429WindowStartUnixNano.Load()
	if windowStart == 0 || time.Since(time.Unix(0, windowStart)) >= openAIOAuth429StormWindow {
		return false
	}
	return s.openaiOAuth429WindowCount.Load() >= openAIOAuth429StormThreshold
}

func (s *OpenAIGatewayService) ShouldStopOpenAIOAuth429Failover(account *Account, statusCode int, failedSwitches int) bool {
	if statusCode != http.StatusTooManyRequests || failedSwitches < openAIOAuth429StormMaxAccountSwitches {
		return false
	}
	if !isOpenAIOAuthAccount(account) {
		return false
	}
	return s.isOpenAIOAuth429Storm()
}
