// Package guard provides anti-detection mechanisms.
//
// Cloudflare Backoff: Detects Cloudflare challenge responses and applies
// progressive cooldown instead of a long fixed suspension. When an upstream
// account triggers a Cloudflare JS challenge, the system marks it with a
// short exponential backoff so other accounts can be tried immediately,
// and the challenged account recovers after a brief waiting period.
package guard

import (
	"math"
	"net/http"
	"strings"
	"time"
)

// CloudflareBackoffConfig defines the progressive backoff parameters.
type CloudflareBackoffConfig struct {
	// Enabled enables Cloudflare challenge detection and backoff.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// InitialCooldown is the first cooldown duration.
	InitialCooldown time.Duration `yaml:"initial_cooldown" json:"initial_cooldown"`

	// MaxCooldown is the maximum cooldown duration.
	MaxCooldown time.Duration `yaml:"max_cooldown" json:"max_cooldown"`

	// BackoffFactor is the multiplier applied at each level (default 3).
	BackoffFactor int `yaml:"backoff_factor" json:"backoff_factor"`
}

// DefaultCloudflareBackoffConfig returns sensible defaults.
func DefaultCloudflareBackoffConfig() CloudflareBackoffConfig {
	return CloudflareBackoffConfig{
		Enabled:         true,
		InitialCooldown: 10 * time.Second,
		MaxCooldown:     120 * time.Second,
		BackoffFactor:   3,
	}
}

// IsCloudflareChallenge checks whether an error response indicates a
// Cloudflare challenge/block page.
func IsCloudflareChallenge(err error) bool {
	if err == nil {
		return false
	}
	return isCloudflareChallengeString(err.Error())
}

// IsCloudflareChallengeResponse checks whether an HTTP response body
// indicates a Cloudflare challenge page.
func IsCloudflareChallengeResponse(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == 403 || resp.StatusCode == 503 {
		bodyStr := string(body)
		return isCloudflareChallengeString(bodyStr)
	}
	return false
}

func isCloudflareChallengeString(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(lower, "challenge-platform") ||
		strings.Contains(lower, "cf-mitigated") ||
		strings.Contains(lower, "just a moment") ||
		(strings.Contains(lower, "cloudflare") && strings.Contains(lower, "<html"))
}

// IsCloudflareChallengeCode checks if a given status code and body
// indicate a Cloudflare challenge.
func IsCloudflareChallengeCode(statusCode int, body []byte) bool {
	if statusCode == 403 || statusCode == 503 {
		return isCloudflareChallengeString(string(body))
	}
	return false
}

// CloudflareBackoff calculates the cooldown duration for a given
// backoff level using exponential progression.
//
// Level 0: InitialCooldown
// Level 1: InitialCooldown * BackoffFactor
// Level 2: InitialCooldown * BackoffFactor^2
// ...
// Cap: MaxCooldown
func CloudflareBackoff(level int, cfg *CloudflareBackoffConfig) time.Duration {
	if cfg == nil {
		cfg = &CloudflareBackoffConfig{
			InitialCooldown: 10 * time.Second,
			MaxCooldown:     120 * time.Second,
			BackoffFactor:   3,
		}
	}
	if !cfg.Enabled {
		return 0
	}
	if level < 0 {
		level = 0
	}
	factor := cfg.BackoffFactor
	if factor <= 1 {
		factor = 3
	}
	d := time.Duration(float64(cfg.InitialCooldown) * math.Pow(float64(factor), float64(level)))
	if d > cfg.MaxCooldown {
		d = cfg.MaxCooldown
	}
	if d < cfg.InitialCooldown {
		d = cfg.InitialCooldown
	}
	return d
}
