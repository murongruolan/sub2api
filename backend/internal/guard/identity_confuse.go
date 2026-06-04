// Package guard provides anti-detection mechanisms for upstream API requests.
//
// Identity Confuse: Obfuscates per-account session identity fields so that
// different upstream accounts serving the same logical session present
// different identity values to chatgpt.com. This prevents session poisoning
// where a flagged session would cause all accounts using it to be banned.
//
// Design:
//   - SHA256-based deterministic obfuscation: same accountID + kind + value
//     always produces the same obfuscated value across requests.
//   - Different accountIDs produce completely different obfuscated values
//     even when the original value is the same (session isolation).
//   - Response payload is restored before returning to the downstream client
//     so the obfuscation is transparent.
package guard

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ConfuseKey returns a deterministic obfuscated key for a given account,
// kind, and value. The same inputs always produce the same output.
//
// Examples:
//
//	ConfuseKey(1, "prompt-cache", "sess_abc") → "a1b2c3..."
//	ConfuseKey(2, "prompt-cache", "sess_abc") → "d4e5f6..."
//	ConfuseKey(1, "session", "sess_abc")      → "g7h8i9..."
func ConfuseKey(accountID int64, kind string, value string) string {
	name := fmt.Sprintf("sub2api:identity-confuse:%s:account_%d:%s",
		strings.TrimSpace(kind),
		accountID,
		strings.TrimSpace(value),
	)
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars
}

// ConfuseState tracks the original→obfuscated mapping for a single request,
// allowing the response to be restored transparently.
type ConfuseState struct {
	mu sync.Mutex

	AccountID int64

	// Body field obfuscation
	PromptCacheKey string // obfuscated value sent upstream
	origCacheKey   string

	// Turn ID mapping (obfuscated → original)
	origTurnIDs map[string]string
}

func newConfuseState(accountID int64) *ConfuseState {
	return &ConfuseState{
		AccountID:   accountID,
		origTurnIDs: make(map[string]string),
	}
}

// recordTurnID records an obfuscated→original turn ID mapping.
func (s *ConfuseState) recordTurnID(obfuscated, original string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.origTurnIDs[obfuscated] = original
}

// ConfuseBody obfuscates session identity fields in the JSON request body.
// It returns the modified body and a state object for response restoration.
//
// Fields obfuscated:
//   - prompt_cache_key
//   - client_metadata.x-codex-installation-id
//   - client_metadata.x-codex-turn-metadata → prompt_cache_key, turn_id
//   - client_metadata.x-codex-window-id
func ConfuseBody(body []byte, accountID int64) ([]byte, *ConfuseState) {
	if len(body) == 0 || accountID <= 0 {
		return body, nil
	}

	state := newConfuseState(accountID)
	updated := body

	// 1. Obfuscate prompt_cache_key
	if pcKey := strings.TrimSpace(gjson.GetBytes(updated, "prompt_cache_key").String()); pcKey != "" {
		state.origCacheKey = pcKey
		state.PromptCacheKey = ConfuseKey(accountID, "prompt-cache", pcKey)
		updated, _ = sjson.SetBytes(updated, "prompt_cache_key", state.PromptCacheKey)
	}

	// 2. Obfuscate x-codex-installation-id
	if instID := strings.TrimSpace(gjson.GetBytes(updated, "client_metadata.x-codex-installation-id").String()); instID != "" {
		obfuscated := ConfuseKey(accountID, "installation", instID)
		updated, _ = sjson.SetBytes(updated, "client_metadata.x-codex-installation-id", obfuscated)
	}

	// 3. Obfuscate x-codex-turn-metadata
	if turnMeta := strings.TrimSpace(gjson.GetBytes(updated, "client_metadata.x-codex-turn-metadata").String()); turnMeta != "" {
		updated = confuseTurnMetadata(updated, turnMeta, state)
	}

	// 4. Obfuscate x-codex-window-id
	if state.PromptCacheKey != "" {
		if winID := strings.TrimSpace(gjson.GetBytes(updated, "client_metadata.x-codex-window-id").String()); winID != "" {
			updated, _ = sjson.SetBytes(updated, "client_metadata.x-codex-window-id", state.PromptCacheKey+":0")
		}
	}

	return updated, state
}

func confuseTurnMetadata(body []byte, rawMeta string, state *ConfuseState) []byte {
	updatedMeta := rawMeta

	// Obfuscate prompt_cache_key within turn metadata
	if state.PromptCacheKey != "" && state.origCacheKey != "" {
		if gjson.Get(rawMeta, "prompt_cache_key").Exists() {
			updatedMeta, _ = sjson.Set(updatedMeta, "prompt_cache_key", state.PromptCacheKey)
		} else {
			updatedMeta = strings.ReplaceAll(updatedMeta, state.origCacheKey, state.PromptCacheKey)
		}
	}

	// Obfuscate turn_id
	if turnID := strings.TrimSpace(gjson.Get(rawMeta, "turn_id").String()); turnID != "" {
		obfuscated := ConfuseKey(state.AccountID, "turn", turnID)
		updatedMeta, _ = sjson.Set(updatedMeta, "turn_id", obfuscated)
		state.recordTurnID(obfuscated, turnID)
	}

	// Obfuscate window_id
	if state.PromptCacheKey != "" && gjson.Get(rawMeta, "window_id").Exists() {
		updatedMeta, _ = sjson.Set(updatedMeta, "window_id", state.PromptCacheKey+":0")
	}

	body, _ = sjson.SetBytes(body, "client_metadata.x-codex-turn-metadata", updatedMeta)
	return body
}

// ConfuseHeaders obfuscates session identity fields in the request headers.
// Must be called after basic headers are set.
//
// Headers modified:
//   - session_id, Session_id, Session-Id → unified to session_id with obfuscated value
//   - Conversation_id → obfuscated value
//   - X-Client-Request-Id → injected
//   - Thread-Id → injected (uses promptCacheKey)
//   - X-Codex-Window-Id → injected
func ConfuseHeaders(headers http.Header, accountID int64, state *ConfuseState, confusedPromptCacheKey string) {
	if headers == nil || accountID <= 0 {
		return
	}

	// 1. Obfuscate session_id
	for _, key := range []string{"Session-Id", "Session_id", "session_id", "Session_ID"} {
		if v := strings.TrimSpace(headers.Get(key)); v != "" {
			obfuscated := ConfuseKey(accountID, "session", v)
			// Delete all variants
			delete(headers, "Session-Id")
			delete(headers, "Session_id")
			delete(headers, "session_id")
			delete(headers, "Session_ID")
			// Set unified form
			headers.Set("session_id", obfuscated)
			break
		}
	}

	// 2. Obfuscate Conversation_id
	if convID := strings.TrimSpace(headers.Get("Conversation_id")); convID != "" {
		obfuscated := ConfuseKey(accountID, "conversation", convID)
		headers.Set("Conversation_id", obfuscated)
	} else if confusedPromptCacheKey != "" {
		// If no conversation_id but we have a prompt cache key, sync it
		headers.Set("Conversation_id", confusedPromptCacheKey)
	}

	// 3. Inject X-Client-Request-Id
	if headers.Get("X-Client-Request-Id") == "" {
		headers.Set("X-Client-Request-Id", confusedPromptCacheKey)
	}

	// 4. Inject Thread-Id
	if confusedPromptCacheKey != "" {
		headers.Set("Thread-Id", confusedPromptCacheKey)
		headers.Set("X-Codex-Window-Id", confusedPromptCacheKey+":0")
	}
}

// RestoreResponseRestorer returns a response payload restorer function
// that reverts obfuscated values back to originals.
//
// Usage in defer:
//
//	state := ...
//	defer func() {
//	    if state != nil {
//	        resp.Body = guard.RestoreResponseRestorer(state, resp.Body)
//	    }
//	}()
func RestoreResponseRestorer(state *ConfuseState) func([]byte) []byte {
	if state == nil {
		return func(b []byte) []byte { return b }
	}
	return func(payload []byte) []byte {
		return restoreResponse(payload, state)
	}
}

func restoreResponse(payload []byte, state *ConfuseState) []byte {
	if len(payload) == 0 || state == nil {
		return payload
	}

	restored := payload

	// Restore prompt_cache_key in response
	if state.PromptCacheKey != "" && state.origCacheKey != "" {
		restored = bytesReplaceAll(restored, []byte(state.PromptCacheKey), []byte(state.origCacheKey))
	}

	// Restore turn IDs
	for obfuscated, original := range state.origTurnIDs {
		if obfuscated != original {
			restored = bytesReplaceAll(restored, []byte(obfuscated), []byte(original))
		}
	}

	return restored
}

func bytesReplaceAll(src, old, new []byte) []byte {
	if len(src) == 0 || len(old) == 0 || len(new) == 0 {
		return src
	}
	result := make([]byte, 0, len(src))
	for {
		i := indexOf(src, old)
		if i < 0 {
			result = append(result, src...)
			break
		}
		result = append(result, src[:i]...)
		result = append(result, new...)
		src = src[i+len(old):]
	}
	return result
}

func indexOf(s, sep []byte) int {
	if len(sep) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(sep); i++ {
		if string(s[i:i+len(sep)]) == string(sep) {
			return i
		}
	}
	return -1
}
