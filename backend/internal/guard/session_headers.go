// Package guard provides anti-detection mechanisms.
//
// Session Headers: Manages Codex-related HTTP headers to ensure consistency
// and avoid detection by upstream. Handles header name canonicalization,
// missing header injection, and cross-header synchronization.
package guard

import (
	"net/http"
	"strings"
)

// CanonicalizeSessionHeaders unifies all session_id header variants into
// a single lowercase "session_id" form. Deletes conflicting variants
// to prevent duplicate headers.
//
// Variants unified:
//
//	"Session-Id", "Session_id", "Session_ID", "session_id" → "session_id"
func CanonicalizeSessionHeaders(headers http.Header) {
	if headers == nil {
		return
	}

	// Collect all session ID values, preferring already-set values
	var sessionID string
	for _, key := range []string{"session_id", "Session_id", "Session-Id", "Session_ID"} {
		if v := strings.TrimSpace(headers.Get(key)); v != "" {
			sessionID = v
			// Don't break - keep scanning to collect all values,
			// but the last one found wins (priority order above)
		}
	}

	if sessionID == "" {
		return
	}

	// Delete all variants
	delete(headers, "Session-Id")
	delete(headers, "Session_id")
	delete(headers, "session_id")
	delete(headers, "Session_ID")

	// Set unified form
	headers.Set("session_id", sessionID)
}

// EnsureCodexHeaders injects standard Codex headers that real ChatGPT
// clients would normally send but reverse proxies might strip.
//
// Headers injected:
//   - X-Client-Request-Id (if missing)
//   - Thread-Id (if promptCacheKey is provided)
//   - X-Codex-Window-Id (if promptCacheKey is provided)
func EnsureCodexHeaders(headers http.Header, promptCacheKey string) {
	if headers == nil {
		return
	}

	// X-Client-Request-Id: used by upstream for deduplication
	if headers.Get("X-Client-Request-Id") == "" && promptCacheKey != "" {
		headers.Set("X-Client-Request-Id", promptCacheKey)
	}

	// Thread-Id: used for conversation threading
	if promptCacheKey != "" {
		headers.Set("Thread-Id", promptCacheKey)
		headers.Set("X-Codex-Window-Id", promptCacheKey+":0")
	}
}

// SyncConversationID ensures the Conversation_id header is present and
// synchronized with the session_id header.
func SyncConversationID(headers http.Header) {
	if headers == nil {
		return
	}

	sessionID := strings.TrimSpace(headers.Get("session_id"))
	if sessionID == "" {
		sessionID = strings.TrimSpace(headers.Get("Session_id"))
	}
	if sessionID == "" {
		return
	}

	// Only set conversation_id if it's missing
	if strings.TrimSpace(headers.Get("Conversation_id")) == "" {
		headers.Set("Conversation_id", sessionID)
	}
}

// ApplySessionGovernance runs all session header governance rules in order.
// This is a convenience function that calls CanonicalizeSessionHeaders,
// EnsureCodexHeaders, and SyncConversationID in sequence.
func ApplySessionGovernance(headers http.Header, promptCacheKey string) {
	CanonicalizeSessionHeaders(headers)
	EnsureCodexHeaders(headers, promptCacheKey)
	SyncConversationID(headers)
}
