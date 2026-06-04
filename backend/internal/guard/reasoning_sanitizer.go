// Package guard provides anti-detection mechanisms.
//
// Reasoning Sanitizer: Proactively validates and strips invalid
// encrypted_content fields from reasoning items in Codex Responses API
// requests before they are sent upstream. This prevents avoidable 400
// errors ("invalid_encrypted_content") that consume API quota and
// increase the risk of being flagged as anomalous traffic.
package guard

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// MaxGPTReasoningSignatureLen is the maximum allowed length of a GPT
// reasoning signature in bytes.
const MaxGPTReasoningSignatureLen = 32 * 1024 * 1024 // 32 MB

// SanitizeReasoning proactively removes invalid encrypted_content from
// reasoning items in the request body. Returns the cleaned body.
//
// Validation rules (matching OpenAI's expected format):
//   - Must be a string (not null, not object/array)
//   - Must not have leading or trailing whitespace
//   - Must start with "gAAAA" prefix (Fernet token format)
//   - Must contain only base64url characters
func SanitizeReasoning(provider string, body []byte) []byte {
	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return body
	}

	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "codex"
	}

	updated := body
	for index, item := range input.Array() {
		if strings.TrimSpace(item.Get("type").String()) != "reasoning" {
			continue
		}

		encPath := fmt.Sprintf("input.%d.encrypted_content", index)
		enc := gjson.GetBytes(updated, encPath)
		if !enc.Exists() {
			continue
		}

		reason := validateEncryptedContent(enc)
		if reason == "" {
			continue // Valid, keep it
		}

		// Strip invalid encrypted_content
		updated, _ = sjson.DeleteBytes(updated, encPath)

		// Also clear the summary/content fields since reasoning
		// without encrypted content is meaningless
		updated, _ = sjson.SetBytes(updated, fmt.Sprintf("input.%d.summary", index), []byte("[]"))
		updated, _ = sjson.SetBytes(updated, fmt.Sprintf("input.%d.content", index), nil)
	}

	return updated
}

func validateEncryptedContent(enc gjson.Result) string {
	switch enc.Type {
	case gjson.String:
		raw := enc.String()
		if raw != strings.TrimSpace(raw) {
			return "encrypted_content has leading or trailing whitespace"
		}
		if !isValidReasoningSignature(raw) {
			return "encrypted_content has invalid GPT reasoning signature format"
		}
		return ""
	case gjson.Null:
		return "encrypted_content is null"
	default:
		return fmt.Sprintf("encrypted_content must be a string, got %s", enc.Type.String())
	}
}

// IsValidReasoningSignature validates the outer format of a GPT/Codex
// reasoning encrypted_content value. This is a transport-shape check
// only (not cryptographic verification).
//
// Format: base64url-encoded Fernet token starting with "gAAAA"
func IsValidReasoningSignature(raw string) bool {
	return isValidReasoningSignature(raw)
}

func isValidReasoningSignature(raw string) bool {
	sig := strings.TrimSpace(raw)
	if sig == "" {
		return false
	}
	if len(sig) > MaxGPTReasoningSignatureLen {
		return false
	}
	if !strings.HasPrefix(sig, "gAAAA") {
		return false
	}
	// Check for non-base64url characters
	for _, r := range sig {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '=':
		default:
			return false
		}
	}
	return true
}
