// Package guard provides anti-detection mechanisms.
//
// Reasoning Sanitizer: Proactively validates and strips invalid
// encrypted_content fields from reasoning items in Codex Responses API
// requests before they are sent upstream. This prevents avoidable 400
// errors ("invalid_encrypted_content") that consume API quota and
// increase the risk of being flagged as anomalous traffic.
package guard

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// MaxGPTReasoningSignatureLen is the maximum allowed length of a GPT
// reasoning signature in bytes.
const MaxGPTReasoningSignatureLen = 32 * 1024 * 1024 // 32 MB

// GPTReasoningSignatureInfo holds structural metadata about a parsed
// GPT reasoning signature.
type GPTReasoningSignatureInfo struct {
	DecodedLen    int
	CiphertextLen int
}

// SanitizeReasoning proactively removes invalid encrypted_content from
// reasoning items in the request body. Returns the cleaned body.
//
// Validation rules (matching OpenAI's expected format):
//   - Must be a string (not null, not object/array)
//   - Must not have leading or trailing whitespace
//   - Must start with "gAAAA" prefix (Fernet token format)
//   - Must be valid base64url
//   - Version byte must be 0x80
//   - Ciphertext must be AES-block-aligned (multiple of 16)
//   - Decoded payload must be at least 73 bytes
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
		if _, err := InspectGPTReasoningSignature(raw); err != nil {
			return err.Error()
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
// Format: base64url-encoded Fernet token starting with "gAAAA".
// Validates: prefix, characters, version byte (0x80), AES block alignment,
// minimum payload length.
func IsValidReasoningSignature(raw string) bool {
	_, err := InspectGPTReasoningSignature(raw)
	return err == nil
}

// InspectGPTReasoningSignature validates the Fernet-like outer format used
// by GPT/Codex reasoning encrypted_content. This is only a transport-shape
// check; it does not prove decryptability.
//
// Format (Fernet): Version(1) + Timestamp(8) + IV(16) + Ciphertext(N*16) + HMAC(32)
// Minimum decoded length: 1 + 8 + 16 + 0 + 32 = 57, but in practice it's at least 73.
func InspectGPTReasoningSignature(raw string) (*GPTReasoningSignatureInfo, error) {
	sig := strings.TrimSpace(raw)
	if sig == "" {
		return nil, fmt.Errorf("empty GPT reasoning signature")
	}
	if len(sig) > MaxGPTReasoningSignatureLen {
		return nil, fmt.Errorf("GPT reasoning signature exceeds maximum length (%d bytes)", MaxGPTReasoningSignatureLen)
	}
	if index, r, ok := firstInvalidGPTReasoningSignatureChar(sig); ok {
		return nil, fmt.Errorf("invalid GPT reasoning signature: contains non-base64url character U+%04X at byte %d", r, index)
	}
	if !strings.HasPrefix(sig, "gAAAA") {
		return nil, fmt.Errorf("invalid GPT reasoning signature: expected gAAAA prefix")
	}

	decoded, err := decodeGPTReasoningSignature(sig)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 73 {
		return nil, fmt.Errorf("invalid GPT reasoning signature: decoded payload too short (%d bytes)", len(decoded))
	}
	if decoded[0] != 0x80 {
		return nil, fmt.Errorf("invalid GPT reasoning signature: expected version 0x80, got 0x%02x", decoded[0])
	}

	// Fernet format: version(1) + timestamp(8) + IV(16) + ciphertext + HMAC(32)
	// ciphertext = decoded - (1 + 8 + 16 + 32) = decoded - 57
	ciphertextLen := len(decoded) - 1 - 8 - 16 - 32
	if ciphertextLen <= 0 || ciphertextLen%16 != 0 {
		return nil, fmt.Errorf("invalid GPT reasoning signature: ciphertext length %d is not a positive AES block multiple", ciphertextLen)
	}

	return &GPTReasoningSignatureInfo{
		DecodedLen:    len(decoded),
		CiphertextLen: ciphertextLen,
	}, nil
}

func decodeGPTReasoningSignature(sig string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(sig); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(sig); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid GPT reasoning signature: base64url decode failed")
}

func firstInvalidGPTReasoningSignatureChar(sig string) (int, rune, bool) {
	for index, r := range sig {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '=':
		default:
			return index, r, true
		}
	}
	return 0, 0, false
}
