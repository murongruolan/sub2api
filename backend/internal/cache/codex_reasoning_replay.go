// Package cache provides in-memory caching for anti-detection features.
package cache

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/guard"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	// CodexReasoningReplayTTL limits how long encrypted reasoning replay
	// items stay in process memory.
	CodexReasoningReplayTTL = 1 * time.Hour

	// CodexReasoningReplayMaxEntries bounds process memory for replay
	// continuity. Oldest entries are evicted first.
	CodexReasoningReplayMaxEntries = 10240

	// CodexReasoningReplayEvictBatchSize leaves headroom after the cache
	// reaches capacity so high write volume does not rescan the map every turn.
	CodexReasoningReplayEvictBatchSize = 128
)

type codexReasoningReplayEntry struct {
	Items     [][]byte
	Timestamp time.Time
}

var (
	codexReasoningReplayMu      sync.Mutex
	codexReasoningReplayEntries = make(map[string]codexReasoningReplayEntry)
)

// CacheCodexReasoningReplayItems stores the final GPT/Codex assistant output
// items needed to replay a stateless next turn.
func CacheCodexReasoningReplayItems(modelName, sessionKey string, items [][]byte) bool {
	key := codexReasoningReplayCacheKey(modelName, sessionKey)
	if key == "" {
		return false
	}
	normalized, ok := normalizeCodexReasoningReplayItems(items)
	if !ok {
		return false
	}

	now := time.Now()
	codexReasoningReplayMu.Lock()
	defer codexReasoningReplayMu.Unlock()
	codexReasoningReplayEntries[key] = codexReasoningReplayEntry{
		Items:     normalized,
		Timestamp: now,
	}
	if len(codexReasoningReplayEntries) > CodexReasoningReplayMaxEntries {
		evictOldestCodexReasoningReplayEntries(CodexReasoningReplayEvictBatchSize)
	}
	return true
}

// GetCodexReasoningReplayItems retrieves normalized assistant output items.
func GetCodexReasoningReplayItems(modelName, sessionKey string) ([][]byte, bool) {
	key := codexReasoningReplayCacheKey(modelName, sessionKey)
	if key == "" {
		return nil, false
	}

	now := time.Now()
	codexReasoningReplayMu.Lock()
	defer codexReasoningReplayMu.Unlock()
	entry, ok := codexReasoningReplayEntries[key]
	if !ok {
		return nil, false
	}
	if now.Sub(entry.Timestamp) > CodexReasoningReplayTTL {
		delete(codexReasoningReplayEntries, key)
		return nil, false
	}
	entry.Timestamp = now
	codexReasoningReplayEntries[key] = entry
	return cloneCodexReasoningReplayItems(entry.Items), true
}

// DeleteCodexReasoningReplayItem removes one replay item after upstream rejects
// it or the caller otherwise knows it is stale.
func DeleteCodexReasoningReplayItem(modelName, sessionKey string) {
	key := codexReasoningReplayCacheKey(modelName, sessionKey)
	if key == "" {
		return
	}
	codexReasoningReplayMu.Lock()
	delete(codexReasoningReplayEntries, key)
	codexReasoningReplayMu.Unlock()
}

// ClearCodexReasoningReplayCache clears all Codex reasoning replay state.
func ClearCodexReasoningReplayCache() {
	codexReasoningReplayMu.Lock()
	codexReasoningReplayEntries = make(map[string]codexReasoningReplayEntry)
	codexReasoningReplayMu.Unlock()
}

func codexReasoningReplayCacheKey(modelName, sessionKey string) string {
	modelName = strings.TrimSpace(modelName)
	sessionKey = strings.TrimSpace(sessionKey)
	if modelName == "" || sessionKey == "" {
		return ""
	}
	return strings.Join([]string{"codex-reasoning-replay", modelName, sessionKey}, "\x00")
}

func normalizeCodexReasoningReplayItems(items [][]byte) ([][]byte, bool) {
	normalized := make([][]byte, 0, len(items))
	for _, item := range items {
		normalizedItem, ok := normalizeCodexReasoningReplayItem(item)
		if ok {
			normalized = append(normalized, normalizedItem)
		}
	}
	return normalized, len(normalized) > 0
}

func normalizeCodexReasoningReplayItem(item []byte) ([]byte, bool) {
	itemResult := gjson.ParseBytes(item)
	switch strings.TrimSpace(itemResult.Get("type").String()) {
	case "reasoning":
		return normalizeCodexReasoningReplayReasoningItem(itemResult)
	case "function_call":
		return normalizeCodexReasoningReplayFunctionCallItem(itemResult)
	case "custom_tool_call":
		return normalizeCodexReasoningReplayCustomToolCallItem(itemResult)
	default:
		return nil, false
	}
}

func normalizeCodexReasoningReplayReasoningItem(itemResult gjson.Result) ([]byte, bool) {
	encryptedContentResult := itemResult.Get("encrypted_content")
	if encryptedContentResult.Type != gjson.String {
		return nil, false
	}
	encryptedContent := encryptedContentResult.String()
	if encryptedContent != strings.TrimSpace(encryptedContent) {
		return nil, false
	}
	if _, err := guard.InspectGPTReasoningSignature(encryptedContent); err != nil {
		return nil, false
	}

	normalized := []byte(`{"type":"reasoning","summary":[],"content":null}`)
	normalized, _ = sjson.SetBytes(normalized, "encrypted_content", encryptedContent)
	return normalized, true
}

func normalizeCodexReasoningReplayFunctionCallItem(itemResult gjson.Result) ([]byte, bool) {
	callID := strings.TrimSpace(itemResult.Get("call_id").String())
	name := strings.TrimSpace(itemResult.Get("name").String())
	arguments := itemResult.Get("arguments")
	if callID == "" || name == "" || arguments.Type != gjson.String {
		return nil, false
	}

	normalized := []byte(`{"type":"function_call"}`)
	normalized, _ = sjson.SetBytes(normalized, "call_id", callID)
	normalized, _ = sjson.SetBytes(normalized, "name", name)
	normalized, _ = sjson.SetBytes(normalized, "arguments", arguments.String())
	return normalized, true
}

func normalizeCodexReasoningReplayCustomToolCallItem(itemResult gjson.Result) ([]byte, bool) {
	callID := strings.TrimSpace(itemResult.Get("call_id").String())
	name := strings.TrimSpace(itemResult.Get("name").String())
	input := itemResult.Get("input")
	if callID == "" || name == "" || !input.Exists() {
		return nil, false
	}

	normalized := []byte(`{"type":"custom_tool_call","status":"completed"}`)
	if status := strings.TrimSpace(itemResult.Get("status").String()); status != "" {
		normalized, _ = sjson.SetBytes(normalized, "status", status)
	}
	normalized, _ = sjson.SetBytes(normalized, "call_id", callID)
	normalized, _ = sjson.SetBytes(normalized, "name", name)
	if input.Type == gjson.String {
		normalized, _ = sjson.SetBytes(normalized, "input", input.String())
	} else {
		normalized, _ = sjson.SetRawBytes(normalized, "input", []byte(input.Raw))
	}
	return normalized, true
}

func cloneCodexReasoningReplayItems(items [][]byte) [][]byte {
	cloned := make([][]byte, 0, len(items))
	for _, item := range items {
		cloned = append(cloned, append([]byte(nil), item...))
	}
	return cloned
}

func evictOldestCodexReasoningReplayEntries(count int) {
	if count <= 0 || len(codexReasoningReplayEntries) == 0 {
		return
	}
	type candidate struct {
		key       string
		timestamp time.Time
	}
	candidates := make([]candidate, 0, len(codexReasoningReplayEntries))
	for key, entry := range codexReasoningReplayEntries {
		candidates = append(candidates, candidate{key: key, timestamp: entry.Timestamp})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].timestamp.Before(candidates[j].timestamp)
	})
	if count > len(candidates) {
		count = len(candidates)
	}
	for i := 0; i < count; i++ {
		delete(codexReasoningReplayEntries, candidates[i].key)
	}
}

// FilterCodexReasoningReplayItemsForInput removes replay items that are
// already present in the input array to avoid duplicates.
func FilterCodexReasoningReplayItemsForInput(body []byte, items [][]byte) [][]byte {
	if len(items) == 0 {
		return nil
	}
	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return items
	}

	existingCallIDs := make(map[string]bool)
	existingEnc := make(map[string]bool)
	for _, item := range input.Array() {
		if callID := strings.TrimSpace(item.Get("call_id").String()); callID != "" {
			existingCallIDs[callID] = true
		}
		if enc := strings.TrimSpace(item.Get("encrypted_content").String()); enc != "" {
			existingEnc[enc] = true
		}
	}

	filtered := make([][]byte, 0, len(items))
	for _, item := range items {
		itemResult := gjson.ParseBytes(item)
		if callID := strings.TrimSpace(itemResult.Get("call_id").String()); callID != "" {
			if existingCallIDs[callID] {
				continue
			}
			existingCallIDs[callID] = true
		}
		if enc := strings.TrimSpace(itemResult.Get("encrypted_content").String()); enc != "" {
			if existingEnc[enc] {
				continue
			}
			existingEnc[enc] = true
		}
		filtered = append(filtered, item)
	}
	return filtered
}

// InsertCodexReasoningReplayItems inserts replay items into the request body's
// input array. Items are placed before the first non-replay input item.
func InsertCodexReasoningReplayItems(body []byte, replayItems [][]byte) ([]byte, bool) {
	if len(replayItems) == 0 {
		return body, false
	}

	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return body, false
	}

	inputItems := input.Array()
	if len(inputItems) == 0 {
		return body, false
	}

	// Find insertion index: before the first non-replay item
	insertIndex := -1
	for i, item := range inputItems {
		itemType := strings.TrimSpace(item.Get("type").String())
		switch itemType {
		case "reasoning", "function_call", "custom_tool_call":
			continue
		default:
			insertIndex = i
			break
		}
	}
	if insertIndex < 0 {
		insertIndex = len(inputItems)
	}

	// Parse existing input items into raw JSON values
	newInput := make([]json.RawMessage, 0, len(inputItems)+len(replayItems))
	for i := 0; i < insertIndex; i++ {
		newInput = append(newInput, json.RawMessage(inputItems[i].Raw))
	}
	for _, item := range replayItems {
		newInput = append(newInput, json.RawMessage(item))
	}
	for i := insertIndex; i < len(inputItems); i++ {
		newInput = append(newInput, json.RawMessage(inputItems[i].Raw))
	}

	// Marshal into JSON array
	raw, err := json.Marshal(newInput)
	if err != nil {
		return body, false
	}

	updated, err := sjson.SetRawBytes(body, "input", raw)
	if err != nil {
		return body, false
	}

	return updated, true
}

// ExtractCodexReasoningReplayFromCompleted extracts reasoning replay items
// from a completed response.
func ExtractCodexReasoningReplayFromCompleted(completedData []byte) [][]byte {
	output := gjson.GetBytes(completedData, "response.output")
	if !output.Exists() || !output.IsArray() {
		return nil
	}

	var items [][]byte
	for _, item := range output.Array() {
		itemType := strings.TrimSpace(item.Get("type").String())
		switch itemType {
		case "reasoning", "function_call", "custom_tool_call":
			items = append(items, []byte(item.Raw))
		}
	}
	return items
}
