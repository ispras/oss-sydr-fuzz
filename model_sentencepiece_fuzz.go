//go:build gofuzz
// +build gofuzz

package model

import (
	"unicode/utf8"

	"github.com/ollama/ollama/model" // Импортируем пакет, где определены Vocabulary и SentencePieceModel
)

var (
	// testVocab will be initialized from corpus
	testVocab *model.Vocabulary
	testSpm   *model.SentencePieceModel
)

// FuzzEncode tests the Encode method with fuzzed input strings
func FuzzEncode(data []byte) int {
	if testVocab == nil || testSpm == nil {
		return -1
	}

	if !utf8.Valid(data) {
		return -1
	}

	// Test both with and without special tokens
	for _, addSpecial := range []bool{true, false} {
		ids, err := testSpm.Encode(string(data), addSpecial)
		if err != nil {
			return 0
		}

		// Verify we can round-trip the data
		decoded, err := testSpm.Decode(ids)
		if err != nil {
			return 0
		}

		if !utf8.ValidString(decoded) {
			panic("decoded string is not valid UTF-8")
		}
	}

	return 1
}

// FuzzDecode tests the Decode method with fuzzed token sequences
func FuzzDecode(data []byte) int {
	if testVocab == nil || testSpm == nil {
		return -1
	}

	// Convert bytes to int32 IDs (simple approach)
	var ids []int32
	for i := 0; i < len(data); i += 4 {
		if i+4 > len(data) {
			break
		}
		id := int32(data[i])<<24 | int32(data[i+1])<<16 | 
			int32(data[i+2])<<8 | int32(data[i+3])
		ids = append(ids, id)
	}

	decoded, err := testSpm.Decode(ids)
	if err != nil {
		return 0
	}

	if !utf8.ValidString(decoded) {
		panic("decoded string is not valid UTF-8")
	}

	return 1
}
