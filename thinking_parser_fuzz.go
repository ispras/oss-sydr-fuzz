//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"strings"
	"github.com/ollama/ollama/thinking"
)

func FuzzAddContent(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}
	
	const maxSize = 10 * 1024
	if len(data) > maxSize {
		data = data[:maxSize]
	}

	content := string(data)
	thinkingContent, remaining := p.AddContent(content)
	
	if !isSubstring(thinkingContent, content) || !isSubstring(remaining, content) {
		return 0
	}
	
	return 1
}

func FuzzParserState(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}

	content := string(data)
	p.AddContent(content)
	
	// We can't check internal state directly, so we'll verify behavior instead
	// by checking if the parser correctly handles valid/invalid content
	if strings.Contains(content, "<thinking>") && strings.Contains(content, "</thinking>") {
		// Valid thinking tags - should return some thinking content
		thinkingContent, _ := p.AddContent("")
		if thinkingContent == "" {
			return 0
		}
	} else {
		// No thinking tags - should return empty thinking content
		thinkingContent, _ := p.AddContent("")
		if thinkingContent != "" {
			return 0
		}
	}
	
	return 1
}

func FuzzEat(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}
	
	// Test AddContent which internally uses eat()
	thinkingContent, remaining := p.AddContent(string(data))
	
	content := string(data)
	if !isSubstring(thinkingContent, content) || !isSubstring(remaining, content) {
		return 0
	}
	
	return 1
}

func isSubstring(sub, s string) bool {
	if sub == "" {
		return true
	}
	return strings.Contains(s, sub)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
