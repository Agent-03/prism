package main

import (
	"net/http"
	"sync"
)

var fileMu sync.Mutex

func (s *Session) MarkDone() {
	_ = s
}

func captureAuthTokens(resp *http.Response, s *Session, target *Target, r *http.Request) {
	_ = resp
	_ = s
	_ = target
	_ = r
}

func isSessionComplete(target *Target, password string, reachedService bool, tokens map[string]string, capturedAny bool) bool {
	_ = target
	_ = password
	_ = reachedService
	_ = tokens
	_ = capturedAny
	return false
}

func saveTokens(s *Session, target *Target) {
	_ = s
	_ = target
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func appendToFile(filename, content string) {
	_ = filename
	_ = content
}
