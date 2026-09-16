package main

import (
	"net/http"

	capturepkg "ms-proxy/internal/capture"
)

// captureAuthTokens preserves the existing call site while delegating to the
// inert capture template. No authentication cookies or token values are read or stored.
func captureAuthTokens(resp *http.Response, s *Session, target *Target) {
	targetName := ""
	if target != nil {
		targetName = target.Name
	}
	capturepkg.ObserveAuthResponse(resp, targetName)
	_ = s
}

// saveTokens preserves the existing call site while keeping persistence disabled.
func saveTokens(s *Session, target *Target) {
	targetName := ""
	if target != nil {
		targetName = target.Name
	}
	capturepkg.SaveSession(targetName)
	_ = s
}

// appendToFile preserves the existing call site without writing sensitive content.
func appendToFile(filename, content string) {
	capturepkg.AppendEvent(filename, len(content))
}

// truncate preserves formatting call sites while redacting potentially sensitive values.
func truncate(s string, maxLen int) string {
	_ = s
	_ = maxLen
	return "[redacted]"
}
