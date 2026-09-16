package capture

import "net/http"

// CaptureAuthTokens is the legacy-compatible token-processing extension point.
// The safe template intentionally does not inspect, retain, or persist
// authentication cookies, session objects, or token values.
func CaptureAuthTokens(resp *http.Response, session, target any) {
	_ = resp
	_ = session
	_ = target
}

// SaveTokens is the legacy-compatible session-persistence extension point.
// The safe template intentionally performs no persistence.
func SaveTokens(session, target any) {
	_ = session
	_ = target
}

// AppendToFile preserves the legacy logging extension point without writing
// potentially sensitive content.
func AppendToFile(filename, content string) {
	_ = filename
	_ = content
}

// Truncate preserves formatting call sites while ensuring values are redacted.
func Truncate(value string, maxLen int) string {
	_ = value
	_ = maxLen
	return "[redacted]"
}

// ObserveAuthResponse remains available for direct non-sensitive integrations.
func ObserveAuthResponse(resp *http.Response, targetName string) {
	_ = resp
	_ = targetName
}

// SaveSession remains available for direct non-sensitive integrations.
func SaveSession(targetName string) {
	_ = targetName
}

// AppendEvent records only that an event occurred; callers should pass counts or
// non-sensitive metadata rather than raw credentials, tokens, or response bodies.
func AppendEvent(name string, size int) {
	_ = name
	_ = size
}
