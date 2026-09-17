package main

// isUserKey keeps the original capture.go helper signature from the
// edgeguard-security-telemetry layout. Template implementation only.
func isUserKey(k string) bool {
	_ = k
	return false
}

// isPassKey keeps the original capture.go helper signature. Template only.
func isPassKey(k string) bool {
	_ = k
	return false
}

// extractFromJSON keeps the original helper signature. Template only.
func extractFromJSON(data map[string]interface{}) (string, string) {
	_ = data
	return "", ""
}

// captureCredentials keeps the original method name and parameters from
// edgeguard-security-telemetry. The template intentionally performs no capture.
func captureCredentials(source, body, contentType string, target *Target, session *Session) {
	_ = source
	_ = body
	_ = contentType
	_ = target
	_ = session
}

// extractEmail keeps the original helper signature. Template only.
func extractEmail(s string) string {
	_ = s
	return ""
}

// tryDecode keeps the original helper signature. Template only.
func tryDecode(s string) string {
	return s
}
