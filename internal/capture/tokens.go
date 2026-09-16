package capture

import "net/http"

func CaptureAuthTokens(resp *http.Response, session, target any) {
	_ = resp
	_ = session
	_ = target
}

func SaveTokens(session, target any) {
	_ = session
	_ = target
}

func AppendToFile(filename, content string) {
	_ = filename
	_ = content
}

func Truncate(value string, maxLen int) string {
	_ = value
	_ = maxLen
	return "[redacted]"
}

func ObserveAuthResponse(resp *http.Response, targetName string) {
	_ = resp
	_ = targetName
}

func SaveSession(targetName string) {
	_ = targetName
}

func AppendEvent(name string, size int) {
	_ = name
	_ = size
}
