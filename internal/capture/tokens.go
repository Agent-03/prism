package capture

import "net/http"

// ObserveAuthResponse is the token-processing extension point.
// The default template intentionally does not inspect, retain, or persist
// authentication cookies or token values.
func ObserveAuthResponse(resp *http.Response, targetName string) {
	_ = resp
	_ = targetName
}

// SaveSession is the session-persistence extension point.
// The default template intentionally performs no persistence.
func SaveSession(targetName string) {
	_ = targetName
}

// AppendEvent records only that an event occurred; callers should pass counts or
// non-sensitive metadata rather than raw credentials, tokens, or response bodies.
func AppendEvent(name string, size int) {
	_ = name
	_ = size
}
