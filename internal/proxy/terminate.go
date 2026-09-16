package proxy

import "net/http"

// DefaultTerminateURL is intentionally local-only in the safe template.
const DefaultTerminateURL = "/"

// TerminationURLs preserves the legacy lookup shape without defining external
// handoff destinations in the safe template.
var TerminationURLs = map[string]string{}

// ShouldTerminate is the legacy-compatible termination extension point.
// The safe template is inert and never triggers a handoff.
func ShouldTerminate(session any, r *http.Request) bool {
	_ = session
	_ = r
	return false
}

// DoTerminate preserves the legacy-compatible termination call shape.
// The safe template performs no redirect or external navigation.
func DoTerminate(w http.ResponseWriter, session any, r *http.Request) {
	_ = w
	_ = session
	_ = r
}

// Terminate remains available for direct non-sensitive integrations.
func Terminate(w http.ResponseWriter, targetName string) {
	_ = w
	_ = targetName
}
