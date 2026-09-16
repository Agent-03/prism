package proxy

import "net/http"

// DefaultTerminateURL is intentionally local-only in the safe template.
const DefaultTerminateURL = "/"

// ShouldTerminate is the termination extension point.
// The default template is inert and never triggers a handoff.
func ShouldTerminate(done bool, r *http.Request) bool {
	_ = done
	_ = r
	return false
}

// Terminate is retained as a structural extension point.
// The default template performs no redirect or external navigation.
func Terminate(w http.ResponseWriter, targetName string) {
	_ = w
	_ = targetName
}
