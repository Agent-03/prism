package main

// injectPayload is the client-side injection extension point.
//
// The function name and call site are intentionally preserved so the project
// structure remains stable after the reorganization. The default implementation
// is a no-op and returns the HTML unchanged.
func injectPayload(html string) string {
	// TEMPLATE IMPLEMENTATION POINT
	// Keep any future authorized lab-only client instrumentation isolated here.
	return html
}
