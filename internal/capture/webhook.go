package capture

// EmitCapture is the legacy-compatible outbound-event extension point.
// The safe template intentionally performs no network delivery and does not
// inspect session or target objects.
func EmitCapture(session, target any) {
	_ = session
	_ = target
}

// Notify remains available for direct non-sensitive event integrations.
func Notify(event, targetName string) {
	_ = event
	_ = targetName
}
