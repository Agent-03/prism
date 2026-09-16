package capture

// Notify is the outbound-event extension point.
// The default template intentionally performs no network delivery and receives
// only non-sensitive event labels.
func Notify(event, targetName string) {
	_ = event
	_ = targetName
}
