package capture

// InjectPayload is the client-side extension point used by the compatibility
// bridge in cmd/prism. The default implementation returns HTML unchanged.
func InjectPayload(html string) string {
	return html
}
