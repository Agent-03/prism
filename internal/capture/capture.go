package capture

import "log"

// Credentials is the server-side extension point used by the compatibility
// bridge in cmd/prism. This implementation records only non-sensitive metadata.
func Credentials(source, body, contentType, targetName string) {
	log.Printf(
		"[capture-template] target=%s source=%s content_type=%s body_bytes=%d",
		targetName,
		source,
		contentType,
		len(body),
	)
}
