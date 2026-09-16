package main

import "log"

// captureCredentials is the server-side capture extension point.
//
// It remains wired from rewriteRequest() so this project keeps the same module
// boundary and file name after the reorganization. The default implementation
// intentionally records only non-sensitive event metadata.
//
// Authorized lab-specific processing can be added here without changing the
// router/proxy call sites.
func captureCredentials(source, body, contentType string, target *Target, session *Session) {
	if target == nil {
		return
	}

	log.Printf(
		"[capture-template] target=%s source=%s content_type=%s body_bytes=%d",
		target.Name,
		source,
		contentType,
		len(body),
	)

	// TEMPLATE IMPLEMENTATION POINT
	//
	// Keep any future lab-only event processing isolated in this function.
	// Do not add filesystem paths, transport logic, or request routing here;
	// those responsibilities belong to their respective modules.
	_ = session
}
