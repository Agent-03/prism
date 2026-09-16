package main

import (
	"io"
	"log"
	"net/http"
)

// captureHandler is the HTTP extension point for captureEndpoint.
//
// The route remains wired from proxy.go after the project reorganization. The
// default implementation intentionally discards request bodies and records only
// non-sensitive request metadata so the module boundary is preserved without
// coupling routing code to a concrete capture implementation.
func captureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bound and discard the body so this template endpoint cannot retain request
	// contents while still exercising the complete route/wiring during testing.
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))

	log.Printf(
		"[domcapture-template] route=%s host=%s content_type=%s",
		r.URL.Path,
		r.Host,
		r.Header.Get("Content-Type"),
	)

	// TEMPLATE IMPLEMENTATION POINT
	// Add authorized lab-specific event handling here while keeping the route and
	// transport concerns outside of this file.

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}
