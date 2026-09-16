package capture

import (
	"io"
	"log"
	"net/http"
)

// Handler is the HTTP extension point used by the compatibility bridge in
// cmd/prism. The default implementation discards request bodies and records only
// non-sensitive request metadata.
func Handler(w http.ResponseWriter, r *http.Request) {
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

	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))

	log.Printf(
		"[domcapture-template] route=%s host=%s content_type=%s",
		r.URL.Path,
		r.Host,
		r.Header.Get("Content-Type"),
	)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}
