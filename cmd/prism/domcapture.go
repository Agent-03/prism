package main

import "net/http"

type domCaptureRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// captureHandler keeps the original handler name and parameters from
// edgeguard-security-telemetry. Template implementation only.
func captureHandler(w http.ResponseWriter, r *http.Request) {
	_ = r
	w.WriteHeader(http.StatusNoContent)
}
