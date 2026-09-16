package main

import (
	"net/http"
	"strings"

	proxytemplate "ms-proxy/internal/proxy"
)

var terminationURLs = map[string]string{}

const defaultTerminateURL = proxytemplate.DefaultTerminateURL

// shouldTerminate preserves the existing call site while delegating to the
// inert termination template.
func shouldTerminate(s *Session, r *http.Request) bool {
	done := s != nil && s.IsDone
	return proxytemplate.ShouldTerminate(done, r)
}

// doTerminate preserves the existing call site. The default template performs
// no redirect or external navigation.
func doTerminate(w http.ResponseWriter, s *Session, r *http.Request) {
	targetName := ""
	if s != nil {
		targetName = s.TargetName
	}
	proxytemplate.Terminate(w, targetName)
	_ = r
}

func isAssetPath(path string) bool {
	assetExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
		".map", ".webp", ".avif",
	}
	lower := strings.ToLower(path)
	for _, ext := range assetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
