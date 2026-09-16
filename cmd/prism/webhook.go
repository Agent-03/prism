package main

import capturepkg "ms-proxy/internal/capture"

// emitCapture preserves the legacy extension point while the safe template
// intentionally avoids sending credentials, tokens, or session contents.
func emitCapture(s *Session, target *Target) {
	targetName := ""
	if target != nil {
		targetName = target.Name
	}
	capturepkg.Notify("capture-template", targetName)
	_ = s
}
