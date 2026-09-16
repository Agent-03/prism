package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// PrismLinkData is the NSL Mailer link payload carried in ?data= as
// Base64URL(JSON). The core fields are cid, email, and provider. mail_domain is
// optional and is intentionally treated as opaque metadata; Prism does not
// perform any provider/domain discovery or lookup from it here.
type PrismLinkData struct {
	CID        string `json:"cid"`
	Email      string `json:"email"`
	Provider   string `json:"provider"`
	MailDomain string `json:"mail_domain,omitempty"`
}

func parsePrismLinkData(raw string) (PrismLinkData, bool) {
	var payload PrismLinkData
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return payload, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		// Accept padded URL-safe Base64 as a compatibility fallback.
		decoded, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return PrismLinkData{}, false
		}
	}

	if err := json.Unmarshal(decoded, &payload); err != nil {
		return PrismLinkData{}, false
	}

	payload.CID = strings.TrimSpace(payload.CID)
	payload.Email = strings.TrimSpace(strings.ToLower(payload.Email))
	payload.Provider = strings.TrimSpace(strings.ToLower(payload.Provider))
	payload.MailDomain = strings.TrimSpace(strings.ToLower(payload.MailDomain))

	if payload.CID == "" && payload.Email == "" && payload.Provider == "" && payload.MailDomain == "" {
		return PrismLinkData{}, false
	}
	return payload, true
}

func prismLinkDataFromRequest(r *http.Request) (PrismLinkData, bool) {
	if r == nil || r.URL == nil {
		return PrismLinkData{}, false
	}
	return parsePrismLinkData(r.URL.Query().Get("data"))
}

func campaignIDFromRequest(r *http.Request) string {
	if payload, ok := prismLinkDataFromRequest(r); ok && payload.CID != "" {
		return payload.CID
	}
	// Keep the legacy parameter as a compatibility fallback only.
	if r != nil && r.URL != nil {
		return strings.TrimSpace(r.URL.Query().Get("cid"))
	}
	return ""
}
