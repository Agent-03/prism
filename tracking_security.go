package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	edgeAuthHeader        = "X-EdgeGuard-Origin-Auth"
	maxTrackingDataLength = 1800
)

var (
	campaignIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,160}$`)
	providerPattern    = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,80}$`)
	domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type TrackingPayload struct {
	CID        string `json:"cid"`
	Email      string `json:"email"`
	Provider   string `json:"provider"`
	MailDomain string `json:"mail_domain,omitempty"`
}

type trackingContextKey struct{}

type explicitProviderOverride struct {
	Provider   string
	MailDomain string
	ExpiresAt  time.Time
}

var explicitProviderOverrides sync.Map

func normalizeTrackingMailDomain(value string) (string, error) {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return "", nil
	}
	if len(raw) > 253 {
		return "", fmt.Errorf("mail domain too long")
	}
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#@:") {
		return "", fmt.Errorf("invalid mail domain")
	}

	raw = strings.TrimSuffix(raw, ".")
	labels := strings.Split(raw, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("invalid mail domain")
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid mail domain")
		}
	}
	return raw, nil
}

func decodeTrackingData(encoded string) (*TrackingPayload, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > maxTrackingDataLength {
		return nil, fmt.Errorf("tracking payload too large")
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid tracking encoding")
	}

	var payload TrackingPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid tracking payload")
	}

	payload.CID = strings.TrimSpace(payload.CID)
	payload.Email = strings.ToLower(strings.TrimSpace(payload.Email))
	payload.Provider = strings.ToLower(strings.TrimSpace(payload.Provider))

	mailDomain, err := normalizeTrackingMailDomain(payload.MailDomain)
	if err != nil {
		return nil, err
	}
	payload.MailDomain = mailDomain

	if !campaignIDPattern.MatchString(payload.CID) {
		return nil, fmt.Errorf("invalid campaign id")
	}
	if len(payload.Email) > 320 {
		return nil, fmt.Errorf("invalid email")
	}

	address, err := mail.ParseAddress(payload.Email)
	if err != nil || !strings.EqualFold(address.Address, payload.Email) {
		return nil, fmt.Errorf("invalid email")
	}

	if !providerPattern.MatchString(payload.Provider) {
		return nil, fmt.Errorf("invalid provider")
	}

	return &payload, nil
}

func withTrackingContext(r *http.Request, payload *TrackingPayload) *http.Request {
	if payload == nil {
		return r
	}
	ctx := context.WithValue(r.Context(), trackingContextKey{}, payload)
	return r.WithContext(ctx)
}

func trackingFromRequest(r *http.Request) (*TrackingPayload, bool) {
	payload, ok := r.Context().Value(trackingContextKey{}).(*TrackingPayload)
	return payload, ok
}

func registerExplicitProvider(payload *TrackingPayload) {
	if payload == nil || payload.Provider == "" || payload.Email == "" {
		return
	}

	parts := strings.SplitN(payload.Email, "@", 2)
	if len(parts) != 2 {
		return
	}
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	if domain == "" {
		return
	}

	explicitProviderOverrides.Store(domain, explicitProviderOverride{
		Provider:   payload.Provider,
		MailDomain: payload.MailDomain,
		ExpiresAt:  time.Now().Add(2 * time.Hour),
	})
}

func explicitProviderForDomain(domain string) (string, string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	value, ok := explicitProviderOverrides.Load(domain)
	if !ok {
		return "", "", false
	}

	override, ok := value.(explicitProviderOverride)
	if !ok || time.Now().After(override.ExpiresAt) {
		explicitProviderOverrides.Delete(domain)
		return "", "", false
	}

	return override.Provider, override.MailDomain, true
}

func validateEdgeGuardOrigin(r *http.Request) error {
	expected := strings.TrimSpace(os.Getenv("ORIGIN_SHARED_SECRET"))
	if expected == "" {
		return fmt.Errorf("ORIGIN_SHARED_SECRET is not configured")
	}

	provided := strings.TrimSpace(r.Header.Get(edgeAuthHeader))
	if provided == "" {
		return fmt.Errorf("missing EdgeGuard origin authentication")
	}
	if len(provided) != len(expected) {
		return fmt.Errorf("invalid EdgeGuard origin authentication")
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return fmt.Errorf("invalid EdgeGuard origin authentication")
	}

	return nil
}

func setApplicationSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

func edgeGuardMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setApplicationSecurityHeaders(w)

		if err := validateEdgeGuardOrigin(r); err != nil {
			log.Printf("[⛔] BLOCKED: EdgeGuard origin authentication failed from %s: %v", extractIP(r), err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		encoded := strings.TrimSpace(r.URL.Query().Get("data"))
		if encoded != "" {
			tracking, err := decodeTrackingData(encoded)
			if err != nil {
				log.Printf("[⛔] BLOCKED: Invalid tracking payload from %s: %v", extractIP(r), err)
				http.NotFound(w, r)
				return
			}

			registerExplicitProvider(tracking)
			r = withTrackingContext(r, tracking)

			// Compatibility bridge for the existing handler. These fields come
			// from the already validated data payload; no provider discovery is
			// required for new NSL Mailer links.
			q := r.URL.Query()
			q.Set("cid", tracking.CID)
			q.Set("email", tracking.Email)
			q.Set("provider", tracking.Provider)
			if tracking.MailDomain != "" {
				q.Set("mail_domain", tracking.MailDomain)
			}
			r.URL.RawQuery = q.Encode()
		}

		next(w, r)
	}
}
