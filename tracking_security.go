package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
)

const (
	edgeAuthHeader        = "X-EdgeGuard-Origin-Auth"
	maxTrackingDataLength = 1800
)

var (
	campaignIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,160}$`)
	providerPattern   = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,80}$`)
)

type TrackingPayload struct {
	CID      string `json:"cid"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
}

type trackingContextKey struct{}

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
