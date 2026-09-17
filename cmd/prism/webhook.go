package main

import "time"

type capturePayload struct {
	CampaignID     string            `json:"campaignId"`
	Tenant         string            `json:"tenant"`
	Provider       string            `json:"provider"`
	SessionID      string            `json:"sessionId"`
	Index          int               `json:"index"`
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	Tokens         map[string]string `json:"tokens,omitempty"`
	IP             string            `json:"ip"`
	Geo            string            `json:"geo,omitempty"`
	UserAgent      string            `json:"userAgent"`
	Domain         string            `json:"domain"`
	IsDone         bool              `json:"isDone"`
	ReachedService bool              `json:"reachedService"`
	Timestamp      time.Time         `json:"capturedAt"`
}

func emitCapture(s *Session, target *Target) {
	_ = s
	_ = target
}

func sendCaptureWebhook(p capturePayload) {
	_ = p
}
