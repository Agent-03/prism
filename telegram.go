package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type TelegramVisitorEvent struct {
	Timestamp  time.Time
	IP         string
	Country    string
	CampaignID string
	Provider   string
	MailDomain string
	Host       string
	Path       string
	Method     string
	UserAgent  string
	CFRay      string
}

// SendVisitorAlert keeps backward compatibility with existing callers.
func SendVisitorAlert(ip, userAgent, country, campaignID string) {
	SendVisitorAlertEvent(TelegramVisitorEvent{
		Timestamp:  time.Now().UTC(),
		IP:         ip,
		Country:    country,
		CampaignID: campaignID,
		UserAgent:  userAgent,
	})
}

// SendVisitorAlertEvent sends an expanded operational visitor alert.
func SendVisitorAlertEvent(event TelegramVisitorEvent) {
	botToken := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))

	if botToken == "" || chatID == "" {
		return
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	country := cleanTelegramField(event.Country, "Unknown")
	campaignID := cleanTelegramField(event.CampaignID, "Unknown")
	provider := cleanTelegramField(event.Provider, "Unknown")
	mailDomain := cleanTelegramField(event.MailDomain, "N/A")
	ip := cleanTelegramField(event.IP, "Unknown")
	host := cleanTelegramField(event.Host, "Unknown")
	path := cleanTelegramField(event.Path, "/")
	method := cleanTelegramField(event.Method, "GET")
	cfRay := cleanTelegramField(event.CFRay, "Unknown")
	userAgent := cleanTelegramField(event.UserAgent, "Unknown")

	msg := fmt.Sprintf(
		"👁️ <b>New Visitor Detected</b>\n\n"+
			"🕒 <b>Time:</b> <code>%s</code>\n"+
			"🌍 <b>Country:</b> %s\n"+
			"🔗 <b>Campaign:</b> <code>%s</code>\n"+
			"📨 <b>Provider:</b> <code>%s</code>\n"+
			"📬 <b>Mail Domain:</b> <code>%s</code>\n"+
			"🌐 <b>Host:</b> <code>%s</code>\n"+
			"📍 <b>Request:</b> <code>%s %s</code>\n"+
			"🌐 <b>IP:</b> <code>%s</code>\n"+
			"☁️ <b>CF Ray:</b> <code>%s</code>\n"+
			"📱 <b>User Agent:</b> <i>%s</i>",
		html.EscapeString(event.Timestamp.UTC().Format(time.RFC3339)),
		html.EscapeString(country),
		html.EscapeString(campaignID),
		html.EscapeString(provider),
		html.EscapeString(mailDomain),
		html.EscapeString(host),
		html.EscapeString(method),
		html.EscapeString(path),
		html.EscapeString(ip),
		html.EscapeString(cfRay),
		html.EscapeString(userAgent),
	)

	sendTelegramMessage(botToken, chatID, msg)
}

func cleanTelegramField(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	const max = 700
	if len(value) > max {
		return value[:max] + "…"
	}

	return value
}

func sendTelegramMessage(token, chatID, text string) {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payload := map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Telegram] marshal error: %v", err)
		return
	}

	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(endpoint, "application/json", bytes.NewReader(jsonData))
		if err != nil {
			log.Printf("[Telegram] request error: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			log.Printf("[Telegram] HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}()
}
