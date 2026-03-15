package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// Notifier is the interface implemented by all notification channels.
type Notifier interface {
	Send(subject, body string) error
	Name() string
}

// TelegramNotifier sends messages via the Telegram Bot API.
type TelegramNotifier struct {
	Token  string
	ChatID string
}

func (t TelegramNotifier) Name() string { return "telegram" }

func (t TelegramNotifier) Send(subject, body string) error {
	text := fmt.Sprintf("*%s*\n\n%s", subject, body)
	payload := map[string]string{
		"chat_id":    t.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %v", err)
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}
	return nil
}

// SMTPNotifier sends messages via SMTP (STARTTLS, port 587 by default).
type SMTPNotifier struct {
	Host string
	Port string
	From string
	To   []string
	User string
	Pass string
}

func (s SMTPNotifier) Name() string { return "smtp" }

func (s SMTPNotifier) Send(subject, body string) error {
	addr := s.Host + ":" + s.Port
	msg := []byte("From: " + s.From + "\r\n" +
		"To: " + strings.Join(s.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Pass, s.Host)
	}
	return smtp.SendMail(addr, auth, s.From, s.To, msg)
}

// WebhookNotifier POSTs a JSON payload to an arbitrary URL.
type WebhookNotifier struct {
	URL string
}

func (w WebhookNotifier) Name() string { return "webhook" }

func (w WebhookNotifier) Send(subject, body string) error {
	payload := map[string]string{"subject": subject, "body": body}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %v", err)
	}
	resp, err := httpClient.Post(w.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// loadNotifiers reads ENV vars and returns fully-configured notifiers.
// Partially-configured channels are skipped with a warning log.
func loadNotifiers() []Notifier {
	var notifiers []Notifier

	// Telegram
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token != "" || chatID != "" {
		if token == "" || chatID == "" {
			logf("Warning: Telegram notifier requires both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID; skipping.\n")
		} else {
			notifiers = append(notifiers, TelegramNotifier{Token: token, ChatID: chatID})
		}
	}

	// SMTP
	smtpHost := os.Getenv("SMTP_HOST")
	smtpFrom := os.Getenv("SMTP_FROM")
	smtpTo := os.Getenv("SMTP_TO")
	if smtpHost != "" || smtpFrom != "" || smtpTo != "" {
		if smtpHost == "" || smtpFrom == "" || smtpTo == "" {
			logf("Warning: SMTP notifier requires SMTP_HOST, SMTP_FROM, and SMTP_TO; skipping.\n")
		} else {
			port := os.Getenv("SMTP_PORT")
			if port == "" {
				port = "587"
			}
			recipients := strings.Split(smtpTo, ",")
			for i, r := range recipients {
				recipients[i] = strings.TrimSpace(r)
			}
			notifiers = append(notifiers, SMTPNotifier{
				Host: smtpHost,
				Port: port,
				From: smtpFrom,
				To:   recipients,
				User: os.Getenv("SMTP_USER"),
				Pass: os.Getenv("SMTP_PASS"),
			})
		}
	}

	// Webhook
	webhookURL := os.Getenv("WEBHOOK_URL")
	if webhookURL != "" {
		notifiers = append(notifiers, WebhookNotifier{URL: webhookURL})
	}

	return notifiers
}

// notify sends subject+body to all notifiers, logging per-channel success/failure.
// It never calls logf("Fatal") or os.Exit — all errors are non-fatal.
func notify(notifiers []Notifier, subject, body string) {
	for _, n := range notifiers {
		if err := n.Send(subject, body); err != nil {
			logf("Notification via %s failed: %v\n", n.Name(), err)
		} else {
			logf("Notification sent via %s.\n", n.Name())
		}
	}
}
