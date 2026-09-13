package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
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

// SlackNotifier posts messages to a Slack channel using a Bot User OAuth token
// (starts with `xoxb-`). Requires the `chat:write` scope and the bot must be
// invited to the target channel. For a URL-based integration use WebhookNotifier
// with an incoming-webhook URL instead.
type SlackNotifier struct {
	Token   string
	Channel string
}

func (s SlackNotifier) Name() string { return "slack" }

func (s SlackNotifier) Send(subject, body string) error {
	// Slack markdown ("mrkdwn") — asterisks bold the subject line.
	text := fmt.Sprintf("*%s*\n%s", subject, body)
	payload := map[string]interface{}{
		"channel": s.Channel,
		"text":    text,
		"mrkdwn":  true,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack API returned HTTP %d", resp.StatusCode)
	}
	// Slack returns HTTP 200 for both success and application errors —
	// {"ok":false,"error":"..."} means the message did NOT post.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("read response: %v", err)
	}
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decode response: %v", err)
	}
	if !parsed.OK {
		return fmt.Errorf("slack API rejected message: %s", parsed.Error)
	}
	return nil
}

// StandardWebhookNotifier POSTs a JSON payload signed per the Standard Webhooks
// specification (https://github.com/standard-webhooks/standard-webhooks).
//
// Signature protocol:
//   canonical = <msg_id> "." <unix_timestamp> "." <raw_body>
//   signature = base64(HMAC-SHA256(secret_bytes, canonical))
//   headers: webhook-id:        <msg_id>
//            webhook-timestamp: <unix seconds>
//            webhook-signature: v1,<base64 signature>
//
// The secret may be provided with or without the "whsec_" prefix. When present,
// the prefix is stripped and the remainder is base64-decoded to yield the raw
// HMAC key bytes (matching the reference Go library).
//
// Payload shape (envelope form recommended by the spec, camelCase fields):
//   {
//     "type": <event type — e.g. "slack.notification">,
//     "timestamp": <RFC 3339 ISO 8601>,
//     "data": {
//       "from": <from>, "body": <body>, "title": <subject>,
//       "slackChannelId": <optional>, "slackChannelName": <optional>
//     }
//   }
//
// EventType defaults to "slack.notification" (accepted by mode-iris's
// /messaging/standard/slack endpoint). From defaults to INSTANCE_NAME (or "ETR")
// when STANDARD_WEBHOOK_FROM is unset. SlackChannelID and SlackChannelName are
// optional per-message channel overrides — only added to `data` when non-empty.
type StandardWebhookNotifier struct {
	URL              string
	Secret           string
	From             string
	EventType        string
	SlackChannelID   string
	SlackChannelName string
}

func (s StandardWebhookNotifier) Name() string { return "standard-webhook" }

func (s StandardWebhookNotifier) Send(subject, body string) error {
	eventType := s.EventType
	if eventType == "" {
		eventType = "slack.notification"
	}

	data := map[string]string{
		"from":  s.From,
		"body":  body,
		"title": subject,
	}
	if s.SlackChannelID != "" {
		data["slackChannelId"] = s.SlackChannelID
	}
	if s.SlackChannelName != "" {
		data["slackChannelName"] = s.SlackChannelName
	}

	now := time.Now().UTC()
	envelope := map[string]interface{}{
		"type":      eventType,
		"timestamp": now.Format(time.RFC3339),
		"data":      data,
	}
	rawBody, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal: %v", err)
	}

	key, err := decodeStandardWebhookSecret(s.Secret)
	if err != nil {
		return fmt.Errorf("decode secret: %v", err)
	}

	msgID, err := newStandardWebhookMsgID()
	if err != nil {
		return fmt.Errorf("generate msg id: %v", err)
	}

	timestamp := strconv.FormatInt(now.Unix(), 10)
	canonical := msgID + "." + timestamp + "." + string(rawBody)

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(rawBody))
	if err != nil {
		return fmt.Errorf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", "v1,"+signature)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("standard webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// decodeStandardWebhookSecret returns the raw HMAC key. Accepts both
// "whsec_<base64>" (per the spec) and a bare secret string. Bare strings are
// used as-is so operators aren't forced to base64-encode when generating.
func decodeStandardWebhookSecret(secret string) ([]byte, error) {
	if trimmed := strings.TrimPrefix(secret, "whsec_"); trimmed != secret {
		key, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return []byte(secret), nil
}

// newStandardWebhookMsgID returns a "msg_<hex>" ID with 128 bits of entropy.
func newStandardWebhookMsgID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(buf[:]), nil
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

	// Slack (bot token + channel ID)
	slackToken := os.Getenv("SLACK_BOT_TOKEN")
	slackChannel := os.Getenv("SLACK_CHANNEL_ID")
	if slackToken != "" || slackChannel != "" {
		if slackToken == "" || slackChannel == "" {
			logf("Warning: Slack notifier requires both SLACK_BOT_TOKEN and SLACK_CHANNEL_ID; skipping.\n")
		} else {
			notifiers = append(notifiers, SlackNotifier{Token: slackToken, Channel: slackChannel})
		}
	}

	// Standard Webhooks (https://github.com/standard-webhooks/standard-webhooks)
	stdURL := os.Getenv("STANDARD_WEBHOOK_URL")
	stdSecret := os.Getenv("STANDARD_WEBHOOK_SECRET")
	if stdURL != "" || stdSecret != "" {
		if stdURL == "" || stdSecret == "" {
			logf("Warning: standard webhook notifier requires both STANDARD_WEBHOOK_URL and STANDARD_WEBHOOK_SECRET; skipping.\n")
		} else {
			from := os.Getenv("STANDARD_WEBHOOK_FROM")
			if from == "" {
				from = os.Getenv("INSTANCE_NAME")
			}
			if from == "" {
				from = "ETR"
			}
			notifiers = append(notifiers, StandardWebhookNotifier{
				URL:              stdURL,
				Secret:           stdSecret,
				From:             from,
				EventType:        os.Getenv("STANDARD_WEBHOOK_EVENT_TYPE"),
				SlackChannelID:   os.Getenv("STANDARD_WEBHOOK_SLACK_CHANNEL_ID"),
				SlackChannelName: os.Getenv("STANDARD_WEBHOOK_SLACK_CHANNEL_NAME"),
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
