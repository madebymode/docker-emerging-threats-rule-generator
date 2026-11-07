package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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
		return fmt.Errorf("post: %v", safeHTTPError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}
	return nil
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
		return fmt.Errorf("build request: %v", safeHTTPError(err))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %v", safeHTTPError(err))
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
		return fmt.Errorf("post: %v", safeHTTPError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
