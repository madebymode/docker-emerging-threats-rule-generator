package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// clearNotifyEnv unsets all notification-related ENV vars.
func clearNotifyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
		"SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_TO", "SMTP_USER", "SMTP_PASS",
		"SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID",
		"STANDARD_WEBHOOK_URL", "STANDARD_WEBHOOK_SECRET", "STANDARD_WEBHOOK_FROM",
		"INSTANCE_NAME",
		"WEBHOOK_URL",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadNotifiers_none(t *testing.T) {
	clearNotifyEnv(t)
	notifiers := loadNotifiers()
	if len(notifiers) != 0 {
		t.Errorf("expected 0 notifiers, got %d", len(notifiers))
	}
}

func TestLoadNotifiers_partial(t *testing.T) {
	clearNotifyEnv(t)
	// Only token set, no chat ID — should be skipped.
	t.Setenv("TELEGRAM_BOT_TOKEN", "abc123")
	notifiers := loadNotifiers()
	if len(notifiers) != 0 {
		t.Errorf("expected 0 notifiers (partial config), got %d", len(notifiers))
	}
}

func TestLoadNotifiers_telegram(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "mytoken")
	t.Setenv("TELEGRAM_CHAT_ID", "99999")
	notifiers := loadNotifiers()
	if len(notifiers) != 1 {
		t.Fatalf("expected 1 notifier, got %d", len(notifiers))
	}
	if notifiers[0].Name() != "telegram" {
		t.Errorf("expected name 'telegram', got %q", notifiers[0].Name())
	}
	tn, ok := notifiers[0].(TelegramNotifier)
	if !ok {
		t.Fatalf("expected TelegramNotifier, got %T", notifiers[0])
	}
	if tn.Token != "mytoken" || tn.ChatID != "99999" {
		t.Errorf("unexpected token/chatID: %+v", tn)
	}
}

func TestLoadNotifiers_smtp(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_TO", "to@example.com")
	// SMTP_PORT not set → should default to 587
	notifiers := loadNotifiers()
	if len(notifiers) != 1 {
		t.Fatalf("expected 1 notifier, got %d", len(notifiers))
	}
	if notifiers[0].Name() != "smtp" {
		t.Errorf("expected name 'smtp', got %q", notifiers[0].Name())
	}
	sn, ok := notifiers[0].(SMTPNotifier)
	if !ok {
		t.Fatalf("expected SMTPNotifier, got %T", notifiers[0])
	}
	if sn.Port != "587" {
		t.Errorf("expected default port 587, got %q", sn.Port)
	}
	if sn.Host != "smtp.example.com" {
		t.Errorf("unexpected host: %q", sn.Host)
	}
}

func TestLoadNotifiers_webhook(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("WEBHOOK_URL", "https://hooks.example.com/notify")
	notifiers := loadNotifiers()
	if len(notifiers) != 1 {
		t.Fatalf("expected 1 notifier, got %d", len(notifiers))
	}
	if notifiers[0].Name() != "webhook" {
		t.Errorf("expected name 'webhook', got %q", notifiers[0].Name())
	}
	wn, ok := notifiers[0].(WebhookNotifier)
	if !ok {
		t.Fatalf("expected WebhookNotifier, got %T", notifiers[0])
	}
	if wn.URL != "https://hooks.example.com/notify" {
		t.Errorf("unexpected URL: %q", wn.URL)
	}
}

// telegramSendWithBase sends a Telegram message using a custom base URL (for tests).
func telegramSendWithBase(tn TelegramNotifier, baseURL, subject, body string) error {
	text := fmt.Sprintf("*%s*\n\n%s", subject, body)
	payload := map[string]string{
		"chat_id":    tn.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := baseURL + "/bot" + tn.Token + "/sendMessage"
	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}
	return nil
}

func TestTelegramNotifier_send(t *testing.T) {
	var received map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tn := TelegramNotifier{Token: "testtoken", ChatID: "12345"}
	if err := telegramSendWithBase(tn, srv.URL, "Test Subject", "Test body"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if received["chat_id"] != "12345" {
		t.Errorf("expected chat_id 12345, got %q", received["chat_id"])
	}
	if !strings.Contains(received["text"], "Test Subject") {
		t.Errorf("expected text to contain subject, got %q", received["text"])
	}
	if !strings.Contains(received["text"], "Test body") {
		t.Errorf("expected text to contain body, got %q", received["text"])
	}
}

func TestLoadNotifiers_slack(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-fake-token")
	t.Setenv("SLACK_CHANNEL_ID", "C12345")
	notifiers := loadNotifiers()
	if len(notifiers) != 1 {
		t.Fatalf("expected 1 notifier, got %d", len(notifiers))
	}
	sn, ok := notifiers[0].(SlackNotifier)
	if !ok {
		t.Fatalf("expected SlackNotifier, got %T", notifiers[0])
	}
	if sn.Token != "xoxb-fake-token" || sn.Channel != "C12345" {
		t.Errorf("unexpected token/channel: %+v", sn)
	}
}

func TestLoadNotifiers_slack_partial(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-fake-token")
	// SLACK_CHANNEL_ID intentionally unset — should be skipped.
	notifiers := loadNotifiers()
	if len(notifiers) != 0 {
		t.Errorf("expected 0 notifiers (partial slack config), got %d", len(notifiers))
	}
}

// slackSendWithBase posts to a custom URL for tests. Mirrors SlackNotifier.Send.
func slackSendWithBase(sn SlackNotifier, baseURL, subject, body string) error {
	text := fmt.Sprintf("*%s*\n%s", subject, body)
	payload := map[string]interface{}{
		"channel": sn.Channel,
		"text":    text,
		"mrkdwn":  true,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+sn.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack API returned HTTP %d", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return err
	}
	if !parsed.OK {
		return fmt.Errorf("slack API rejected message: %s", parsed.Error)
	}
	return nil
}

func TestSlackNotifier_send_success(t *testing.T) {
	var receivedBody map[string]interface{}
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sn := SlackNotifier{Token: "xoxb-fake", Channel: "C99999"}
	if err := slackSendWithBase(sn, srv.URL, "Alert", "50k blocks in 5m"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if receivedAuth != "Bearer xoxb-fake" {
		t.Errorf("expected Bearer auth header, got %q", receivedAuth)
	}
	if receivedBody["channel"] != "C99999" {
		t.Errorf("expected channel C99999, got %v", receivedBody["channel"])
	}
	text, _ := receivedBody["text"].(string)
	if !strings.Contains(text, "Alert") || !strings.Contains(text, "50k blocks in 5m") {
		t.Errorf("text missing subject or body: %q", text)
	}
}

func TestSlackNotifier_send_apiError(t *testing.T) {
	// Slack returns HTTP 200 with ok:false when the message is rejected —
	// the notifier must surface that as an error, not silently succeed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
	}))
	defer srv.Close()

	sn := SlackNotifier{Token: "xoxb-fake", Channel: "Cbogus"}
	err := slackSendWithBase(sn, srv.URL, "s", "b")
	if err == nil {
		t.Fatal("expected error for ok:false response, got nil")
	}
	if !strings.Contains(err.Error(), "channel_not_found") {
		t.Errorf("expected error to mention channel_not_found, got %v", err)
	}
}

func TestWebhookNotifier_send(t *testing.T) {
	var received map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wn := WebhookNotifier{URL: srv.URL}
	if err := wn.Send("Alert", "Something broke"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if received["subject"] != "Alert" {
		t.Errorf("expected subject 'Alert', got %q", received["subject"])
	}
	if received["body"] != "Something broke" {
		t.Errorf("expected body 'Something broke', got %q", received["body"])
	}
}

func TestLoadNotifiers_standardWebhook(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("STANDARD_WEBHOOK_URL", "https://webhook.example.com/messaging/standard")
	t.Setenv("STANDARD_WEBHOOK_SECRET", "sekret")
	t.Setenv("INSTANCE_NAME", "prod-eu")
	notifiers := loadNotifiers()
	if len(notifiers) != 1 {
		t.Fatalf("expected 1 notifier, got %d", len(notifiers))
	}
	sw, ok := notifiers[0].(StandardWebhookNotifier)
	if !ok {
		t.Fatalf("expected StandardWebhookNotifier, got %T", notifiers[0])
	}
	if sw.From != "prod-eu" {
		t.Errorf("expected From to fall back to INSTANCE_NAME, got %q", sw.From)
	}
}

func TestLoadNotifiers_standardWebhook_partial(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("STANDARD_WEBHOOK_URL", "https://webhook.example.com/x")
	// Secret intentionally unset — must skip and warn, not panic.
	notifiers := loadNotifiers()
	if len(notifiers) != 0 {
		t.Errorf("expected 0 notifiers (partial standard-webhook), got %d", len(notifiers))
	}
}

func TestLoadNotifiers_standardWebhook_fromDefault(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv("STANDARD_WEBHOOK_URL", "https://webhook.example.com/x")
	t.Setenv("STANDARD_WEBHOOK_SECRET", "s")
	notifiers := loadNotifiers()
	sw := notifiers[0].(StandardWebhookNotifier)
	if sw.From != "ETR" {
		t.Errorf("expected From to default to 'ETR' when no INSTANCE_NAME, got %q", sw.From)
	}
}

func TestDecodeStandardWebhookSecret(t *testing.T) {
	// Bare secret is passed through unmodified.
	if got, err := decodeStandardWebhookSecret("plain-secret"); err != nil || string(got) != "plain-secret" {
		t.Errorf("bare secret: got %q err=%v", got, err)
	}
	// whsec_-prefixed secret is base64-decoded.
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := "whsec_" + base64.StdEncoding.EncodeToString(raw)
	got, err := decodeStandardWebhookSecret(encoded)
	if err != nil {
		t.Fatalf("whsec_ prefixed: err=%v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("whsec_ prefixed: got %x, want %x", got, raw)
	}
	// Invalid base64 after prefix must error.
	if _, err := decodeStandardWebhookSecret("whsec_not!valid!base64"); err == nil {
		t.Error("expected error for invalid base64 after whsec_")
	}
}

// TestStandardWebhookNotifier_end_to_end verifies the signature the sender
// produces matches what a Standard Webhooks receiver would compute. Regression
// guard against sender/receiver contract drift.
func TestStandardWebhookNotifier_end_to_end(t *testing.T) {
	// Use whsec_-prefixed secret to exercise the base64 decode path.
	keyBytes := []byte("test-secret-42-raw-bytes-goes-here")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(keyBytes)

	var (
		receivedPath      string
		receivedMsgID     string
		receivedTimestamp string
		receivedSignature string
		receivedBody      []byte
		receivedFrom      string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMsgID = r.Header.Get("webhook-id")
		receivedTimestamp = r.Header.Get("webhook-timestamp")
		receivedSignature = r.Header.Get("webhook-signature")
		receivedBody, _ = io.ReadAll(r.Body)

		// Re-derive the signature the way any Standard Webhooks receiver would.
		canonical := receivedMsgID + "." + receivedTimestamp + "." + string(receivedBody)
		mac := hmac.New(sha256.New, keyBytes)
		_, _ = mac.Write([]byte(canonical))
		expected := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(receivedSignature), []byte(expected)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Spec: reject timestamps outside a 5-minute tolerance window.
		ts, err := strconv.ParseInt(receivedTimestamp, 10, 64)
		if err != nil || time.Since(time.Unix(ts, 0)) > 5*time.Minute {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var envelope struct {
			Type      string            `json:"type"`
			Timestamp string            `json:"timestamp"`
			Data      map[string]string `json:"data"`
		}
		_ = json.Unmarshal(receivedBody, &envelope)
		receivedFrom = envelope.Data["from"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sn := StandardWebhookNotifier{
		URL:    srv.URL + "/messaging/standard?ignored=true",
		Secret: secret,
		From:   "etr-prod",
	}
	if err := sn.Send("Blocklist update abandoned", "42% of upstream sources failed"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if receivedPath != "/messaging/standard" {
		t.Errorf("expected path /messaging/standard, got %q", receivedPath)
	}
	if !strings.HasPrefix(receivedMsgID, "msg_") {
		t.Errorf("expected webhook-id to start with msg_, got %q", receivedMsgID)
	}
	if !strings.HasPrefix(receivedSignature, "v1,") {
		t.Errorf("expected v1, prefix on signature, got %q", receivedSignature)
	}
	if receivedFrom != "etr-prod" {
		t.Errorf("expected data.from=etr-prod in payload, got %q", receivedFrom)
	}
	var envelope struct {
		Type      string            `json:"type"`
		Timestamp string            `json:"timestamp"`
		Data      map[string]string `json:"data"`
	}
	if err := json.Unmarshal(receivedBody, &envelope); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if envelope.Type != "slack.notification" {
		t.Errorf("expected envelope.type=slack.notification, got %q", envelope.Type)
	}
	if envelope.Data["body"] != "42% of upstream sources failed" {
		t.Errorf("unexpected data.body: %q", envelope.Data["body"])
	}
	if envelope.Data["title"] != "Blocklist update abandoned" {
		t.Errorf("unexpected data.title: %q", envelope.Data["title"])
	}
}

// errNotifier always returns an error; used to test that notify() doesn't panic.
type errNotifier struct{}

func (errNotifier) Name() string           { return "error-notifier" }
func (errNotifier) Send(_, _ string) error { return fmt.Errorf("injected failure") }

func TestNotify_logsError(t *testing.T) {
	// Should not panic even when a notifier fails.
	notifiers := []Notifier{errNotifier{}}
	notify(notifiers, "subject", "body") // must not panic
}
