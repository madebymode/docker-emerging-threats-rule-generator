package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clearNotifyEnv unsets all notification-related ENV vars.
func clearNotifyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
		"SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_TO", "SMTP_USER", "SMTP_PASS",
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

// errNotifier always returns an error; used to test that notify() doesn't panic.
type errNotifier struct{}

func (errNotifier) Name() string           { return "error-notifier" }
func (errNotifier) Send(_, _ string) error { return fmt.Errorf("injected failure") }

func TestNotify_logsError(t *testing.T) {
	// Should not panic even when a notifier fails.
	notifiers := []Notifier{errNotifier{}}
	notify(notifiers, "subject", "body") // must not panic
}
