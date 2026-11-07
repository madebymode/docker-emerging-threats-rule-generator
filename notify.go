package main

import (
	"os"
	"strings"
)

// Notifier is the interface implemented by all notification channels.
type Notifier interface {
	Send(subject, body string) error
	Name() string
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
