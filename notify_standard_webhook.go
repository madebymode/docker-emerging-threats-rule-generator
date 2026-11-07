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
	"net/http"
	"strconv"
	"strings"
	"time"
)

// StandardWebhookNotifier POSTs a JSON payload signed per the Standard Webhooks
// specification (https://github.com/standard-webhooks/standard-webhooks).
//
// Signature protocol:
//
//	canonical = <msg_id> "." <unix_timestamp> "." <raw_body>
//	signature = base64(HMAC-SHA256(secret_bytes, canonical))
//	headers: webhook-id:        <msg_id>
//	         webhook-timestamp: <unix seconds>
//	         webhook-signature: v1,<base64 signature>
//
// The secret may be provided with or without the "whsec_" prefix. When present,
// the prefix is stripped and the remainder is base64-decoded to yield the raw
// HMAC key bytes (matching the reference Go library).
//
// Payload shape (envelope form recommended by the spec, camelCase fields):
//
//	{
//	  "type": <event type — e.g. "slack.notification">,
//	  "timestamp": <RFC 3339 ISO 8601>,
//	  "data": {
//	    "from": <from>, "body": <body>, "title": <subject>,
//	    "slackChannelId": <optional>, "slackChannelName": <optional>
//	  }
//	}
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
		return fmt.Errorf("build request: %v", safeHTTPError(err))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", "v1,"+signature)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %v", safeHTTPError(err))
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
