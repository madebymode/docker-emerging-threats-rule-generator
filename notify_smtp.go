package main

import (
	"net/smtp"
	"strings"
)

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
