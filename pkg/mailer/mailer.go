// Package mailer is the mock email/SMTP provider.
//
// Codes and reset tokens travel only through this channel. They are never
// logged and never returned in API responses. In development the SMTP driver
// points at Mailpit (a local inbox with a web UI) and the file driver writes
// .eml files to an outbox directory.
package mailer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"godigi/pkg/config"
	"godigi/pkg/logger"
)

type Message struct {
	To      string
	Subject string
	Body    string
	// id identifies one logical email across retries (see Resend's
	// Idempotency-Key). Assigned on Enqueue.
	id string
}

func (m Message) idempotencyKey() string {
	if m.id == "" {
		return uuid.NewString()
	}
	return m.id
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

// FromEnv builds the configured sender: MAIL_DRIVER=resend|smtp|file.
func FromEnv(l *config.Loader) Sender {
	from := l.String("MAIL_FROM", "Godigi <no-reply@godigi.local>")
	switch driver := l.String("MAIL_DRIVER", "smtp"); driver {
	case "resend":
		return NewResendSender(l.Secret("RESEND_API_KEY", 10), from)
	case "file":
		return &FileSender{Dir: l.String("MAIL_OUTBOX_DIR", "./tmp/outbox"), From: from}
	default:
		return &SMTPSender{
			Addr:     l.String("SMTP_ADDR", "localhost:1025"),
			From:     from,
			Username: l.String("SMTP_USERNAME", ""),
			Password: l.String("SMTP_PASSWORD", ""),
		}
	}
}

func render(from string, m Message) ([]byte, error) {
	// Refuse header injection through any header value.
	for _, v := range []string{from, m.To, m.Subject} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("mail header contains a line break")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", m.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", m.Subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(m.Body, "\n", "\r\n"))
	return []byte(b.String()), nil
}

type SMTPSender struct {
	Addr, From, Username, Password string
}

func (s *SMTPSender) Send(_ context.Context, m Message) error {
	msg, err := render(s.From, m)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if s.Username != "" {
		host, _, _ := net.SplitHostPort(s.Addr)
		auth = smtp.PlainAuth("", s.Username, s.Password, host)
	}
	envelopeFrom := s.From
	if i := strings.LastIndex(envelopeFrom, "<"); i >= 0 {
		envelopeFrom = strings.TrimSuffix(envelopeFrom[i+1:], ">")
	}
	return smtp.SendMail(s.Addr, auth, envelopeFrom, []string{m.To}, msg)
}

// FileSender writes each message to Dir as an .eml file (mode 0600).
type FileSender struct {
	Dir, From string
}

func (f *FileSender) Send(_ context.Context, m Message) error {
	msg, err := render(f.From, m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("%s-%s.eml", time.Now().UTC().Format("20060102T150405.000000000"), hex.EncodeToString(suffix))
	return os.WriteFile(filepath.Join(f.Dir, name), msg, 0o600)
}

// Async sends mail from a small worker pool, so API latency doesn't depend on
// the mail provider. It also keeps response timing independent of whether an
// email was actually sent, which matters for anti-enumeration. Close drains
// the queue on shutdown.
type Async struct {
	next   Sender
	log    *slog.Logger
	queue  chan Message
	wg     sync.WaitGroup
	mu     sync.RWMutex
	closed bool
}

func NewAsync(next Sender, log *slog.Logger, workers, buffer int) *Async {
	a := &Async{next: next, log: log, queue: make(chan Message, buffer)}
	for i := 0; i < workers; i++ {
		a.wg.Add(1)
		go a.work()
	}
	return a
}

func (a *Async) Enqueue(m Message) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.log.Error("mail dropped: mailer closed", "to", logger.MaskEmail(m.To), "subject", m.Subject)
		return
	}
	m.id = uuid.NewString()
	select {
	case a.queue <- m:
	default:
		a.log.Error("mail dropped: queue full", "to", logger.MaskEmail(m.To), "subject", m.Subject)
	}
}

func (a *Async) work() {
	defer a.wg.Done()
	for m := range a.queue {
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = a.next.Send(ctx, m)
			cancel()
			if err == nil {
				a.log.Info("mail sent", "to", logger.MaskEmail(m.To), "subject", m.Subject)
				break
			}
			if isPermanent(err) {
				break
			}
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		if err != nil {
			// Body omitted on purpose: it contains the code or token.
			a.log.Error("mail delivery failed", "to", logger.MaskEmail(m.To), "subject", m.Subject, "error", err.Error())
		}
	}
}

func (a *Async) Close() {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.mu.Unlock()
	a.wg.Wait()
}
