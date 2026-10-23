package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const resendEndpoint = "https://api.resend.com/emails"

// ResendSender delivers mail through the Resend HTTP API
// (https://resend.com/docs/api-reference/emails/send-email).
type ResendSender struct {
	APIKey   string
	From     string
	Endpoint string
	Client   *http.Client
}

func NewResendSender(apiKey, from string) *ResendSender {
	return &ResendSender{
		APIKey:   apiKey,
		From:     from,
		Endpoint: resendEndpoint,
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// PermanentError marks a failure that retrying cannot fix (a rejected
// recipient, an unverified sender domain, a bad API key). The async worker
// gives up on these immediately.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

func (r *ResendSender) Send(ctx context.Context, m Message) error {
	if _, err := render(r.From, m); err != nil { // same header-injection guard as SMTP
		return &PermanentError{Err: err}
	}
	payload, err := json.Marshal(map[string]any{
		"from":    r.From,
		"to":      []string{m.To},
		"subject": m.Subject,
		"text":    m.Body,
	})
	if err != nil {
		return &PermanentError{Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("Content-Type", "application/json")
	// Resend deduplicates on this key, so a retry after a timeout can't
	// deliver the same code twice. The key is per attempt-series because
	// the worker reuses the same Message value for its retries.
	req.Header.Set("Idempotency-Key", m.idempotencyKey())

	res, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("resend request: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}

	var apiErr struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &apiErr)
	err = fmt.Errorf("resend: HTTP %d %s: %s", res.StatusCode, apiErr.Name, apiErr.Message)
	if res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500 {
		return err // transient: let the worker retry
	}
	return &PermanentError{Err: err}
}

func isPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}
