package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResendSender(t *testing.T) {
	var got map[string]any
	var auth, idem string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, idem = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"name":"validation_error","message":"nope"}`))
	}))
	defer srv.Close()

	s := NewResendSender("re_test", "Godigi <onboarding@resend.dev>")
	s.Endpoint = srv.URL
	msg := Message{To: "jane@example.com", Subject: "Hi", Body: "code 123456", id: "fixed-id"}

	if err := s.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer re_test" || idem != "fixed-id" {
		t.Errorf("headers: auth=%q idempotency=%q", auth, idem)
	}
	if got["from"] != "Godigi <onboarding@resend.dev>" || got["subject"] != "Hi" || got["text"] != "code 123456" {
		t.Errorf("payload: %v", got)
	}
	if to, _ := got["to"].([]any); len(to) != 1 || to[0] != "jane@example.com" {
		t.Errorf("to: %v", got["to"])
	}

	status = http.StatusForbidden
	if err := s.Send(context.Background(), msg); err == nil || !isPermanent(err) {
		t.Errorf("403 must be a permanent error, got %v", err)
	}
	status = http.StatusTooManyRequests
	if err := s.Send(context.Background(), msg); err == nil || isPermanent(err) {
		t.Errorf("429 must be retryable, got %v", err)
	}
	if err := s.Send(context.Background(), Message{To: "a@b.c\r\nBcc: x@y.z", Subject: "s"}); !isPermanent(err) {
		t.Errorf("header injection must be rejected, got %v", err)
	}
}
