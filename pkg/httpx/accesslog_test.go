package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"godigi/pkg/apperr"
)

func logLine(t *testing.T, opts AccessLogOptions, method, body string, handler gin.HandlerFunc) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	r := gin.New()
	r.Use(RequestID(log), AccessLog(opts))
	r.Handle(method, "/x", handler)
	req := httptest.NewRequest(method, "/x?secret=should-not-be-logged", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %q", buf.String())
	}
	return line
}

func TestAccessLogRedactsBodies(t *testing.T) {
	body := `{"email":"jane.doe@example.com","password":"Sup3r-secret","nested":{"refresh_token":"rt-123","list":[{"otp":"123456"}]}}`
	line := logLine(t, AccessLogOptions{LogBodies: true}, http.MethodPost, body, func(c *gin.Context) {
		var v map[string]any
		_ = json.NewDecoder(c.Request.Body).Decode(&v)
		OK(c, http.StatusOK, "", gin.H{"access_token": "eyJhbGciOi.secret", "refresh_token": "rt-456", "token_type": "Bearer"})
	})
	raw, _ := json.Marshal(line)
	for _, secret := range []string{"Sup3r-secret", "rt-123", "123456", "eyJhbGciOi", "rt-456", "jane.doe@", "should-not-be-logged"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("log line leaks %q: %s", secret, raw)
		}
	}
	if !strings.Contains(string(raw), `"j***@example.com"`) || !strings.Contains(string(raw), `"Bearer"`) {
		t.Errorf("expected masked email and non-sensitive fields to remain: %s", raw)
	}
	if line["status"].(float64) != 200 || line["route"] != "/x" || line["path"] != "/x" {
		t.Errorf("unexpected request fields: %s", raw)
	}
}

func TestAccessLogErrorCodeAndNoBodiesByDefault(t *testing.T) {
	line := logLine(t, AccessLogOptions{}, http.MethodPost, `{"password":"x"}`, func(c *gin.Context) {
		Fail(c, errUnauthorizedForTest)
	})
	if line["error_code"] != "INVALID_CREDENTIALS" || line["level"] != "WARN" {
		t.Errorf("expected WARN with error_code, got %v", line)
	}
	if _, ok := line["request_body"]; ok {
		t.Error("bodies must not be logged unless enabled")
	}
}

func TestAccessLogOmitsUnparseableAndOversizeBodies(t *testing.T) {
	line := logLine(t, AccessLogOptions{LogBodies: true}, http.MethodPost, `password=hunter2`, func(c *gin.Context) {
		_, _ = c.GetRawData()
		c.Status(http.StatusNoContent)
	})
	if line["request_body"] != "[unparseable JSON omitted]" {
		t.Errorf("got %v", line["request_body"])
	}
	big := `{"password":"` + strings.Repeat("a", 100) + `"}`
	line = logLine(t, AccessLogOptions{LogBodies: true, MaxBodyBytes: 32}, http.MethodPost, big, func(c *gin.Context) {
		_, _ = c.GetRawData()
		c.Status(http.StatusNoContent)
	})
	if line["request_body"] != "[body larger than log limit omitted]" || line["bytes_in"].(float64) != float64(len(big)) {
		t.Errorf("got %v / %v", line["request_body"], line["bytes_in"])
	}
}

var errUnauthorizedForTest = apperr.Unauthorized("INVALID_CREDENTIALS", "invalid email or password")
