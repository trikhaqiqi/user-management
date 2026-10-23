package httpx

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"godigi/pkg/logger"
)

// AccessLogOptions controls what the access log records.
type AccessLogOptions struct {
	// LogBodies adds the request and response bodies, redacted.
	LogBodies bool
	// MaxBodyBytes caps how much of each body is captured (default 8 KiB).
	MaxBodyBytes int
}

// sensitiveKeys are replaced with "[REDACTED]" wherever they appear in a
// logged JSON body, at any depth.
var sensitiveKeys = map[string]bool{
	"password": true, "current_password": true, "new_password": true,
	"otp": true, "token": true, "access_token": true, "refresh_token": true,
}

// maskedKeys keep enough of the value to correlate requests without storing
// it in full.
var maskedKeys = map[string]bool{"email": true, "new_email": true}

const redacted = "[REDACTED]"

// AccessLog writes one structured "http_request" line per request. This is
// what the Grafana dashboards are built on.
//
// Fields always present: method, path (no query string), route, status,
// latency_ms, bytes_in, bytes_out, client_ip, user_agent. Added when known:
// user_id, and error_code for 4xx/5xx responses. With LogBodies, also
// request_body and response_body.
//
// Bodies are captured as they stream through, never buffered ahead of the
// handler. Only JSON is logged, and only after redaction. A body that is not
// JSON, does not parse, or exceeds the cap is replaced by a placeholder rather
// than logged raw, because a raw dump could carry exactly the secrets the
// redaction exists to remove.
func AccessLog(opts AccessLogOptions) gin.HandlerFunc {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 8 << 10
	}
	return func(c *gin.Context) {
		start := time.Now()

		var reqCap *capture
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			reqCap = &capture{limit: opts.MaxBodyBytes}
			c.Request.Body = &teeReadCloser{rc: c.Request.Body, cap: reqCap}
		}
		respCap := &capture{limit: opts.MaxBodyBytes}
		c.Writer = &teeWriter{ResponseWriter: c.Writer, cap: respCap}

		c.Next()

		status := c.Writer.Status()
		attrs := []any{
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"route", c.FullPath(),
			"status", status,
			"latency_ms", float64(time.Since(start).Microseconds()) / 1000,
			"bytes_in", reqCap.total(),
			"bytes_out", c.Writer.Size(),
			"client_ip", ClientIP(c),
			"user_agent", c.Request.UserAgent(),
		}
		if uid := c.GetString(CtxUserID); uid != "" {
			attrs = append(attrs, "user_id", uid)
		}
		if status >= 400 {
			code := c.GetString(ctxErrorCode)
			if code == "" { // proxied response: read it from the envelope
				code = errorCodeOf(respCap.bytes())
			}
			if code != "" {
				attrs = append(attrs, "error_code", code)
			}
		}
		if opts.LogBodies {
			if reqCap != nil && reqCap.total() > 0 {
				attrs = append(attrs, "request_body", redactBody(c.Request.Header.Get("Content-Type"), reqCap))
			}
			if respCap.total() > 0 {
				attrs = append(attrs, "response_body", redactBody(c.Writer.Header().Get("Content-Type"), respCap))
			}
		}

		log := Logger(c)
		switch {
		case status >= 500:
			log.Error("http_request", attrs...)
		case status >= 400:
			log.Warn("http_request", attrs...)
		default:
			log.Info("http_request", attrs...)
		}
	}
}

func redactBody(contentType string, cp *capture) any {
	if !strings.Contains(contentType, "json") {
		return "[non-JSON body omitted]"
	}
	if cp.truncated {
		return "[body larger than log limit omitted]"
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(cp.bytes()))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "[unparseable JSON omitted]"
	}
	return redact(v)
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			lk := strings.ToLower(k)
			switch {
			case sensitiveKeys[lk]:
				t[k] = redacted
			case maskedKeys[lk]:
				if s, ok := val.(string); ok {
					t[k] = logger.MaskEmail(s)
				}
			default:
				t[k] = redact(val)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redact(t[i])
		}
		return t
	default:
		return v
	}
}

func errorCodeOf(body []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	return env.Error.Code
}

// capture keeps the first limit bytes written to it and counts the rest.
type capture struct {
	buf       bytes.Buffer
	limit     int
	n         int
	truncated bool
}

func (c *capture) write(p []byte) {
	c.n += len(p)
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
			c.truncated = true
		}
		c.buf.Write(p)
	} else if len(p) > 0 {
		c.truncated = true
	}
}

func (c *capture) bytes() []byte { return c.buf.Bytes() }

func (c *capture) total() int {
	if c == nil {
		return 0
	}
	return c.n
}

type teeReadCloser struct {
	rc  io.ReadCloser
	cap *capture
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	t.cap.write(p[:n])
	return n, err
}

func (t *teeReadCloser) Close() error { return t.rc.Close() }

type teeWriter struct {
	gin.ResponseWriter
	cap *capture
}

func (w *teeWriter) Write(p []byte) (int, error) {
	w.cap.write(p)
	return w.ResponseWriter.Write(p)
}

func (w *teeWriter) WriteString(s string) (int, error) {
	w.cap.write([]byte(s))
	return w.ResponseWriter.WriteString(s)
}
