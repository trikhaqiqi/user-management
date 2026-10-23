package httpx

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"godigi/pkg/apperr"
)

// RequestID accepts a well-formed incoming X-Request-ID (so a trace survives
// the gateway hop) or generates one, and attaches a request-scoped logger.
func RequestID(base *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if !validRequestID(id) {
			id = uuid.NewString()
		}
		c.Request.Header.Set(HeaderRequestID, id)
		c.Set(ctxRequestID, id)
		c.Set(ctxLogger, base.With("request_id", id))
		c.Header(HeaderRequestID, id)
		c.Next()
	}
}

// validRequestID rejects ids that could forge log lines or bloat them.
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		ok := r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

// Recovery turns a panic into a 500 envelope instead of a dropped connection.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				Logger(c).Error("panic recovered", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
				Fail(c, apperr.Internal(fmt.Errorf("panic: %v", r)))
			}
		}()
		c.Next()
	}
}

// BodyLimit caps the request body; reads past the limit fail and BindJSON
// reports them as 413.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// SecurityHeaders sets conservative defaults. Responses carry tokens and
// personal data, so nothing may be cached.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		c.Next()
	}
}

// InternalAuth admits only callers holding the shared internal token, i.e.
// the gateway. Without it, anyone reaching a service directly could assert an
// arbitrary X-User-ID. Both sides are hashed first so the comparison is
// constant-time regardless of length.
func InternalAuth(token string) gin.HandlerFunc {
	want := sha256.Sum256([]byte(token))
	return func(c *gin.Context) {
		got := sha256.Sum256([]byte(c.GetHeader(HeaderInternalToken)))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			Fail(c, apperr.Unauthorized("UNTRUSTED_CALLER", "requests must come through the API gateway"))
			return
		}
		c.Next()
	}
}

// ClientIP prefers the address asserted by the gateway. Services are only
// reachable with the internal token, so the header cannot be client-forged.
func ClientIP(c *gin.Context) string {
	if v := c.GetHeader(HeaderClientIP); v != "" && net.ParseIP(v) != nil {
		return v
	}
	return c.ClientIP()
}
