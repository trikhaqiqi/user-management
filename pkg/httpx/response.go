package httpx

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"godigi/pkg/apperr"
)

type envelope struct {
	Success   bool       `json:"success"`
	Message   string     `json:"message,omitempty"`
	Data      any        `json:"data,omitempty"`
	Error     *errorBody `json:"error,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
}

type errorBody struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Details []apperr.FieldError `json:"details,omitempty"`
}

// OK writes a success envelope.
func OK(c *gin.Context, status int, message string, data any) {
	c.JSON(status, envelope{Success: true, Message: message, Data: data, RequestID: RequestIDOf(c)})
}

// Fail writes an error envelope. Anything that is not an *apperr.Error is
// treated as a 500 whose cause is logged but never returned.
func Fail(c *gin.Context, err error) {
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		ae = apperr.Internal(err)
	}
	if ae.Status >= http.StatusInternalServerError {
		Logger(c).Error("request failed", "code", ae.Code, "error", errString(ae.Err))
	}
	c.Set(ctxErrorCode, ae.Code)
	if ae.RetryAfter > 0 {
		c.Header("Retry-After", strconv.Itoa(int(math.Ceil(ae.RetryAfter.Seconds()))))
	}
	c.AbortWithStatusJSON(ae.Status, envelope{
		Success:   false,
		Error:     &errorBody{Code: ae.Code, Message: ae.Message, Details: ae.Details},
		RequestID: RequestIDOf(c),
	})
}

// NotFound is the handler for unknown routes.
func NotFound(c *gin.Context) {
	Fail(c, apperr.NotFound("ROUTE_NOT_FOUND", "the requested resource does not exist"))
}

// MethodNotAllowed is the handler for known paths with the wrong method.
func MethodNotAllowed(c *gin.Context) {
	Fail(c, apperr.New(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed"))
}

// RequestIDOf returns the id assigned by the RequestID middleware.
func RequestIDOf(c *gin.Context) string {
	return c.GetString(ctxRequestID)
}

// Logger returns the request-scoped logger, falling back to the default.
func Logger(c *gin.Context) *slog.Logger {
	if l, ok := c.Get(ctxLogger); ok {
		if lg, ok := l.(*slog.Logger); ok {
			return lg
		}
	}
	return slog.Default()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
