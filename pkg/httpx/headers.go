// Package httpx holds the HTTP plumbing shared by every service: the JSON
// envelope, strict request binding and common middleware.
package httpx

const (
	HeaderRequestID     = "X-Request-ID"
	HeaderInternalToken = "X-Internal-Token"
	HeaderUserID        = "X-User-ID"
	HeaderSessionID     = "X-Session-ID"
	HeaderClientIP      = "X-Client-IP"
)

// IdentityHeaders are asserted by the gateway and trusted by the services.
// The gateway strips any client-supplied copy before setting its own.
var IdentityHeaders = []string{HeaderInternalToken, HeaderUserID, HeaderSessionID, HeaderClientIP}

const (
	ctxRequestID = "httpx.request_id"
	ctxLogger    = "httpx.logger"
	ctxErrorCode = "httpx.error_code"
	// CtxUserID is set by whichever layer authenticated the request, so the
	// access log can attribute it.
	CtxUserID = "httpx.user_id"
)
