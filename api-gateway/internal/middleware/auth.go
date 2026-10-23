// Package middleware holds gateway-only middleware.
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"godigi/pkg/apperr"
	"godigi/pkg/httpx"
	"godigi/pkg/jwtx"
)

const ctxUserID = "gateway.user_id"

// StripIdentityHeaders removes any client-supplied copy of the headers the
// gateway asserts to services. It must run before anything sets them.
func StripIdentityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, h := range httpx.IdentityHeaders {
			c.Request.Header.Del(h)
		}
		c.Next()
	}
}

// Authenticate verifies the bearer access token (signature, EdDSA only,
// issuer, audience, expiry) and forwards the user and session ids. Whether
// the session is still live is checked by the service, which has the
// database.
func Authenticate(v *jwtx.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, token, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			c.Header("WWW-Authenticate", `Bearer realm="godigi"`)
			httpx.Fail(c, apperr.Unauthorized("MISSING_TOKEN", "missing or malformed Authorization header; expected: Bearer <access_token>"))
			return
		}
		claims, err := v.Verify(strings.TrimSpace(token))
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer realm="godigi", error="invalid_token"`)
			if jwtx.IsExpired(err) {
				httpx.Fail(c, apperr.Unauthorized("TOKEN_EXPIRED", "access token has expired; use the refresh token to get a new one"))
				return
			}
			httpx.Fail(c, apperr.Unauthorized("INVALID_TOKEN", "access token is invalid"))
			return
		}
		c.Request.Header.Set(httpx.HeaderUserID, claims.Subject)
		c.Request.Header.Set(httpx.HeaderSessionID, claims.SessionID)
		c.Set(ctxUserID, claims.Subject)
		c.Set(httpx.CtxUserID, claims.Subject)
		c.Next()
	}
}

// UserKey keys rate limits on the authenticated user.
func UserKey(c *gin.Context) string { return c.GetString(ctxUserID) }
