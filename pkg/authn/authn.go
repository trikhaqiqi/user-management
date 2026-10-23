// Package authn is the service-side half of authentication.
//
// The gateway has already verified the JWT's signature and expiry and passed
// the user and session ids in headers (trusted because of InternalAuth). The
// gateway has no database, so this middleware does what it cannot: confirm,
// on every request, that the session has not been revoked and the account is
// still active. That is what makes logout, password reset and deactivation
// take effect immediately rather than when the access token expires.
package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"godigi/pkg/apperr"
	"godigi/pkg/database"
	"godigi/pkg/httpx"
)

type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
}

const ctxPrincipal = "authn.principal"

var errNoSession = errors.New("session not found")

type sessionState struct {
	userStatus    string
	sessionActive bool
}

func loadSessionState(ctx context.Context, q database.Querier, sessionID, userID uuid.UUID) (*sessionState, error) {
	var s sessionState
	err := q.QueryRow(ctx, `SELECT u.status::text, (s.revoked_at IS NULL AND s.expires_at > now())
		FROM sys_sessions s JOIN m_users u ON u.id = s.user_id
		WHERE s.id = $1 AND s.user_id = $2`, sessionID, userID).Scan(&s.userStatus, &s.sessionActive)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("load session state: %w", err)
	}
	return &s, nil
}

func RequireSession(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err1 := uuid.Parse(c.GetHeader(httpx.HeaderUserID))
		sessionID, err2 := uuid.Parse(c.GetHeader(httpx.HeaderSessionID))
		if err1 != nil || err2 != nil {
			httpx.Fail(c, apperr.Unauthorized("UNAUTHENTICATED", "authentication required"))
			return
		}
		state, err := loadSessionState(c.Request.Context(), pool, sessionID, userID)
		if errors.Is(err, errNoSession) || (err == nil && !state.sessionActive) {
			httpx.Fail(c, apperr.Unauthorized("SESSION_REVOKED", "your session has ended, please log in again"))
			return
		}
		if err != nil {
			httpx.Fail(c, err)
			return
		}
		if state.userStatus != "active" {
			httpx.Fail(c, apperr.Forbidden("ACCOUNT_INACTIVE", "this account is not active"))
			return
		}
		c.Set(ctxPrincipal, Principal{UserID: userID, SessionID: sessionID})
		c.Set(httpx.CtxUserID, userID.String())
		c.Next()
	}
}

// From returns the principal set by RequireSession.
func From(c *gin.Context) Principal {
	p, _ := c.MustGet(ctxPrincipal).(Principal)
	return p
}
