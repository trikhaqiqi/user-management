package router

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"godigi/core-service/internal/handler"
	"godigi/pkg/authn"
	"godigi/pkg/httpx"
)

func New(log *slog.Logger, h *handler.UserHandler, pool *pgxpool.Pool, internalToken string) *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.HandleMethodNotAllowed = true
	r.Use(httpx.RequestID(log), httpx.Recovery(), httpx.AccessLog(httpx.AccessLogOptions{}), httpx.SecurityHeaders(), httpx.BodyLimit(1<<20))
	r.NoRoute(httpx.NotFound)
	r.NoMethod(httpx.MethodNotAllowed)

	r.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			httpx.OK(c, http.StatusServiceUnavailable, "", gin.H{"database": "unavailable"})
			return
		}
		httpx.OK(c, http.StatusOK, "", gin.H{"database": "ok"})
	})

	me := r.Group("/api/v1/users/me", httpx.InternalAuth(internalToken), authn.RequireSession(pool))
	me.GET("", h.GetMe)
	me.PATCH("", h.UpdateMe)
	me.POST("/change-email", h.ChangeEmail)
	me.POST("/change-email/verify", h.VerifyEmailChange)
	me.POST("/deactivate", h.Deactivate)
	return r
}
