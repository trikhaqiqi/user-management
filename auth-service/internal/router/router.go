package router

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"godigi/auth-service/internal/handler"
	"godigi/pkg/authn"
	"godigi/pkg/httpx"
)

func New(log *slog.Logger, h *handler.AuthHandler, pool *pgxpool.Pool, rdb *redis.Client, internalToken string) *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.HandleMethodNotAllowed = true
	r.Use(httpx.RequestID(log), httpx.Recovery(), httpx.AccessLog(httpx.AccessLogOptions{}), httpx.SecurityHeaders(), httpx.BodyLimit(1<<20))
	r.NoRoute(httpx.NotFound)
	r.NoMethod(httpx.MethodNotAllowed)

	r.GET("/health", health(pool, rdb))

	auth := r.Group("/api/v1/auth", httpx.InternalAuth(internalToken))
	auth.POST("/register", h.Register)
	auth.POST("/verify-otp", h.VerifyOTP)
	auth.POST("/resend-otp", h.ResendOTP)
	auth.POST("/login", h.Login)
	auth.POST("/refresh", h.Refresh)
	auth.POST("/logout", h.Logout)
	auth.POST("/forgot-password", h.ForgotPassword)
	auth.POST("/reset-password", h.ResetPassword)
	auth.POST("/change-password", authn.RequireSession(pool), h.ChangePassword)
	return r
}

func health(pool *pgxpool.Pool, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		status := gin.H{"database": "ok", "redis": "ok"}
		code := http.StatusOK
		if err := pool.Ping(ctx); err != nil {
			status["database"], code = "unavailable", http.StatusServiceUnavailable
		}
		if err := rdb.Ping(ctx).Err(); err != nil {
			status["redis"], code = "unavailable", http.StatusServiceUnavailable
		}
		httpx.OK(c, code, "", status)
	}
}
