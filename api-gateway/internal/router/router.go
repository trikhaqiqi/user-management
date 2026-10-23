package router

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"godigi/api-gateway/internal/config"
	"godigi/api-gateway/internal/middleware"
	"godigi/api-gateway/internal/proxy"
	"godigi/pkg/httpx"
	"godigi/pkg/jwtx"
	"godigi/pkg/ratelimit"
)

func New(cfg *config.Config, log *slog.Logger, rdb *redis.Client) (*gin.Engine, error) {
	r := gin.New()
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}
	r.HandleMethodNotAllowed = true
	limiter := ratelimit.New(rdb, "gw")
	verifier := jwtx.NewVerifier(cfg.JWTPublicKey)
	auth := proxy.New(cfg.AuthServiceURL, cfg.InternalToken, cfg.ProxyTimeout, log).Handler()
	core := proxy.New(cfg.CoreServiceURL, cfg.InternalToken, cfg.ProxyTimeout, log).Handler()

	r.Use(
		middleware.StripIdentityHeaders(),
		httpx.RequestID(log),
		httpx.Recovery(),
		// The gateway's access log is the request/response record shown in
		// Grafana. Services log their own lines without bodies.
		httpx.AccessLog(httpx.AccessLogOptions{LogBodies: cfg.LogHTTPBodies}),
		httpx.SecurityHeaders(),
		middleware.CORS(cfg.CORSOrigins),
		httpx.BodyLimit(cfg.MaxBodyBytes),
	)
	r.NoRoute(httpx.NotFound)
	r.NoMethod(httpx.MethodNotAllowed)

	r.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			httpx.OK(c, http.StatusServiceUnavailable, "", gin.H{"redis": "unavailable"})
			return
		}
		httpx.OK(c, http.StatusOK, "", gin.H{"redis": "ok"})
	})
	registerDocs(r, cfg.OpenAPIPath)

	// Coarse per-IP limit; fails open so a Redis outage doesn't take the
	// whole API down.
	api := r.Group("/api/v1", ratelimit.Middleware(limiter, ratelimit.Rule{
		Name: "global", Limit: cfg.GlobalLimitPerMinute, Window: time.Minute, Key: ratelimit.ByIP, FailOpen: true,
	}))

	// Credential and code endpoints get their own small per-IP budget per
	// route, and fail closed.
	strict := ratelimit.Middleware(limiter, ratelimit.Rule{
		Name: "auth", Limit: cfg.AuthLimitPerMinute, Window: time.Minute, Key: ratelimit.ByIPAndRoute,
	})
	tokens := ratelimit.Middleware(limiter, ratelimit.Rule{
		Name: "token", Limit: cfg.RefreshLimitPerMinute, Window: time.Minute, Key: ratelimit.ByIPAndRoute,
	})
	// Endpoints that check the current password: per-user limit, so a
	// stolen access token can't be used to brute-force the password.
	sensitive := ratelimit.Middleware(limiter, ratelimit.Rule{
		Name: "sensitive", Limit: cfg.SensitiveLimitPer15Min, Window: 15 * time.Minute, Key: middleware.UserKey,
	})
	authenticate := middleware.Authenticate(verifier)

	a := api.Group("/auth")
	a.POST("/register", strict, auth)
	a.POST("/verify-otp", strict, auth)
	a.POST("/resend-otp", strict, auth)
	a.POST("/login", strict, auth)
	a.POST("/forgot-password", strict, auth)
	a.POST("/reset-password", strict, auth)
	a.POST("/refresh", tokens, auth)
	a.POST("/logout", tokens, auth)
	a.POST("/change-password", authenticate, sensitive, auth)

	u := api.Group("/users/me", authenticate)
	u.GET("", core)
	u.PATCH("", core)
	u.POST("/change-email", sensitive, core)
	u.POST("/change-email/verify", sensitive, core)
	u.POST("/deactivate", sensitive, core)
	return r, nil
}
