package ratelimit

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"godigi/pkg/apperr"
	"godigi/pkg/httpx"
)

// Rule describes one limit enforced by Middleware.
type Rule struct {
	Name   string
	Limit  int
	Window time.Duration
	// Key identifies the caller; an empty key skips the rule.
	Key func(c *gin.Context) string
	// FailOpen admits requests when Redis is unreachable. Use it for
	// coarse limits; sensitive endpoints should fail closed.
	FailOpen bool
}

func Middleware(l *Limiter, rule Rule) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := rule.Key(c)
		if key == "" {
			c.Next()
			return
		}
		res, err := l.Hit(c.Request.Context(), rule.Name+":"+key, rule.Limit, rule.Window)
		if err != nil {
			httpx.Logger(c).Error("rate limiter unavailable", "rule", rule.Name, "fail_open", rule.FailOpen, "error", err.Error())
			if rule.FailOpen {
				c.Next()
				return
			}
			httpx.Fail(c, apperr.Unavailable(err))
			return
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(rule.Limit))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(res.Remaining, 10))
		if !res.Allowed {
			httpx.Fail(c, apperr.TooManyRequests("RATE_LIMITED", "too many requests, please try again later", res.RetryAfter))
			return
		}
		c.Next()
	}
}

// ByIP keys a rule on the client address.
func ByIP(c *gin.Context) string { return httpx.ClientIP(c) }

// ByIPAndRoute gives each route its own budget per client address.
func ByIPAndRoute(c *gin.Context) string { return httpx.ClientIP(c) + ":" + c.FullPath() }
