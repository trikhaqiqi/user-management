package config

import (
	"crypto/ed25519"
	"fmt"
	"net/url"
	"time"

	"godigi/pkg/config"
	"godigi/pkg/jwtx"
)

type Config struct {
	Port           string
	LogLevel       string
	RedisURL       string
	InternalToken  string
	AuthServiceURL *url.URL
	CoreServiceURL *url.URL
	JWTPublicKey   ed25519.PublicKey
	CORSOrigins    []string
	TrustedProxies []string
	ProxyTimeout   time.Duration
	MaxBodyBytes   int64
	OpenAPIPath    string
	LogHTTPBodies  bool

	GlobalLimitPerMinute   int
	AuthLimitPerMinute     int
	RefreshLimitPerMinute  int
	SensitiveLimitPer15Min int
}

func Load() (*Config, error) {
	l := &config.Loader{}
	c := &Config{
		Port:                   l.String("GATEWAY_PORT", "8080"),
		LogLevel:               l.String("LOG_LEVEL", "info"),
		RedisURL:               l.String("REDIS_URL", "redis://localhost:6379/0"),
		InternalToken:          l.Secret("INTERNAL_SERVICE_TOKEN", 32),
		CORSOrigins:            l.List("CORS_ALLOWED_ORIGINS"),
		TrustedProxies:         l.List("TRUSTED_PROXIES"),
		ProxyTimeout:           l.Duration("PROXY_TIMEOUT", 15*time.Second),
		MaxBodyBytes:           int64(l.Int("MAX_BODY_BYTES", 1<<20)),
		OpenAPIPath:            l.String("OPENAPI_SPEC_PATH", "../docs/openapi.yaml"),
		LogHTTPBodies:          l.String("LOG_HTTP_BODIES", "false") == "true",
		GlobalLimitPerMinute:   l.Int("RATE_LIMIT_GLOBAL_PER_MINUTE", 120),
		AuthLimitPerMinute:     l.Int("RATE_LIMIT_AUTH_PER_MINUTE", 10),
		RefreshLimitPerMinute:  l.Int("RATE_LIMIT_REFRESH_PER_MINUTE", 30),
		SensitiveLimitPer15Min: l.Int("RATE_LIMIT_SENSITIVE_PER_15_MINUTES", 10),
	}
	authURL := l.String("AUTH_SERVICE_URL", "http://localhost:8091")
	coreURL := l.String("CORE_SERVICE_URL", "http://localhost:8092")
	pubB64 := l.Required("JWT_PUBLIC_KEY")
	if err := l.Err(); err != nil {
		return nil, err
	}
	var err error
	if c.AuthServiceURL, err = parseURL("AUTH_SERVICE_URL", authURL); err != nil {
		return nil, err
	}
	if c.CoreServiceURL, err = parseURL("CORE_SERVICE_URL", coreURL); err != nil {
		return nil, err
	}
	if c.JWTPublicKey, err = jwtx.ParsePublicKey(pubB64); err != nil {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: %w", err)
	}
	return c, nil
}

func parseURL(key, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URL such as http://auth-service:8091", key)
	}
	return u, nil
}
