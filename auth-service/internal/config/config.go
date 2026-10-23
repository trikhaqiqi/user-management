package config

import (
	"crypto/ed25519"
	"time"

	"godigi/pkg/config"
	"godigi/pkg/jwtx"
	"godigi/pkg/mailer"
	"godigi/pkg/otp"
)

type Config struct {
	Port          string
	LogLevel      string
	DatabaseURL   string
	RedisURL      string
	InternalToken string

	JWTPrivateKey   ed25519.PrivateKey
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// SessionMaxAge caps a session's lifetime no matter how often it is
	// refreshed.
	SessionMaxAge time.Duration

	OTP otp.Config

	PasswordResetTTL      time.Duration
	PasswordResetCooldown time.Duration
	PasswordResetURL      string

	LoginMaxFailures int
	LoginLockout     time.Duration

	Mail mailer.Sender
}

func Load() (*Config, error) {
	l := &config.Loader{}
	c := &Config{
		Port:                  l.String("AUTH_SERVICE_PORT", "8091"),
		LogLevel:              l.String("LOG_LEVEL", "info"),
		DatabaseURL:           l.Required("DATABASE_URL"),
		RedisURL:              l.String("REDIS_URL", "redis://localhost:6379/0"),
		InternalToken:         l.Secret("INTERNAL_SERVICE_TOKEN", 32),
		AccessTokenTTL:        l.Duration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:       l.Duration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
		SessionMaxAge:         l.Duration("SESSION_MAX_AGE", 30*24*time.Hour),
		OTP:                   otp.ConfigFromEnv(l),
		PasswordResetTTL:      l.Duration("PASSWORD_RESET_TTL", 15*time.Minute),
		PasswordResetCooldown: l.Duration("PASSWORD_RESET_COOLDOWN", 60*time.Second),
		PasswordResetURL:      l.String("PASSWORD_RESET_URL", "http://localhost:3000/reset-password"),
		LoginMaxFailures:      l.Int("LOGIN_MAX_FAILURES", 5),
		LoginLockout:          l.Duration("LOGIN_LOCKOUT", 15*time.Minute),
		Mail:                  mailer.FromEnv(l),
	}
	keyB64 := l.Required("JWT_PRIVATE_KEY")
	if err := l.Err(); err != nil {
		return nil, err
	}
	key, err := jwtx.ParsePrivateKey(keyB64)
	if err != nil {
		return nil, err
	}
	c.JWTPrivateKey = key
	return c, nil
}
