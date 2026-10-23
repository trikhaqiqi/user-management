package config

import (
	"godigi/pkg/config"
	"godigi/pkg/mailer"
	"godigi/pkg/otp"
)

type Config struct {
	Port          string
	LogLevel      string
	DatabaseURL   string
	InternalToken string
	OTP           otp.Config
	Mail          mailer.Sender
}

func Load() (*Config, error) {
	l := &config.Loader{}
	c := &Config{
		Port:          l.String("CORE_SERVICE_PORT", "8092"),
		LogLevel:      l.String("LOG_LEVEL", "info"),
		DatabaseURL:   l.Required("DATABASE_URL"),
		InternalToken: l.Secret("INTERNAL_SERVICE_TOKEN", 32),
		OTP:           otp.ConfigFromEnv(l),
		Mail:          mailer.FromEnv(l),
	}
	if err := l.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
