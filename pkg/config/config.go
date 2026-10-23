// Package config reads service configuration from environment variables.
//
// Loader collects every problem instead of failing on the first one, so a
// misconfigured deployment reports all missing variables at once.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Loader struct {
	errs []string
}

func (l *Loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Sprintf(format, args...))
}

// String returns the variable or def when it is unset or empty.
func (l *Loader) String(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Required returns the variable and records an error when it is missing.
func (l *Loader) Required(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		l.fail("%s is required", key)
	}
	return v
}

// Secret is a required value that must be at least minLen bytes long.
func (l *Loader) Secret(key string, minLen int) string {
	v := l.Required(key)
	if v != "" && len(v) < minLen {
		l.fail("%s must be at least %d characters", key, minLen)
	}
	return v
}

// Base64Secret is a required base64 value decoding to at least minBytes bytes.
func (l *Loader) Base64Secret(key string, minBytes int) []byte {
	v := l.Required(key)
	if v == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		l.fail("%s must be valid base64", key)
		return nil
	}
	if len(b) < minBytes {
		l.fail("%s must decode to at least %d bytes", key, minBytes)
	}
	return b
}

func (l *Loader) Int(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		l.fail("%s must be a positive integer", key)
		return def
	}
	return n
}

func (l *Loader) Duration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		l.fail("%s must be a positive duration such as 15m", key)
		return def
	}
	return d
}

// List splits a comma-separated variable, dropping empty items.
func (l *Loader) List(key string) []string {
	var out []string
	for _, item := range strings.Split(os.Getenv(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Err returns every configuration problem found, or nil.
func (l *Loader) Err() error {
	if len(l.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(l.errs, "\n  - "))
}
