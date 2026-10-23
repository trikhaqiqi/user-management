// Package ratelimit implements fixed-window counters in Redis.
//
// A fixed window can admit up to 2x the limit across a window boundary. That
// is acceptable here: the limits exist to make brute force and abuse
// impractical, not to shape traffic precisely, and the per-OTP and per-account
// limits that actually bound guessing live in Postgres.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// incr atomically increments the counter and starts its window on first hit.
// Re-applying the TTL when it is missing covers a key that lost its expiry.
var incr = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}
`)

type Limiter struct {
	rdb    *redis.Client
	prefix string
}

func New(rdb *redis.Client, prefix string) *Limiter {
	return &Limiter{rdb: rdb, prefix: prefix + ":"}
}

type Result struct {
	Allowed    bool
	Count      int64
	Remaining  int64
	RetryAfter time.Duration
}

// Hit counts one event against key and reports whether it is within limit.
func (l *Limiter) Hit(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	vals, err := incr.Run(ctx, l.rdb, []string{l.prefix + key}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return Result{}, err
	}
	count, ttl := vals[0], time.Duration(vals[1])*time.Millisecond
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}
	return Result{Allowed: count <= int64(limit), Count: count, Remaining: remaining, RetryAfter: ttl}, nil
}

// Peek returns the current count and time left without counting an event.
func (l *Limiter) Peek(ctx context.Context, key string) (int64, time.Duration, error) {
	pipe := l.rdb.Pipeline()
	get := pipe.Get(ctx, l.prefix+key)
	ttl := pipe.PTTL(ctx, l.prefix+key)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, 0, err
	}
	n, err := get.Int64()
	if errors.Is(err, redis.Nil) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return n, ttl.Val(), nil
}

// Reset clears a counter, e.g. after a successful login.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	return l.rdb.Del(ctx, l.prefix+key).Err()
}

// HashKey turns an identifier such as an email into a fixed-length key, so
// personal data is not stored in Redis key names.
func HashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
