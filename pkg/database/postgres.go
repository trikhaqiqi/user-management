// Package database wraps pgx connection setup and transaction handling.
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens a pool and waits (up to ~30s) for the database to answer,
// so services started alongside Postgres don't crash on the first attempt.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	for attempt := 1; ; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if attempt == 10 {
			pool.Close()
			return nil, fmt.Errorf("database not reachable: %w", err)
		}
		time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
	}
}

// commitAndFail marks an error whose transaction must still be committed.
type commitAndFail struct{ err error }

func (e *commitAndFail) Error() string { return e.err.Error() }
func (e *commitAndFail) Unwrap() error { return e.err }

// CommitAndFail makes WithTx commit the work done so far and then return err.
//
// It exists for failures that must leave a trace. A wrong OTP has to increment
// the attempt counter, and a reused refresh token has to revoke its session.
// Rolling those back along with the request would hand an attacker unlimited
// guesses, or leave a stolen token family alive.
func CommitAndFail(err error) error { return &commitAndFail{err: err} }

// WithTx runs fn in a READ COMMITTED transaction. A nil return commits. Any
// other error rolls back, except one wrapped in CommitAndFail.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if err := fn(tx); err != nil {
		var cf *commitAndFail
		if errors.As(err, &cf) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return fmt.Errorf("commit tx: %w", cerr)
			}
			return cf.err
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// IsUniqueViolation reports whether err is a unique violation. If constraint
// is non-empty, the violation must be on that constraint.
func IsUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx, so repository
// functions can run on the pool or inside a caller's transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
