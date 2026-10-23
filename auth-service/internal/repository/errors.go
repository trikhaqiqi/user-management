// Package repository is auth-service's data access layer. All SQL is
// parameterised. Functions take a database.Querier, so the service decides
// whether they run on the pool or inside its transaction.
package repository

import "errors"

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email already registered")
)
