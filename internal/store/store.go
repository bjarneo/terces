// Package store keeps repositories, findings, the blob cache, the audit log
// and the job queue in Postgres. It never stores a plaintext secret.
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"terces/migrations"
)

// ErrNotFound means that no row matches.
var ErrNotFound = errors.New("not found")

// Store is a connection pool with typed queries.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "terces"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close closes the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the connection.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies the embedded migrations that are not yet applied. It
// returns the names of the applied files.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	// Serialize concurrent migrate runs.
	if _, err := conn.Exec(ctx, "select pg_advisory_lock(hashtext('terces-migrate'))"); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), "select pg_advisory_unlock(hashtext('terces-migrate'))")

	if _, err := conn.Exec(ctx, `create table if not exists schema_migrations (
		version text primary key,
		applied_at timestamptz not null default now())`); err != nil {
		return nil, err
	}
	var applied []string
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, "select exists (select 1 from schema_migrations where version = $1)", name).Scan(&exists); err != nil {
			return applied, err
		}
		if exists {
			continue
		}
		sql, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return applied, err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "insert into schema_migrations (version) values ($1)", name)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// CheckSchema returns an error when migrations are missing.
func (s *Store) CheckSchema(ctx context.Context) error {
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return err
	}
	var have []string
	rows, err := s.pool.Query(ctx, "select version from schema_migrations")
	if err != nil {
		return fmt.Errorf("the database has no schema: run `terces migrate`")
	}
	have, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, n := range names {
		if !set[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the database misses migrations %s: run `terces migrate`", strings.Join(missing, ", "))
	}
	return nil
}
