// Package dbtest creates a temporary Postgres database for a test.
//
// Set TERCES_TEST_DATABASE_URL to a server URL with a role that can
// create databases. Tests that need a database skip when it is not set:
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine
//	export TERCES_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable
package dbtest

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"terces/internal/store"
)

// EnvVar holds the server URL for tests.
const EnvVar = "TERCES_TEST_DATABASE_URL"

// New creates a database, applies the migrations and returns a store. The
// database is dropped when the test ends.
func New(t testing.TB) (*store.Store, string) {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		t.Skipf("set %s to run tests that need Postgres", EnvVar)
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to test server: %v", err)
	}
	name := fmt.Sprintf("terces_test_%d", rand.Uint64()%1e12)
	if _, err := admin.Exec(ctx, "create database "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dsn := u.String()

	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Exec(context.Background(), "drop database if exists "+name+" with (force)")
		admin.Close(context.Background())
	})
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s, dsn
}
