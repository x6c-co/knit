package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// These exercise the real Postgres layer. They run only when KNIT_TEST_DB_URL
// points at a disposable database (the tests create/drop knit_ tables and
// truncate them), and skip otherwise so the suite stays runnable without a DB.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("KNIT_TEST_DB_URL")
	if dsn == "" {
		t.Skip("set KNIT_TEST_DB_URL to run store integration tests")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	// Start from a clean slate without dropping (tables are shared-db safe).
	if _, err := s.pool.Exec(ctx, "TRUNCATE knit_certs, knit_acme_account RESTART IDENTITY"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestEnsureSchemaIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// Calling twice must not error (CREATE TABLE IF NOT EXISTS).
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
	}
}

func TestUpsertListRemove(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	c := Cert{
		Domains: "example.com,www.example.com", Provider: "desec",
		ValkeyKey: "knit:example", CertPath: "/etc/ssl/c.pem", KeyPath: "/etc/ssl/k.pem",
	}
	if err := s.Upsert(ctx, c); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Upsert again with a changed provider — should update, not duplicate.
	c.Provider = "cloudflare"
	if err := s.Upsert(ctx, c); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}

	certs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("want 1 cert, got %d", len(certs))
	}
	if certs[0].Provider != "cloudflare" {
		t.Errorf("provider = %q, want cloudflare", certs[0].Provider)
	}
	if !certs[0].Enabled {
		t.Error("expected enabled")
	}

	removed, err := s.RemoveByDomains(ctx, "example.com,www.example.com")
	if err != nil || !removed {
		t.Fatalf("RemoveByDomains: removed=%v err=%v", removed, err)
	}
	certs, _ = s.List(ctx)
	if len(certs) != 0 {
		t.Fatalf("want 0 certs after remove, got %d", len(certs))
	}
}

func TestRenewBookkeeping(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Upsert(ctx, Cert{Domains: "a.com", Provider: "desec", ValkeyKey: "knit:a", CertPath: "/c", KeyPath: "/k"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	certs, _ := s.List(ctx)
	id := certs[0].ID

	// Error path records last_error.
	if err := s.MarkError(ctx, id, "dns timeout"); err != nil {
		t.Fatalf("MarkError: %v", err)
	}
	certs, _ = s.List(ctx)
	if certs[0].LastError != "dns timeout" {
		t.Errorf("last_error = %q", certs[0].LastError)
	}

	// Success path updates timestamps and clears the error.
	exp := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	if err := s.MarkRenewed(ctx, id, exp, time.Now()); err != nil {
		t.Fatalf("MarkRenewed: %v", err)
	}
	certs, _ = s.List(ctx)
	if certs[0].LastError != "" {
		t.Errorf("last_error should be cleared, got %q", certs[0].LastError)
	}
	if certs[0].NotAfter == nil || !certs[0].NotAfter.Equal(exp) {
		t.Errorf("not_after = %v, want %v", certs[0].NotAfter, exp)
	}
}

func TestAccountSaveGet(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetAccount(ctx); err != nil || ok {
		t.Fatalf("expected no account initially: ok=%v err=%v", ok, err)
	}
	a := Account{Email: "a@b.com", PrivateKey: "PEM", Registration: `{"x":1}`}
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	// Saving again must keep a single row.
	if err := s.SaveAccount(ctx, Account{Email: "c@d.com", PrivateKey: "PEM2", Registration: `{"y":2}`}); err != nil {
		t.Fatalf("SaveAccount 2: %v", err)
	}
	got, ok, err := s.GetAccount(ctx)
	if err != nil || !ok {
		t.Fatalf("GetAccount: ok=%v err=%v", ok, err)
	}
	if got.Email != "c@d.com" {
		t.Errorf("email = %q, want c@d.com (single row replaced)", got.Email)
	}
}
