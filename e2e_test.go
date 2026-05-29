package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/x6c-co/knit/internal/renew"
	"github.com/x6c-co/knit/internal/store"
	"github.com/x6c-co/knit/internal/valkey"
	"github.com/x6c-co/knit/internal/watch"
)

// e2eStore is a minimal CertStore for the pipeline test.
type e2eStore struct {
	certs   []store.Cert
	renewed map[int64]time.Time
}

func (s *e2eStore) EnsureSchema(context.Context) error                { return nil }
func (s *e2eStore) ListEnabled(context.Context) ([]store.Cert, error) { return s.certs, nil }
func (s *e2eStore) MarkRenewed(_ context.Context, id int64, na, _ time.Time) error {
	s.renewed[id] = na
	return nil
}
func (s *e2eStore) MarkError(context.Context, int64, string) error { return nil }

type e2eIssuer struct{ calls int }

func (i *e2eIssuer) Obtain(context.Context, string, []string) ([]byte, []byte, time.Time, error) {
	i.calls++
	return []byte("FULLCHAIN-PEM"), []byte("PRIVKEY-PEM"), time.Now().Add(90 * 24 * time.Hour), nil
}

// TestRenewToWatchPipeline exercises the full central→node path: renew issues a
// cert and publishes it to Valkey, then watch discovers it via the index, writes
// it to disk with the right modes, and a second watch pass is a no-op. This
// proves the shared hash contract holds across the two sides (the linchpin).
func TestRenewToWatchPipeline(t *testing.T) {
	mr := miniredis.RunT(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	vkRenew, err := valkey.New("redis://"+mr.Addr(), "knit:index")
	if err != nil {
		t.Fatalf("valkey.New (renew): %v", err)
	}
	defer vkRenew.Close()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	st := &e2eStore{
		certs: []store.Cert{{
			ID: 1, Domains: "example.com,www.example.com", Provider: "desec",
			ValkeyKey: "knit:example", CertPath: certPath, KeyPath: keyPath,
		}},
		renewed: map[int64]time.Time{},
	}
	iss := &e2eIssuer{}
	runner := renew.NewRunner(st, vkRenew, log, 30, func(context.Context) (renew.Issuer, error) {
		return iss, nil
	})

	ctx := context.Background()
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("renew pass: %v", err)
	}
	if iss.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", iss.calls)
	}

	// Node side: a separate Valkey client (as a POP would have), plus watch.
	vkWatch, err := valkey.New("redis://"+mr.Addr(), "knit:index")
	if err != nil {
		t.Fatalf("valkey.New (watch): %v", err)
	}
	defer vkWatch.Close()

	// Empty reload command keeps the test from spawning a shell; reload
	// behavior itself is covered by the watch package tests.
	w := watch.New(vkWatch, "", log)

	if err := w.RunOnce(ctx); err != nil {
		t.Fatalf("watch pass 1: %v", err)
	}

	cert, err := os.ReadFile(certPath)
	if err != nil || string(cert) != "FULLCHAIN-PEM" {
		t.Fatalf("cert on disk = %q err=%v", cert, err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || string(key) != "PRIVKEY-PEM" {
		t.Fatalf("key on disk = %q err=%v", key, err)
	}
	if info, _ := os.Stat(certPath); info.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %o, want 0644", info.Mode().Perm())
	}
	if info, _ := os.Stat(keyPath); info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 0600", info.Mode().Perm())
	}

	// Second watch pass: the on-disk hash must match the published sha256, so
	// nothing is rewritten. Confirm via mtime.
	before, _ := os.Stat(certPath)
	if err := w.RunOnce(ctx); err != nil {
		t.Fatalf("watch pass 2: %v", err)
	}
	after, _ := os.Stat(certPath)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("cert rewritten on no-change pass: hash contract broken between renew and watch")
	}
}
