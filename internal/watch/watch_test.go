package watch

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/x6c-co/knit/internal/valkey"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testWatcher builds a Watcher backed by miniredis, with a reload counter
// instead of a real shell command.
func testWatcher(t *testing.T, reloadCmd string) (*Watcher, *valkey.Client, *int) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := valkey.New("redis://"+mr.Addr(), "knit:index")
	if err != nil {
		t.Fatalf("valkey.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	reloads := 0
	w := New(c, reloadCmd, discardLog())
	w.runReload = func(context.Context, string) error {
		reloads++
		return nil
	}
	return w, c, &reloads
}

// seed publishes a cert value whose sha256 matches fullchain/privkey, pointing
// at paths inside dir.
func seed(t *testing.T, c *valkey.Client, key, dir, fc, pk string) valkey.Value {
	t.Helper()
	v := valkey.Value{
		Fullchain: fc, Privkey: pk,
		NotAfter: "2026-12-31T00:00:00Z",
		SHA256:   valkey.Hash([]byte(fc), []byte(pk)),
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "privkey.pem"),
	}
	if err := c.SetCert(context.Background(), key, v); err != nil {
		t.Fatalf("SetCert: %v", err)
	}
	if err := c.AddToIndex(context.Background(), key); err != nil {
		t.Fatalf("AddToIndex: %v", err)
	}
	return v
}

func TestWritesFilesWithModesAndReloadsOnce(t *testing.T) {
	// Acceptance #3: discover via index, write fullchain (0644) and key (0600),
	// run reload once.
	dir := t.TempDir()
	w, c, reloads := testWatcher(t, "caddy reload")
	v := seed(t, c, "knit:a", dir, "FULLCHAIN-PEM", "PRIVKEY-PEM")

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	cert, err := os.ReadFile(v.CertPath)
	if err != nil || string(cert) != "FULLCHAIN-PEM" {
		t.Fatalf("cert content = %q err=%v", cert, err)
	}
	key, err := os.ReadFile(v.KeyPath)
	if err != nil || string(key) != "PRIVKEY-PEM" {
		t.Fatalf("key content = %q err=%v", key, err)
	}

	certInfo, _ := os.Stat(v.CertPath)
	if certInfo.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %o, want 0644", certInfo.Mode().Perm())
	}
	keyInfo, _ := os.Stat(v.KeyPath)
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 0600", keyInfo.Mode().Perm())
	}
	if *reloads != 1 {
		t.Errorf("reloads = %d, want 1", *reloads)
	}
}

func TestNoChangeNoWriteNoReload(t *testing.T) {
	// Acceptance #4: a second pass with no change in Valkey writes nothing and
	// does not run the reload command.
	dir := t.TempDir()
	w, c, reloads := testWatcher(t, "caddy reload")
	v := seed(t, c, "knit:a", dir, "FC", "PK")

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	if *reloads != 1 {
		t.Fatalf("after first pass reloads = %d, want 1", *reloads)
	}
	// Capture mtime to confirm no rewrite occurs.
	infoBefore, _ := os.Stat(v.CertPath)

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if *reloads != 1 {
		t.Errorf("after no-change pass reloads = %d, want still 1", *reloads)
	}
	infoAfter, _ := os.Stat(v.CertPath)
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Error("cert file was rewritten despite no change")
	}
}

func TestRewriteOnChangeAndReload(t *testing.T) {
	// When Valkey material changes, watch rewrites and reloads again.
	dir := t.TempDir()
	w, c, reloads := testWatcher(t, "caddy reload")
	seed(t, c, "knit:a", dir, "FC1", "PK1")
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}

	v2 := seed(t, c, "knit:a", dir, "FC2", "PK2") // overwrites the value
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	cert, _ := os.ReadFile(v2.CertPath)
	if string(cert) != "FC2" {
		t.Errorf("cert not updated, got %q", cert)
	}
	if *reloads != 2 {
		t.Errorf("reloads = %d, want 2", *reloads)
	}
}

func TestRecoversMissingFiles(t *testing.T) {
	// If the on-disk files are deleted but Valkey is unchanged, watch rewrites
	// them (missing file counts as differing).
	dir := t.TempDir()
	w, c, _ := testWatcher(t, "")
	v := seed(t, c, "knit:a", dir, "FC", "PK")
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 1: %v", err)
	}
	os.Remove(v.CertPath)

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if _, err := os.Stat(v.CertPath); err != nil {
		t.Errorf("cert not recreated: %v", err)
	}
}

func TestSkipsAbsentValue(t *testing.T) {
	// An index member without a value is skipped, not an error.
	w, c, reloads := testWatcher(t, "caddy reload")
	if err := c.AddToIndex(context.Background(), "knit:ghost"); err != nil {
		t.Fatalf("AddToIndex: %v", err)
	}
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if *reloads != 0 {
		t.Errorf("reloads = %d, want 0 (nothing written)", *reloads)
	}
}

func TestReloadFailureIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	w, c, _ := testWatcher(t, "false")
	w.runReload = func(context.Context, string) error { return errors.New("exit 1") }
	seed(t, c, "knit:a", dir, "FC", "PK")

	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("reload failure must not fail the pass, got %v", err)
	}
}

func TestAtomicWriteSetsModeRegardlessOfUmask(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.pem")
	if err := atomicWrite(p, []byte("data"), 0o644); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 0644", info.Mode().Perm())
	}
	// No leftover temp files in the directory.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only the target file, found %d entries", len(entries))
	}
}
