// Package watch implements the node-side poll loop. It relies solely on Valkey:
// it reads the index SET to discover certs, GETs each value, writes changed
// material to disk atomically, and runs a locally-configured reload command at
// most once per pass when anything changed. It never touches Postgres.
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/x6c-co/knit/internal/valkey"
)

// Reader is the Valkey surface watch needs: list the index and GET values.
type Reader interface {
	IndexMembers(ctx context.Context) ([]string, error)
	GetCert(ctx context.Context, key string) (*valkey.Value, bool, error)
}

// Watcher writes certs from Valkey to disk and runs a reload command on change.
type Watcher struct {
	Reader    Reader
	ReloadCmd string
	Log       *slog.Logger

	// runReload executes the reload command; overridable in tests.
	runReload func(ctx context.Context, cmd string) error
}

// New builds a Watcher. reloadCmd may be empty (no reload).
func New(reader Reader, reloadCmd string, log *slog.Logger) *Watcher {
	return &Watcher{Reader: reader, ReloadCmd: reloadCmd, Log: log, runReload: shellReload}
}

// RunOnce performs a single watch pass. Errors for an individual cert are logged
// locally and never abort the pass (watch cannot write Postgres). It returns an
// error only when the index itself cannot be read.
func (w *Watcher) RunOnce(ctx context.Context) error {
	members, err := w.Reader.IndexMembers(ctx)
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}

	changed := false
	for _, key := range members {
		v, ok, err := w.Reader.GetCert(ctx, key)
		if err != nil {
			w.Log.Error("reading cert value failed", "key", key, "err", err)
			continue
		}
		if !ok {
			// Value absent (e.g. mid-prune); skip per spec.
			w.Log.Debug("index member has no value, skipping", "key", key)
			continue
		}
		wrote, err := w.syncCert(*v)
		if err != nil {
			w.Log.Error("writing cert to disk failed", "key", key, "err", err)
			continue
		}
		if wrote {
			changed = true
			w.Log.Info("wrote cert", "key", key, "cert_path", v.CertPath, "key_path", v.KeyPath)
		}
	}

	// One reload covers all changed certs, run at most once per pass.
	if changed && w.ReloadCmd != "" {
		if err := w.runReload(ctx, w.ReloadCmd); err != nil {
			// Logged but not fatal: a non-zero exit must not crash the watcher.
			w.Log.Error("reload command failed", "cmd", w.ReloadCmd, "err", err)
		} else {
			w.Log.Info("ran reload command", "cmd", w.ReloadCmd)
		}
	}
	return nil
}

// syncCert writes the cert material to disk if the on-disk state differs from
// the value's hash. It reports whether it wrote anything.
func (w *Watcher) syncCert(v valkey.Value) (bool, error) {
	if !diskDiffers(v) {
		return false, nil
	}
	if err := atomicWrite(v.CertPath, []byte(v.Fullchain), 0o644); err != nil {
		return false, fmt.Errorf("write fullchain %q: %w", v.CertPath, err)
	}
	if err := atomicWrite(v.KeyPath, []byte(v.Privkey), 0o600); err != nil {
		return false, fmt.Errorf("write privkey %q: %w", v.KeyPath, err)
	}
	return true, nil
}

// diskDiffers reports whether the on-disk cert/key differ from the value. A
// missing file counts as differing (needs writing). The on-disk hash uses the
// same shared valkey.Hash as renew, with cert_path bytes as fullchain and
// key_path bytes as privkey.
func diskDiffers(v valkey.Value) bool {
	cert, err1 := os.ReadFile(v.CertPath)
	key, err2 := os.ReadFile(v.KeyPath)
	if err1 != nil || err2 != nil {
		return true
	}
	return valkey.Hash(cert, key) != v.SHA256
}

// atomicWrite writes data to path via a temp file in the destination directory
// followed by a rename (atomic on the same filesystem). The mode is set
// explicitly, since os.CreateTemp makes the temp file 0600.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".knit-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we don't make it to a successful rename.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// shellReload runs the reload command through the shell so users can configure
// arbitrary commands (e.g. "caddy reload").
func shellReload(ctx context.Context, cmd string) error {
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	return c.Run()
}
