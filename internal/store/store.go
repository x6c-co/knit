// Package store is the Postgres access layer, used ONLY by the central-side
// commands (add/remove/list/renew). It is the source of truth for the cert list
// and renewal bookkeeping. It never stores issued certificate or private-key
// bytes — those live solely in Valkey. The `watch` command never imports this
// package.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Cert is a row of knit_certs.
type Cert struct {
	ID          int64
	Domains     string // comma-separated SANs; first entry is the primary/CN
	Provider    string // lego provider code, e.g. "desec", "cloudflare"
	ValkeyKey   string
	CertPath    string
	KeyPath     string
	Enabled     bool
	NotAfter    *time.Time
	LastRenewed *time.Time
	LastError   string
}

// Account is the single-row knit_acme_account.
type Account struct {
	Email        string
	PrivateKey   string // PEM
	Registration string // JSON of the lego registration resource
}

// Store wraps a pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres using the given DSN.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// EnsureSchema creates knit_ tables if absent. The database is shared with the
// rest of the project, so this uses CREATE TABLE IF NOT EXISTS and prefixes all
// names with knit_; it must coexist with unrelated tables.
func (s *Store) EnsureSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS knit_certs (
	id           BIGSERIAL PRIMARY KEY,
	domains      TEXT NOT NULL,
	provider     TEXT NOT NULL,
	valkey_key   TEXT NOT NULL,
	cert_path    TEXT NOT NULL,
	key_path     TEXT NOT NULL,
	enabled      BOOLEAN NOT NULL DEFAULT true,
	not_after    TIMESTAMPTZ,
	last_renewed TIMESTAMPTZ,
	last_error   TEXT,
	UNIQUE (domains)
);
CREATE TABLE IF NOT EXISTS knit_acme_account (
	email        TEXT,
	private_key  TEXT,
	registration TEXT
);`
	if _, err := s.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("ensure schema: %w", err)
	}
	return nil
}

// Upsert inserts a managed cert, or updates the provider/keys/paths of the
// existing row with the same domains set. It re-enables a previously disabled
// row. It does not touch renewal bookkeeping.
func (s *Store) Upsert(ctx context.Context, c Cert) error {
	const q = `
INSERT INTO knit_certs (domains, provider, valkey_key, cert_path, key_path, enabled)
VALUES ($1, $2, $3, $4, $5, true)
ON CONFLICT (domains) DO UPDATE SET
	provider   = EXCLUDED.provider,
	valkey_key = EXCLUDED.valkey_key,
	cert_path  = EXCLUDED.cert_path,
	key_path   = EXCLUDED.key_path,
	enabled    = true`
	if _, err := s.pool.Exec(ctx, q, c.Domains, c.Provider, c.ValkeyKey, c.CertPath, c.KeyPath); err != nil {
		return fmt.Errorf("upsert cert: %w", err)
	}
	return nil
}

// RemoveByID deletes a cert by id, returning whether a row was removed.
func (s *Store) RemoveByID(ctx context.Context, id int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM knit_certs WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("remove by id: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RemoveByDomains deletes a cert by its domains set, returning whether a row was
// removed.
func (s *Store) RemoveByDomains(ctx context.Context, domains string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM knit_certs WHERE domains = $1`, domains)
	if err != nil {
		return false, fmt.Errorf("remove by domains: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

const selectColumns = `id, domains, provider, valkey_key, cert_path, key_path, enabled, not_after, last_renewed, COALESCE(last_error, '')`

func scanCerts(rows pgx.Rows) ([]Cert, error) {
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		var c Cert
		if err := rows.Scan(&c.ID, &c.Domains, &c.Provider, &c.ValkeyKey, &c.CertPath,
			&c.KeyPath, &c.Enabled, &c.NotAfter, &c.LastRenewed, &c.LastError); err != nil {
			return nil, fmt.Errorf("scan cert: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// List returns all managed certs ordered by id.
func (s *Store) List(ctx context.Context) ([]Cert, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selectColumns+` FROM knit_certs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	return scanCerts(rows)
}

// ListEnabled returns only enabled certs ordered by id.
func (s *Store) ListEnabled(ctx context.Context) ([]Cert, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selectColumns+` FROM knit_certs WHERE enabled = true ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list enabled certs: %w", err)
	}
	return scanCerts(rows)
}

// MarkRenewed records a successful renewal: updates not_after/last_renewed and
// clears last_error.
func (s *Store) MarkRenewed(ctx context.Context, id int64, notAfter, lastRenewed time.Time) error {
	const q = `UPDATE knit_certs SET not_after = $2, last_renewed = $3, last_error = NULL WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, notAfter, lastRenewed); err != nil {
		return fmt.Errorf("mark renewed: %w", err)
	}
	return nil
}

// MarkError records a renewal error for a cert without disturbing its other
// bookkeeping.
func (s *Store) MarkError(ctx context.Context, id int64, msg string) error {
	const q = `UPDATE knit_certs SET last_error = $2 WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, msg); err != nil {
		return fmt.Errorf("mark error: %w", err)
	}
	return nil
}

// GetAccount returns the single ACME account row, or ok=false if none exists.
func (s *Store) GetAccount(ctx context.Context) (*Account, bool, error) {
	var a Account
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(email, ''), COALESCE(private_key, ''), COALESCE(registration, '') FROM knit_acme_account LIMIT 1`).
		Scan(&a.Email, &a.PrivateKey, &a.Registration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get acme account: %w", err)
	}
	return &a, true, nil
}

// SaveAccount stores the ACME account, replacing any existing row so the table
// holds a single account.
func (s *Store) SaveAccount(ctx context.Context, a Account) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM knit_acme_account`); err != nil {
		return fmt.Errorf("clear acme account: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO knit_acme_account (email, private_key, registration) VALUES ($1, $2, $3)`,
		a.Email, a.PrivateKey, a.Registration); err != nil {
		return fmt.Errorf("insert acme account: %w", err)
	}
	return tx.Commit(ctx)
}
