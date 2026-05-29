// Package renew implements the central reconcile pass: the only writer to
// Valkey. Each pass it loads enabled certs from Postgres, issues/renews any that
// are near expiry via ACME (DNS-01), publishes every enabled cert's current
// material + metadata to its valkey_key, maintains the index SET, and prunes
// Valkey entries for certs that were removed or disabled.
package renew

import (
	"context"
	"log/slog"
	"time"

	"github.com/x6c-co/knit/internal/store"
	"github.com/x6c-co/knit/internal/valkey"
)

// CertStore is the subset of the Postgres store the reconcile loop needs. Kept
// narrow so the loop can be tested with a fake.
type CertStore interface {
	EnsureSchema(ctx context.Context) error
	ListEnabled(ctx context.Context) ([]store.Cert, error)
	MarkRenewed(ctx context.Context, id int64, notAfter, lastRenewed time.Time) error
	MarkError(ctx context.Context, id int64, msg string) error
}

// Issuer obtains certificate material for a set of domains using a named DNS
// provider. The production implementation wraps the acme package; tests use a
// fake.
type Issuer interface {
	Obtain(ctx context.Context, provider string, domains []string) (fullchain, privkey []byte, notAfter time.Time, err error)
}

// Publisher is the Valkey surface the reconcile loop needs. *valkey.Client
// satisfies it, so tests run against a real (mini)redis.
type Publisher interface {
	SetCert(ctx context.Context, key string, v valkey.Value) error
	GetCert(ctx context.Context, key string) (*valkey.Value, bool, error)
	AddToIndex(ctx context.Context, key string) error
	IndexMembers(ctx context.Context) ([]string, error)
	Prune(ctx context.Context, key string) error
}

// Runner holds the dependencies for a reconcile pass. The Issuer is created
// lazily (and the ACME account registered on first use) only when a cert
// actually needs issuance, so passes that just refresh metadata never touch ACME.
type Runner struct {
	Store         CertStore
	Pub           Publisher
	Log           *slog.Logger
	ThresholdDays int

	newIssuer func(ctx context.Context) (Issuer, error)
	issuer    Issuer
}

// NewRunner constructs a Runner. newIssuer is invoked at most once per Runner,
// the first time a cert needs issuing.
func NewRunner(s CertStore, pub Publisher, log *slog.Logger, thresholdDays int, newIssuer func(ctx context.Context) (Issuer, error)) *Runner {
	return &Runner{Store: s, Pub: pub, Log: log, ThresholdDays: thresholdDays, newIssuer: newIssuer}
}

func (r *Runner) getIssuer(ctx context.Context) (Issuer, error) {
	if r.issuer != nil {
		return r.issuer, nil
	}
	iss, err := r.newIssuer(ctx)
	if err != nil {
		return nil, err
	}
	r.issuer = iss
	return iss, nil
}

// Run performs a single reconcile pass. It never returns early on a single
// cert's failure — that cert's error is logged and recorded, and the pass
// continues. It returns an error only for failures that prevent the whole pass
// (schema, listing certs).
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Store.EnsureSchema(ctx); err != nil {
		return err
	}
	certs, err := r.Store.ListEnabled(ctx)
	if err != nil {
		return err
	}

	enabled := make(map[string]bool, len(certs))
	for _, c := range certs {
		enabled[c.ValkeyKey] = true
	}

	for _, c := range certs {
		if err := r.reconcileCert(ctx, c); err != nil {
			r.Log.Error("cert reconcile failed", "id", c.ID, "domains", c.Domains, "err", err)
			if e := r.Store.MarkError(ctx, c.ID, err.Error()); e != nil {
				r.Log.Error("recording last_error failed", "id", c.ID, "err", e)
			}
			// A single cert's failure must never abort the pass.
		}
	}

	r.prune(ctx, enabled)
	return nil
}

// thresholdDuration is the renewal window as a duration.
func (r *Runner) thresholdDuration() time.Duration {
	return time.Duration(r.ThresholdDays) * 24 * time.Hour
}

func (r *Runner) reconcileCert(ctx context.Context, c store.Cert) error {
	domains := splitDomains(c.Domains)

	// Decide whether we must obtain fresh material: no known expiry, or within
	// the renewal threshold.
	needIssue := c.NotAfter == nil || time.Until(*c.NotAfter) < r.thresholdDuration()

	var fullchain, privkey []byte
	var notAfter time.Time
	issued := false

	if !needIssue {
		// Cert is still valid: reuse the material already in Valkey and just
		// refresh the metadata (paths may have changed in Postgres). If the
		// value is somehow absent, fall through to issuance to repopulate it.
		existing, ok, err := r.Pub.GetCert(ctx, c.ValkeyKey)
		if err != nil {
			return err
		}
		if ok && existing.Fullchain != "" {
			fullchain = []byte(existing.Fullchain)
			privkey = []byte(existing.Privkey)
			notAfter = *c.NotAfter
		} else {
			needIssue = true
		}
	}

	if needIssue {
		iss, err := r.getIssuer(ctx)
		if err != nil {
			return err
		}
		fc, pk, na, err := iss.Obtain(ctx, c.Provider, domains)
		if err != nil {
			return err
		}
		fullchain, privkey, notAfter = fc, pk, na
		issued = true
	}

	// Publish the value (cert material + current paths from Postgres) and ensure
	// it is indexed. Done every pass so Valkey always reflects current metadata.
	v := valkey.Value{
		Fullchain: string(fullchain),
		Privkey:   string(privkey),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
		SHA256:    valkey.Hash(fullchain, privkey),
		CertPath:  c.CertPath,
		KeyPath:   c.KeyPath,
	}
	if err := r.Pub.SetCert(ctx, c.ValkeyKey, v); err != nil {
		return err
	}
	if err := r.Pub.AddToIndex(ctx, c.ValkeyKey); err != nil {
		return err
	}

	if issued {
		if err := r.Store.MarkRenewed(ctx, c.ID, notAfter, time.Now()); err != nil {
			return err
		}
		r.Log.Info("issued certificate", "id", c.ID, "domains", c.Domains, "not_after", notAfter)
	} else {
		r.Log.Debug("refreshed metadata", "id", c.ID, "domains", c.Domains)
	}
	return nil
}

// prune removes Valkey entries (index membership + per-cert value) for any index
// member whose cert is no longer enabled/present in Postgres. Failures are
// logged, never fatal.
func (r *Runner) prune(ctx context.Context, enabled map[string]bool) {
	members, err := r.Pub.IndexMembers(ctx)
	if err != nil {
		r.Log.Error("reading index for prune failed", "err", err)
		return
	}
	for _, m := range members {
		if enabled[m] {
			continue
		}
		if err := r.Pub.Prune(ctx, m); err != nil {
			r.Log.Error("pruning stale cert failed", "key", m, "err", err)
			continue
		}
		r.Log.Info("pruned stale cert", "key", m)
	}
}
