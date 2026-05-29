package renew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/x6c-co/knit/internal/acme"
	"github.com/x6c-co/knit/internal/store"
)

// splitDomains parses the comma-separated domains column into a slice, trimming
// spaces and dropping empties. The first entry is the primary/CN.
func splitDomains(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// AccountStore is the subset of the store used to load/persist the ACME account.
type AccountStore interface {
	GetAccount(ctx context.Context) (*store.Account, bool, error)
	SaveAccount(ctx context.Context, a store.Account) error
}

// ACMEIssuerFactory returns a newIssuer function suitable for NewRunner. On first
// call it loads the ACME account from Postgres (or generates one if absent),
// registers it if needed using email, persists the account, and returns an
// Issuer bound to a lego client for the given directory URL.
func ACMEIssuerFactory(as AccountStore, directoryURL, email string, log *slog.Logger) func(ctx context.Context) (Issuer, error) {
	return func(ctx context.Context) (Issuer, error) {
		stored, ok, err := as.GetAccount(ctx)
		if err != nil {
			return nil, err
		}

		var account *acme.Account
		if ok {
			account, err = acme.LoadAccount(stored.Email, stored.PrivateKey, stored.Registration)
			if err != nil {
				return nil, err
			}
		} else {
			if email == "" {
				return nil, errors.New("KNIT_ACME_EMAIL is required for first ACME registration")
			}
			account, err = acme.NewAccount(email)
			if err != nil {
				return nil, err
			}
		}

		client, err := acme.NewClient(account, directoryURL)
		if err != nil {
			return nil, err
		}

		if !account.Registered() {
			if err := client.Register(ctx); err != nil {
				return nil, err
			}
			regJSON, err := account.RegistrationJSON()
			if err != nil {
				return nil, err
			}
			if err := as.SaveAccount(ctx, store.Account{
				Email:        account.GetEmail(),
				PrivateKey:   account.KeyPEM(),
				Registration: regJSON,
			}); err != nil {
				return nil, fmt.Errorf("persist acme account: %w", err)
			}
			log.Info("registered ACME account", "email", account.GetEmail())
		}

		return &legoIssuer{client: client}, nil
	}
}

// legoIssuer adapts an acme.Client to the Issuer interface, parsing not_after
// from the issued leaf certificate.
type legoIssuer struct {
	client *acme.Client
}

func (l *legoIssuer) Obtain(ctx context.Context, provider string, domains []string) (fullchain, privkey []byte, notAfter time.Time, err error) {
	res, err := l.client.Obtain(ctx, provider, domains)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	certs, err := certcrypto.ParsePEMBundle(res.Certificate)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, nil, time.Time{}, errors.New("issued bundle contained no certificates")
	}
	// certs[0] is the leaf; its NotAfter is the cert's expiry.
	return res.Certificate, res.PrivateKey, certs[0].NotAfter, nil
}
