// Package acme is a thin wrapper over go-acme/lego v5 covering exactly what knit
// needs: holding the single ACME account, registering it on first use, and
// obtaining/renewing certificates via a per-cert DNS-01 provider chosen from
// lego's built-in provider registry. Provider credentials come from the
// environment following lego's own conventions (e.g. DESEC_TOKEN,
// CLOUDFLARE_DNS_API_TOKEN), so switching providers needs no code change.
package acme

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	lacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/registration"
)

// ConfigureDNSResolvers overrides lego's process-global recursive-resolver
// client, which is used by the DNS-01 propagation precheck and by zone/CNAME
// lookups. Call it once at startup, before any Obtain. It is a no-op when both
// arguments are zero so that lego keeps its default behavior (recursive
// nameservers from /etc/resolv.conf and the LEGO_EXPERIMENTAL_DNS_TCP_ONLY
// passthrough, which dns01.NewClient(opts) does not honor). lego mutates the
// Options in place, so a fresh literal is passed each call. Resolver entries
// without a port get :53 appended by lego.
func ConfigureDNSResolvers(resolvers []string, timeout time.Duration) {
	if len(resolvers) == 0 && timeout == 0 {
		return
	}
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{
		RecursiveNameservers: resolvers,
		Timeout:              timeout,
	}))
}

// Account is the single ACME account. It implements lego's registration.User
// interface. The private key and registration resource are persisted (as PEM
// and JSON) in Postgres by the caller; the issued cert/key bytes are not.
type Account struct {
	email        string
	privateKey   crypto.Signer
	registration *lacme.ExtendedAccount
}

// Compile-time check that Account satisfies lego's User interface.
var _ registration.User = (*Account)(nil)

func (a *Account) GetEmail() string                        { return a.email }
func (a *Account) GetRegistration() *lacme.ExtendedAccount { return a.registration }
func (a *Account) GetPrivateKey() crypto.Signer            { return a.privateKey }

// Registered reports whether the account already has a registration resource.
func (a *Account) Registered() bool { return a.registration != nil }

// NewAccount creates an account with a freshly generated EC P-256 account key
// and no registration yet.
func NewAccount(email string) (*Account, error) {
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	return &Account{email: email, privateKey: key}, nil
}

// LoadAccount reconstructs an account from a persisted PEM private key and the
// JSON-encoded registration resource. A blank registrationJSON means the account
// key exists but was never registered.
func LoadAccount(email, keyPEM, registrationJSON string) (*Account, error) {
	key, err := certcrypto.ParsePEMPrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	a := &Account{email: email, privateKey: key}
	if registrationJSON != "" {
		var reg lacme.ExtendedAccount
		if err := json.Unmarshal([]byte(registrationJSON), &reg); err != nil {
			return nil, fmt.Errorf("parse registration: %w", err)
		}
		a.registration = &reg
	}
	return a, nil
}

// KeyPEM returns the account private key as PEM, for persistence.
func (a *Account) KeyPEM() string {
	return string(certcrypto.PEMEncode(a.privateKey))
}

// RegistrationJSON returns the registration resource as JSON, for persistence.
// It returns "" when the account is not yet registered.
func (a *Account) RegistrationJSON() (string, error) {
	if a.registration == nil {
		return "", nil
	}
	b, err := json.Marshal(a.registration)
	if err != nil {
		return "", fmt.Errorf("marshal registration: %w", err)
	}
	return string(b), nil
}

// Client is a lego client bound to one Account and ACME directory.
type Client struct {
	lc      *lego.Client
	account *Account

	// disableRecursiveCheck, when set, drops the cache-prone recursive
	// propagation precheck and relies on the (inherently uncached) authoritative
	// check instead.
	disableRecursiveCheck bool
}

// NewClient builds a lego client for the account against the given ACME
// directory URL (point at Let's Encrypt staging for testing). When
// disableRecursiveCheck is set, DNS-01 issuance skips lego's recursive
// propagation check.
func NewClient(account *Account, directoryURL string, disableRecursiveCheck bool) (*Client, error) {
	cfg := lego.NewConfig(account)
	cfg.CADirURL = directoryURL
	lc, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new lego client: %w", err)
	}
	return &Client{lc: lc, account: account, disableRecursiveCheck: disableRecursiveCheck}, nil
}

// Register registers the account with the ACME server and stores the resulting
// registration resource on the Account. It is a no-op if already registered.
func (c *Client) Register(ctx context.Context) error {
	if c.account.Registered() {
		return nil
	}
	reg, err := c.lc.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("register acme account: %w", err)
	}
	c.account.registration = reg
	return nil
}

// Obtain issues (or renews — ACME treats both as a fresh order) a certificate
// for domains, solving DNS-01 with the named lego provider. The provider reads
// its credentials from the environment. The returned resource carries the
// bundled fullchain and the private key.
func (c *Client) Obtain(ctx context.Context, provider string, domains []string) (*certificate.Resource, error) {
	dnsProvider, err := dns.NewDNSChallengeProviderByName(provider)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", provider, err)
	}
	var opts []dns01.ChallengeOption
	if c.disableRecursiveCheck {
		opts = append(opts, dns01.DisableRecursiveNSsPropagationRequirement())
	}
	if err := c.lc.Challenge.SetDNS01Provider(dnsProvider, opts...); err != nil {
		return nil, fmt.Errorf("set dns-01 provider %q: %w", provider, err)
	}
	res, err := c.lc.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true, // fullchain = leaf + intermediates
		// lego v5 dropped the Config.Certificate.KeyType default (v4 had one);
		// the key type must be set per request or Obtain fails with
		// "the key type is missing".
		KeyType: certcrypto.EC256,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain certificate for %v: %w", domains, err)
	}
	return res, nil
}
