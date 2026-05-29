package acme

import (
	"context"
	"crypto"
	"strings"
	"testing"

	lacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge/dns01"
)

func TestAccountKeyRoundTrip(t *testing.T) {
	a, err := NewAccount("ops@example.com")
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if a.Registered() {
		t.Fatal("new account should not be registered")
	}
	if a.GetPrivateKey() == nil {
		t.Fatal("nil private key")
	}

	// Persist and reload: the reconstructed key must match the original.
	keyPEM := a.KeyPEM()
	if !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatalf("unexpected PEM:\n%s", keyPEM)
	}
	reg, err := a.RegistrationJSON()
	if err != nil {
		t.Fatalf("RegistrationJSON: %v", err)
	}
	if reg != "" {
		t.Fatalf("unregistered account should have empty registration JSON, got %q", reg)
	}

	loaded, err := LoadAccount("ops@example.com", keyPEM, "")
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if loaded.GetEmail() != "ops@example.com" {
		t.Errorf("email = %q", loaded.GetEmail())
	}
	// The reconstructed key must be the same key we generated.
	orig := a.GetPrivateKey().Public().(interface{ Equal(crypto.PublicKey) bool })
	if !orig.Equal(loaded.GetPrivateKey().Public()) {
		t.Fatal("reloaded account key does not match original")
	}
	if loaded.Registered() {
		t.Fatal("account loaded with empty registration should not be registered")
	}
}

func TestLoadAccountWithRegistration(t *testing.T) {
	a, _ := NewAccount("ops@example.com")
	// Simulate a registered account.
	a.registration = &lacme.ExtendedAccount{Location: "https://acme/acct/1"}
	if !a.Registered() {
		t.Fatal("expected Registered()=true")
	}
	regJSON, err := a.RegistrationJSON()
	if err != nil {
		t.Fatalf("RegistrationJSON: %v", err)
	}

	loaded, err := LoadAccount("ops@example.com", a.KeyPEM(), regJSON)
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if !loaded.Registered() {
		t.Fatal("reloaded account should be registered")
	}
	if loaded.GetRegistration().Location != "https://acme/acct/1" {
		t.Errorf("registration location = %q", loaded.GetRegistration().Location)
	}
}

func TestObtainUnknownProvider(t *testing.T) {
	// Both with and without the recursive-check skip, an unrecognized provider
	// must fail fast with no network call.
	for _, disableRecursive := range []bool{false, true} {
		a, _ := NewAccount("ops@example.com")
		c, err := NewClient(a, "https://acme-staging-v02.api.letsencrypt.org/directory", disableRecursive)
		if err != nil {
			t.Fatalf("NewClient(disableRecursive=%v): %v", disableRecursive, err)
		}
		_, err = c.Obtain(context.Background(), "definitely-not-a-provider", []string{"example.com"})
		if err == nil {
			t.Fatalf("disableRecursive=%v: expected error for unknown DNS provider", disableRecursive)
		}
	}
}

func TestConfigureDNSResolvers(t *testing.T) {
	// ConfigureDNSResolvers swaps lego's process-global resolver client; restore
	// the original afterward so it cannot leak into other tests.
	before := dns01.DefaultClient()
	t.Cleanup(func() { dns01.SetDefaultClient(before) })

	// No-op when both args are zero: the global client must be untouched so lego
	// keeps its default behavior.
	ConfigureDNSResolvers(nil, 0)
	if dns01.DefaultClient() != before {
		t.Fatal("ConfigureDNSResolvers(nil, 0) should be a no-op")
	}

	// Setting resolvers installs a new global client.
	ConfigureDNSResolvers([]string{"9.9.9.9", "1.1.1.1:53"}, 0)
	if dns01.DefaultClient() == before {
		t.Fatal("ConfigureDNSResolvers with resolvers should replace the default client")
	}
}
