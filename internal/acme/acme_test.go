package acme

import (
	"context"
	"crypto"
	"strings"
	"testing"

	lacme "github.com/go-acme/lego/v5/acme"
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
	a, _ := NewAccount("ops@example.com")
	c, err := NewClient(a, "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// An unrecognized provider must fail fast, with no network call.
	_, err = c.Obtain(context.Background(), "definitely-not-a-provider", []string{"example.com"})
	if err == nil {
		t.Fatal("expected error for unknown DNS provider")
	}
}
