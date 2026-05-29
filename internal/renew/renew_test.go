package renew

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/x6c-co/knit/internal/store"
	"github.com/x6c-co/knit/internal/valkey"
)

// --- fakes ---

type fakeStore struct {
	certs   []store.Cert
	renewed map[int64]time.Time
	errors  map[int64]string
}

func newFakeStore(certs ...store.Cert) *fakeStore {
	return &fakeStore{certs: certs, renewed: map[int64]time.Time{}, errors: map[int64]string{}}
}

func (f *fakeStore) EnsureSchema(context.Context) error { return nil }
func (f *fakeStore) ListEnabled(context.Context) ([]store.Cert, error) {
	return f.certs, nil
}
func (f *fakeStore) MarkRenewed(_ context.Context, id int64, notAfter, _ time.Time) error {
	f.renewed[id] = notAfter
	delete(f.errors, id)
	return nil
}
func (f *fakeStore) MarkError(_ context.Context, id int64, msg string) error {
	f.errors[id] = msg
	return nil
}

type fakeIssuer struct {
	calls     int
	fullchain string
	privkey   string
	notAfter  time.Time
	err       error
}

func (f *fakeIssuer) Obtain(context.Context, string, []string) ([]byte, []byte, time.Time, error) {
	f.calls++
	if f.err != nil {
		return nil, nil, time.Time{}, f.err
	}
	return []byte(f.fullchain), []byte(f.privkey), f.notAfter, nil
}

func testPub(t *testing.T) *valkey.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := valkey.New("redis://"+mr.Addr(), "knit:index")
	if err != nil {
		t.Fatalf("valkey.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func runnerWith(t *testing.T, s CertStore, iss Issuer) (*Runner, *valkey.Client) {
	pub := testPub(t)
	r := NewRunner(s, pub, discardLog(), 30, func(context.Context) (Issuer, error) {
		return iss, nil
	})
	return r, pub
}

// --- tests ---

func TestRunIssuesAndPublishes(t *testing.T) {
	// Cert with no not_after must be issued, published, and indexed (acceptance #2).
	fs := newFakeStore(store.Cert{
		ID: 1, Domains: "example.com,www.example.com", Provider: "desec",
		ValkeyKey: "knit:example", CertPath: "/c.pem", KeyPath: "/k.pem",
	})
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	iss := &fakeIssuer{fullchain: "FULLCHAIN", privkey: "PRIVKEY", notAfter: notAfter}
	r, pub := runnerWith(t, fs, iss)

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if iss.calls != 1 {
		t.Fatalf("issuer called %d times, want 1", iss.calls)
	}

	v, ok, _ := pub.GetCert(context.Background(), "knit:example")
	if !ok {
		t.Fatal("value not published")
	}
	if v.Fullchain != "FULLCHAIN" || v.Privkey != "PRIVKEY" {
		t.Errorf("material mismatch: %+v", v)
	}
	if v.CertPath != "/c.pem" || v.KeyPath != "/k.pem" {
		t.Errorf("paths not carried from postgres: %+v", v)
	}
	if v.SHA256 != valkey.Hash([]byte("FULLCHAIN"), []byte("PRIVKEY")) {
		t.Error("sha256 mismatch with shared Hash")
	}
	members, _ := pub.IndexMembers(context.Background())
	if len(members) != 1 || members[0] != "knit:example" {
		t.Errorf("index members = %v", members)
	}
	if !fs.renewed[1].Equal(notAfter) {
		t.Errorf("MarkRenewed not_after = %v, want %v", fs.renewed[1], notAfter)
	}
}

func TestRunValidCertRefreshesMetadataWithoutIssuing(t *testing.T) {
	// Cert valid well beyond threshold: must NOT call the issuer, but must still
	// republish with current paths from Postgres (advisor constraint #2).
	future := time.Now().Add(60 * 24 * time.Hour)
	fs := newFakeStore(store.Cert{
		ID: 1, Domains: "example.com", Provider: "desec",
		ValkeyKey: "knit:example", CertPath: "/new/c.pem", KeyPath: "/new/k.pem",
		NotAfter: &future,
	})
	iss := &fakeIssuer{err: errors.New("issuer must not be called")}
	r, pub := runnerWith(t, fs, iss)

	// Seed existing material under the old paths.
	pub.SetCert(context.Background(), "knit:example", valkey.Value{
		Fullchain: "EXISTING_FC", Privkey: "EXISTING_PK",
		NotAfter: future.UTC().Format(time.RFC3339),
		SHA256:   valkey.Hash([]byte("EXISTING_FC"), []byte("EXISTING_PK")),
		CertPath: "/old/c.pem", KeyPath: "/old/k.pem",
	})

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if iss.calls != 0 {
		t.Fatalf("issuer called %d times, want 0", iss.calls)
	}
	v, _, _ := pub.GetCert(context.Background(), "knit:example")
	if v.Fullchain != "EXISTING_FC" {
		t.Errorf("material should be reused, got %q", v.Fullchain)
	}
	if v.CertPath != "/new/c.pem" || v.KeyPath != "/new/k.pem" {
		t.Errorf("paths should be refreshed from postgres: %+v", v)
	}
	if _, ok := fs.renewed[1]; ok {
		t.Error("MarkRenewed should not be called when no issuance occurred")
	}
}

func TestRunValidCertButMissingValueReissues(t *testing.T) {
	// Cert valid per Postgres but its Valkey value is absent: must re-issue to
	// repopulate rather than publish empty material.
	future := time.Now().Add(60 * 24 * time.Hour)
	fs := newFakeStore(store.Cert{
		ID: 1, Domains: "example.com", Provider: "desec",
		ValkeyKey: "knit:example", CertPath: "/c.pem", KeyPath: "/k.pem",
		NotAfter: &future,
	})
	iss := &fakeIssuer{fullchain: "REISSUED", privkey: "PK", notAfter: future}
	r, pub := runnerWith(t, fs, iss)

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if iss.calls != 1 {
		t.Fatalf("issuer called %d times, want 1 (repopulate)", iss.calls)
	}
	v, ok, _ := pub.GetCert(context.Background(), "knit:example")
	if !ok || v.Fullchain != "REISSUED" {
		t.Errorf("value not repopulated: ok=%v v=%+v", ok, v)
	}
}

func TestRunPrunesDisabledCert(t *testing.T) {
	// knit:gone is in the index but not among enabled certs → must be pruned
	// (acceptance #5).
	future := time.Now().Add(60 * 24 * time.Hour)
	fs := newFakeStore(store.Cert{
		ID: 1, Domains: "keep.com", Provider: "desec",
		ValkeyKey: "knit:keep", CertPath: "/c", KeyPath: "/k", NotAfter: &future,
	})
	iss := &fakeIssuer{}
	r, pub := runnerWith(t, fs, iss)

	ctx := context.Background()
	// Seed both a kept cert's value and a stale one.
	pub.SetCert(ctx, "knit:keep", valkey.Value{Fullchain: "FC", Privkey: "PK"})
	pub.AddToIndex(ctx, "knit:keep")
	pub.SetCert(ctx, "knit:gone", valkey.Value{Fullchain: "OLD", Privkey: "OLD"})
	pub.AddToIndex(ctx, "knit:gone")

	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	members, _ := pub.IndexMembers(ctx)
	if len(members) != 1 || members[0] != "knit:keep" {
		t.Errorf("index after prune = %v, want [knit:keep]", members)
	}
	if _, ok, _ := pub.GetCert(ctx, "knit:gone"); ok {
		t.Error("stale value should be deleted")
	}
}

func TestRunOneFailureDoesNotAbortPass(t *testing.T) {
	// Two certs both need issuance; the issuer always errors for one of them.
	// The pass must record last_error and still process the other.
	fs := newFakeStore(
		store.Cert{ID: 1, Domains: "bad.com", Provider: "desec", ValkeyKey: "knit:bad", CertPath: "/c1", KeyPath: "/k1"},
		store.Cert{ID: 2, Domains: "good.com", Provider: "desec", ValkeyKey: "knit:good", CertPath: "/c2", KeyPath: "/k2"},
	)
	// Issuer that fails the first time (bad.com) then succeeds (good.com).
	iss := &failOnceIssuer{notAfter: time.Now().Add(90 * 24 * time.Hour)}
	r, pub := runnerWith(t, fs, iss)

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run should not return error on per-cert failure: %v", err)
	}
	if fs.errors[1] == "" {
		t.Error("expected last_error recorded for failing cert")
	}
	if _, ok, _ := pub.GetCert(context.Background(), "knit:good"); !ok {
		t.Error("good cert should still be published after the other failed")
	}
}

type failOnceIssuer struct {
	calls    int
	notAfter time.Time
}

func (f *failOnceIssuer) Obtain(context.Context, string, []string) ([]byte, []byte, time.Time, error) {
	f.calls++
	if f.calls == 1 {
		return nil, nil, time.Time{}, errors.New("dns propagation timeout")
	}
	return []byte("FC"), []byte("PK"), f.notAfter, nil
}

func TestSplitDomains(t *testing.T) {
	got := splitDomains(" a.com , b.com ,, c.com ")
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
