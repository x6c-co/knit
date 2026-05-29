package valkey

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := New("redis://"+mr.Addr(), "knit:index")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestHashStableAndOrderSensitive(t *testing.T) {
	a := Hash([]byte("fullchain"), []byte("privkey"))
	b := Hash([]byte("fullchain"), []byte("privkey"))
	if a != b {
		t.Fatalf("hash not stable: %s != %s", a, b)
	}
	// Concatenation order matters: swapping the inputs must change the digest,
	// otherwise a cert/key swap on disk would go undetected.
	if swapped := Hash([]byte("privkey"), []byte("fullchain")); swapped == a {
		t.Fatal("hash should depend on argument order")
	}
	// And it must not collide with a naive concatenation boundary shift.
	if shifted := Hash([]byte("fullchainpriv"), []byte("key")); shifted == a {
		t.Fatal("unexpected boundary collision")
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	v := Value{
		Fullchain: "CERT", Privkey: "KEY", NotAfter: "2026-01-01T00:00:00Z",
		SHA256: Hash([]byte("CERT"), []byte("KEY")), CertPath: "/c.pem", KeyPath: "/k.pem",
	}
	if err := c.SetCert(ctx, "knit:example", v); err != nil {
		t.Fatalf("SetCert: %v", err)
	}
	got, ok, err := c.GetCert(ctx, "knit:example")
	if err != nil || !ok {
		t.Fatalf("GetCert: ok=%v err=%v", ok, err)
	}
	if *got != v {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", *got, v)
	}
}

func TestGetMissingKey(t *testing.T) {
	c := newTestClient(t)
	_, ok, err := c.GetCert(context.Background(), "knit:absent")
	if err != nil {
		t.Fatalf("GetCert error on missing key: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for missing key")
	}
}

func TestIndexAddListPrune(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	c.SetCert(ctx, "knit:a", Value{Fullchain: "A"})
	c.SetCert(ctx, "knit:b", Value{Fullchain: "B"})
	if err := c.AddToIndex(ctx, "knit:a"); err != nil {
		t.Fatalf("AddToIndex: %v", err)
	}
	c.AddToIndex(ctx, "knit:b")

	members, err := c.IndexMembers(ctx)
	if err != nil {
		t.Fatalf("IndexMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("want 2 members, got %v", members)
	}

	// Prune removes both the index membership and the per-cert value.
	if err := c.Prune(ctx, "knit:a"); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	members, _ = c.IndexMembers(ctx)
	if len(members) != 1 || members[0] != "knit:b" {
		t.Fatalf("after prune want [knit:b], got %v", members)
	}
	if _, ok, _ := c.GetCert(ctx, "knit:a"); ok {
		t.Fatal("pruned value should be deleted")
	}
}
