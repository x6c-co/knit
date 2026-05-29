// Package valkey holds the Valkey client wrapper, the per-cert value
// (de)serialization, the shared change-detection hash, and index maintenance.
//
// It is the only shared dependency between the central-side `renew` command
// (the sole writer) and the node-side `watch` command (a reader). Everything
// `watch` needs lives in Valkey; it never touches Postgres.
package valkey

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Value is the JSON object stored at a managed cert's valkey_key. It is written
// with a single atomic SET so a reader never observes a half-updated pair, and
// it carries both the cert material and the metadata `watch` needs.
type Value struct {
	Fullchain string `json:"fullchain"`
	Privkey   string `json:"privkey"`
	NotAfter  string `json:"not_after"`
	SHA256    string `json:"sha256"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
}

// Hash is the single change-detection digest used by BOTH sides. `renew` hashes
// the cert material it publishes; `watch` hashes the on-disk file contents in
// the same order. They MUST be byte-identical or watch will either rewrite every
// pass or never detect a change. The concatenation order is fullchain then
// privkey. The fullchain length is written as an 8-byte big-endian prefix so the
// field boundary is unambiguous and the digest cannot collide across different
// splits of the same concatenated bytes.
func Hash(fullchain, privkey []byte) string {
	h := sha256.New()
	var lenPrefix [8]byte
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(fullchain)))
	h.Write(lenPrefix[:])
	h.Write(fullchain)
	h.Write(privkey)
	return hex.EncodeToString(h.Sum(nil))
}
