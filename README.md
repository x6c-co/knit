# knit

`knit` is a single Go binary that manages ACME (Let's Encrypt) certificates from
a central host and distributes them to consuming nodes. It has two sides, run on
different machines:

- **Central host** (`add` / `remove` / `list` / `renew`): keeps the certificate
  list in Postgres, renews certs via ACME using a DNS-01 challenge, and publishes
  each cert plus its watch metadata into Valkey.
- **Each consuming node** (`watch`): polls Valkey for those certificates, writes
  them to disk on change, and runs a locally configured reload command (e.g.
  `caddy reload`). **`watch` never connects to Postgres.**

Distribution from the central host to the nodes is handled externally by Valkey
replication. `knit` does not implement replication or transport security; it
assumes the network (e.g. a WireGuard mesh) provides that.

## Architecture

- **Postgres** is the source of truth for the cert list and renewal bookkeeping,
  accessed **only** by the central commands. It never stores issued certificate
  or private-key bytes.
- **`renew` is the only writer to Valkey.** Each pass it reconciles Postgres →
  Valkey: publishing/refreshing every enabled cert's value, maintaining an index
  SET, and pruning certs that were removed or disabled.
- **`watch` relies solely on Valkey.** It reads the index to discover which keys
  to watch and gets each cert's material and file paths from the per-cert value.
  A node needs only its local Valkey replica — no Postgres, no central host.

## Build

Requires Go (latest stable). Builds as a static binary:

```sh
CGO_ENABLED=0 go build -o knit .
```

## Configuration (environment variables)

| var | meaning | default | used by |
|-----|---------|---------|---------|
| `KNIT_DB_URL` | Postgres DSN | (required) | central commands only |
| `KNIT_VALKEY_URL` | Valkey connection string; supports auth and TLS (`rediss://`) | (required) | all |
| `KNIT_INDEX_KEY` | Valkey SET key listing active certs | `knit:index` | `renew`, `watch` |
| `KNIT_ACME_DIRECTORY` | ACME directory URL (point at LE **staging** for testing) | LE production | `renew` |
| `KNIT_ACME_EMAIL` | account email, used on first registration | — | `renew` |
| `KNIT_RENEW_THRESHOLD_DAYS` | renew when fewer than N days of validity remain | `30` | `renew` |
| `KNIT_RENEW_INTERVAL` | `renew` daemon check interval | `12h` | `renew` |
| `KNIT_WATCH_INTERVAL` | `watch` Valkey poll interval | `60s` | `watch` |
| `KNIT_RELOAD_CMD` | command `watch` runs once per pass when any cert changed; empty = no reload | (empty) | `watch` |
| `KNIT_LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` | all |

`watch` requires **no** Postgres configuration.

### DNS provider credentials

The DNS provider is selected **per cert** (the `provider` field) using
[lego](https://github.com/go-acme/lego)'s built-in provider registry. Credentials
are supplied via environment variables following lego's own conventions, so
switching providers needs no code change. For example:

- **deSEC:** `DESEC_TOKEN`
- **Cloudflare:** `CLOUDFLARE_DNS_API_TOKEN`

See the [lego DNS provider docs](https://go-acme.github.io/lego/dns/) for the
variable names of other providers.

### CNAME delegation

You can issue certificates for domains **without giving knit any access to those
domains' DNS**, by delegating the ACME challenge to a zone you do control (e.g. a
deSEC-hosted `a5t.dev`). This is handled entirely at the lego/DNS layer — knit
needs no special configuration and no code changes.

How it works: lego follows CNAMEs when solving the DNS-01 challenge (on by
default; only `LEGO_DISABLE_CNAME_SUPPORT=true` turns it off). The DNS provider
writes the TXT record at the CNAME-resolved name, so the record lands in your
delegation zone rather than in the certificate's own domain.

Setup:

1. **Add the cert in knit using the REAL domain(s)** — never the delegation
   target. lego discovers the target at runtime by following the CNAME.

   ```sh
   knit add --domains example.com --provider desec \
     --valkey-key knit:example.com \
     --cert-path /etc/ssl/example/fullchain.pem \
     --key-path  /etc/ssl/example/privkey.pem
   ```

2. **Create a static CNAME, once, in each real domain's zone** (out of band —
   knit/lego never creates or touches this). Note the source label is
   `_acme-challenge` (hyphen):

   ```dns
   _acme-challenge.example.com.  CNAME  _acme-challenge.example.acme.a5t.dev.
   ```

   The target name is your choice since it lives in your zone; only the
   `_acme-challenge.<domain>` source label is fixed by ACME.

3. **Point the provider credentials at the delegation zone.** Set `DESEC_TOKEN`
   to a token that controls `a5t.dev` (deSEC resolves whether `a5t.dev` or
   `acme.a5t.dev` is the registered domain). The token's scope must allow both
   reading the responsible zone and writing the `_acme-challenge.*` TXT RRset.

With that in place, `knit renew` issues normally: lego writes the TXT into your
deSEC delegation zone, and the certificate is issued for `example.com` even
though knit has no access to `example.com`'s DNS.

Operational notes: deSEC propagation can lag — lego polls and you can extend the
wait with `DESEC_PROPAGATION_TIMEOUT`. A too-narrow deSEC token policy is the
most common live failure. Verify the whole path with a dry run against Let's
Encrypt **staging** (`KNIT_ACME_DIRECTORY`) before switching to production.

## Subcommands

### `knit add`

Insert or update a managed cert in Postgres (upsert on the unique domains set).
Writes Postgres only; the cert appears in Valkey after the next `renew` pass.

```sh
knit add \
  --domains example.com,www.example.com \
  --provider desec \
  --valkey-key knit:example.com \
  --cert-path /etc/ssl/example/fullchain.pem \
  --key-path  /etc/ssl/example/privkey.pem
```

All five flags are required.

### `knit remove`

Remove a managed cert by `--id` or `--domains`. The corresponding Valkey value
and index membership are cleaned up on the next `renew` pass.

```sh
knit remove --domains example.com,www.example.com
knit remove --id 3
```

### `knit list`

Print managed certs and their state: id, enabled, domains, provider, valkey_key,
paths, not_after, last_renewed, last_error.

```sh
knit list
```

### `knit renew [--once]`

Reconcile Postgres → Valkey. Runs as a daemon by default, reconciling every
`KNIT_RENEW_INTERVAL`; `--once` performs a single pass and exits (for cron / a
systemd timer). **This is the only command that writes Valkey.**

Each pass: load enabled certs, issue/renew any within the renewal threshold (or
with no known expiry) via ACME DNS-01, publish every enabled cert's value +
metadata to its `valkey_key`, maintain the index SET, and prune Valkey entries
for certs that are no longer enabled/present. A single cert's failure is recorded
in `last_error` and never aborts the pass.

```sh
# one pass against Let's Encrypt staging
KNIT_DB_URL=postgres://... \
KNIT_VALKEY_URL=redis://... \
KNIT_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory \
KNIT_ACME_EMAIL=ops@example.com \
DESEC_TOKEN=... \
knit renew --once
```

### `knit watch [--once]`

Poll Valkey and write changed certs to disk. Runs as a daemon by default, polling
every `KNIT_WATCH_INTERVAL`; `--once` performs a single pass and exits. A single
`watch` process handles all certs. **No Postgres access.**

Each pass: read the index, GET each value, and where the on-disk files differ
from the published hash, write the fullchain (`0644`) and private key (`0600`)
atomically (temp file + rename in the destination directory). If anything changed
and `KNIT_RELOAD_CMD` is set, run it exactly once; a non-zero exit is logged but
does not crash the watcher.

```sh
KNIT_VALKEY_URL=redis://... \
KNIT_RELOAD_CMD='caddy reload' \
knit watch
```

Both daemons shut down gracefully on SIGINT/SIGTERM, finishing the current pass
before exiting.

## Testing

```sh
go test ./...
```

The store package's tests are integration tests that run only when
`KNIT_TEST_DB_URL` points at a disposable Postgres database (they create/drop
`knit_` tables and truncate them); they skip otherwise. All other packages —
including the renew reconcile loop and the watch loop — are unit-tested against
an in-memory Valkey, so the suite runs with no external services.
