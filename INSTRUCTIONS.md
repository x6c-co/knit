# knit — Technical Specification

## Overview

`knit` is a single Go binary with two responsibilities, exposed as subcommands of the same binary, intended to run on different machines:

1. **Central host** (`add` / `remove` / `list` / `renew`): manages the list of certificates in Postgres, renews them via ACME (DNS-01), and publishes each cert plus its watch metadata into Valkey.
2. **Each consuming node** (`watch`): polls Valkey for those certificates, writes them to disk on change, and runs a locally-configured reload command. **`watch` never connects to Postgres.**

Distribution of the cert from the central host to the nodes is handled externally by Valkey replication. `knit` does not implement replication, transport security, or any node-to-node communication.

## Architecture boundary (important)

- **Postgres is accessed only by the central-side commands** (`add`, `remove`, `list`, `renew`). It is the source of truth for the cert list and renewal bookkeeping.
- **`watch` relies solely on Valkey** for cert data and the list of certs — which keys to watch, and per cert the file paths. Its reload command is local deployment config (an env var), not pushed from the center. A POP needs only its local Valkey replica reachable; it has no dependency on Postgres or the central host at runtime.
- **`renew` is the only writer to Valkey.** Each pass it reconciles Postgres → Valkey: publishing/refreshing each enabled cert's value and maintaining an index key, and pruning certs that were removed or disabled.

## Non-goals

Do not build any of the following — explicitly out of scope:

- Ansible, systemd units, or any deployment/packaging tooling.
- Any cert distribution mechanism beyond writing to / reading from Valkey.
- Web UI, metrics/Prometheus endpoints, healthchecks, or notifications.
- Multiple ACME accounts.

Implement only what is specified below. Do not add features not described here.

## Tech stack

- **Language:** Go (latest stable). Binary must build with `CGO_ENABLED=0`.
- **ACME:** `github.com/go-acme/lego/v5` used as a library (not by shelling out to the CLI). **Note:** lego v5 is recent (v5.0.x, released May 2026) and its API differs from v4. Pin the latest v5.0.x, and verify the actual v5 library signatures (`lego.Client`, `registration`, the `providers/dns` registry, `certificate.Obtain`) against the v5 source/godoc before writing code — do not assume v4 call patterns. The major v5 changes are CLI-side and largely do not affect library use.
- **DNS providers:** provider-agnostic via lego's built-in provider registry (`dns.NewDNSChallengeProviderByName`). The provider is selected per managed cert. Provider credentials are supplied via environment variables following lego's own conventions. Must work with at least deSEC and Cloudflare with no code changes to switch between them.
- **Postgres client:** `github.com/jackc/pgx/v5` (pure Go, keeps `CGO_ENABLED=0`).
- **Valkey client:** `github.com/valkey-io/valkey-go` (acceptable to use `github.com/redis/go-redis/v9` instead if it is simpler).
- **Logging:** stdlib `log/slog`, structured, level configurable.

## Data model (Postgres)

The Postgres database is **shared with the rest of the project**, so:

- Create tables with `CREATE TABLE IF NOT EXISTS`.
- Prefix all table names with `knit_` to avoid collisions.
- Do not assume the database is empty or owned exclusively by `knit`.

**Table `knit_certs`:**

| column        | type        | notes |
|---------------|-------------|-------|
| id            | BIGSERIAL   | primary key |
| domains       | TEXT        | comma-separated SANs; first entry is the primary/CN |
| provider      | TEXT        | lego provider code, e.g. `desec`, `cloudflare` |
| valkey_key    | TEXT        | the Valkey key holding this cert's bundle |
| cert_path     | TEXT        | where `watch` writes the fullchain PEM |
| key_path      | TEXT        | where `watch` writes the private key PEM |
| enabled       | BOOLEAN     | default true |
| not_after     | TIMESTAMPTZ | last known expiry, updated by `renew` |
| last_renewed  | TIMESTAMPTZ | |
| last_error    | TEXT        | last renewal error, if any |

`UNIQUE(domains)`.

**Table `knit_acme_account`** (single row):

| column      | type | notes |
|-------------|------|-------|
| email       | TEXT | account email |
| private_key | TEXT | PEM, generated on first registration |
| registration| TEXT | JSON of the lego registration resource |

Postgres holds configuration, renewal bookkeeping, and the ACME account key only. It must **never** store issued certificate or private-key bytes — those live solely in Valkey.

## Valkey layout

### Per-cert value

One Valkey key per managed cert (`valkey_key`). The value is a single JSON object written with one `SET` (atomic, so a reader never observes a half-updated pair). It carries both the cert material and the metadata `watch` needs:

```json
{
  "fullchain":     "<PEM: leaf + intermediates>",
  "privkey":       "<PEM: private key>",
  "not_after":     "<RFC3339>",
  "sha256":        "<hex digest of fullchain+privkey, for change detection>",
  "cert_path":     "<where watch writes the fullchain>",
  "key_path":      "<where watch writes the private key>"
}
```

### Index key

`renew` maintains a Valkey SET (default key `knit:index`) whose members are the `valkey_key`s of all currently enabled certs. `watch` reads this set to discover what to watch. When a cert is removed or disabled, `renew` removes its member and deletes the per-cert value.

## Configuration (environment variables)

| var | meaning | default | used by |
|-----|---------|---------|---------|
| `KNIT_DB_URL` | Postgres DSN | (required) | central commands only |
| `KNIT_VALKEY_URL` | Valkey connection string; supports auth and TLS (`rediss://`). Transport security is assumed to be provided by the network (WireGuard mesh), so plaintext is acceptable. | (required) | all |
| `KNIT_INDEX_KEY` | Valkey SET key listing active certs | `knit:index` | `renew`, `watch` |
| `KNIT_ACME_DIRECTORY` | ACME directory URL. Point at Let's Encrypt **staging** for testing. | LE production | `renew` |
| `KNIT_ACME_EMAIL` | account email (for registration) | — | `renew` |
| `KNIT_RENEW_THRESHOLD_DAYS` | renew when fewer than N days of validity remain | `30` | `renew` |
| `KNIT_RENEW_INTERVAL` | `renew` daemon check interval | `12h` | `renew` |
| `KNIT_WATCH_INTERVAL` | `watch` Valkey poll interval | `60s` | `watch` |
| `KNIT_RELOAD_CMD` | command `watch` runs once per pass when any cert changed (e.g. `caddy reload`). If empty, no reload is run. | (empty) | `watch` |
| `KNIT_LOG_LEVEL` | `debug`/`info`/`warn`/`error` | `info` | all |

DNS provider credentials are passed via the environment per lego's conventions (e.g. `DESEC_TOKEN`, `CLOUDFLARE_DNS_API_TOKEN`).

`watch` must not require `KNIT_DB_URL` or any Postgres-related configuration.

## Subcommands

### `knit add`

Insert/upsert a managed cert in Postgres. Flags:

- `--domains` (csv, required)
- `--provider` (required)
- `--valkey-key` (required)
- `--cert-path` (required)
- `--key-path` (required)

Upsert on the unique `domains` set. Writes Postgres only; the cert appears in Valkey after the next `renew` pass issues/publishes it.

### `knit remove`

Remove a managed cert from Postgres by `--id` or `--domains`. The corresponding Valkey value and index membership are cleaned up on the next `renew` pass.

### `knit list`

Print managed certs and their state from Postgres: domains, provider, valkey_key, paths, not_after, last_renewed, last_error, enabled.

### `knit renew [--once]`

Runs as a daemon by default, reconciling every `KNIT_RENEW_INTERVAL`. `--once` performs a single pass and exits (for cron / systemd timer). This is the only command that writes Valkey.

On each pass:

1. Load all enabled certs from Postgres. Ensure tables exist first.
2. For each enabled cert:
   a. Determine remaining validity from `not_after`. If missing, treat as needing issuance.
   b. If remaining validity `< KNIT_RENEW_THRESHOLD_DAYS`, obtain/renew via lego using the cert's `provider` and a DNS-01 challenge. On first use, register the ACME account using `KNIT_ACME_EMAIL` and persist the account key + registration to `knit_acme_account`.
   c. Assemble the JSON value (cert material + current `cert_path` / `key_path` from Postgres) and `SET` it to `valkey_key`. Do this even when no renewal occurred, so Valkey always reflects current metadata.
   d. Add `valkey_key` to the index SET.
   e. On success update `not_after` / `last_renewed` and clear `last_error`; on failure record `last_error` and continue. **A single cert's failure must never abort the pass or crash the daemon.**
3. Prune: for any index member or per-cert key whose cert is no longer enabled/present in Postgres, delete the Valkey value and remove it from the index.

### `knit watch [--once]`

Runs as a daemon by default, polling every `KNIT_WATCH_INTERVAL`. `--once` performs a single pass and exits. A single `watch` process handles all certs. **No Postgres access.**

On each pass:

1. Read the members of `KNIT_INDEX_KEY` from Valkey.
2. For each member, `GET` its value. If absent, skip.
3. Compute the on-disk state (hash of existing `cert_path` + `key_path` contents) and compare to the value's `sha256`. If unchanged, do nothing.
4. If changed (or files missing): write `fullchain` to `cert_path` (mode `0644`) and `privkey` to `key_path` (mode `0600`), each via write-to-temp-then-rename within the destination directory (atomic).
5. After all members are processed, if **any** cert changed this pass and `KNIT_RELOAD_CMD` is non-empty, run it exactly once. A non-zero exit is logged but does not crash the watcher. (One reload covers all changed certs; in practice this is `caddy reload`.)

Errors in `watch` are logged locally only (it cannot write Postgres).

## Behavioral requirements

- All file writes are atomic (temp file + rename within the destination directory).
- The reload command runs only when on-disk files actually change, and at most once per `watch` pass.
- A single bad cert (renewal error, missing key, script failure) must never bring down a daemon — log it, record `last_error` where applicable, move on.
- Both daemons shut down gracefully on SIGINT/SIGTERM: finish the current operation, then exit.
- Issued cert/key bytes exist only in Valkey and on the nodes' disks — never in Postgres.
- `watch` has zero runtime dependency on Postgres or the central host; only its local Valkey must be reachable.

## Acceptance criteria

1. `knit add` / `knit list` / `knit remove` correctly manage entries in Postgres, creating tables if absent and coexisting with unrelated tables in the same database.
2. With `KNIT_ACME_DIRECTORY` set to Let's Encrypt **staging** and valid deSEC (or Cloudflare) credentials in the environment, `knit renew --once` issues a staging certificate for a configured domain, stores the JSON value at its `valkey_key`, and adds that key to the index SET.
3. `knit watch --once`, with only `KNIT_VALKEY_URL` and `KNIT_RELOAD_CMD` configured (no Postgres), discovers the cert via the index, writes the fullchain (`0644`) and private key (`0600`) to the paths carried in the value, and runs `KNIT_RELOAD_CMD` once.
4. Re-running `knit watch --once` with no change in Valkey writes nothing and does not run `KNIT_RELOAD_CMD`.
5. Removing a cert with `knit remove` causes the next `knit renew --once` pass to delete its Valkey value and drop it from the index.
6. The DNS provider can be switched between deSEC and Cloudflare for a given cert purely by changing the `provider` field — no code change.
7. The binary builds with `CGO_ENABLED=0`.

## Suggested repo layout

- `main.go` / `cmd/` — subcommand wiring
- `internal/store` — Postgres access (central commands only)
- `internal/acme` — lego wrapper (account registration, issue/renew)
- `internal/valkey` — client, value (de)serialization, index maintenance
- `internal/watch` — index read / GET / diff / atomic write / run reload command
- `README.md` — build instructions, env var reference, subcommand usage
