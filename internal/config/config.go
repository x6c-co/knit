// Package config loads knit configuration from the environment. Configuration
// is loaded per-subcommand so that, for example, `watch` never requires
// KNIT_DB_URL or any Postgres setting — only its local Valkey.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for the optional environment variables.
const (
	DefaultIndexKey           = "knit:index"
	DefaultACMEDirectory      = "https://acme-v02.api.letsencrypt.org/directory"
	DefaultRenewThresholdDays = 30
	DefaultRenewInterval      = 12 * time.Hour
	DefaultWatchInterval      = 60 * time.Second
)

// SetupLogger builds a structured slog.Logger writing to stderr at the level
// given by KNIT_LOG_LEVEL (debug/info/warn/error; default info).
func SetupLogger() *slog.Logger {
	var level slog.Level
	switch os.Getenv("KNIT_LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// required returns the value of an env var or an error naming it.
func required(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

// stringDefault returns the env var value or def when unset/empty.
func stringDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// durationDefault parses a Go duration env var, falling back to def.
func durationDefault(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

// intDefault parses an integer env var, falling back to def.
func intDefault(name string, def int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

// boolDefault parses a boolean env var (per strconv.ParseBool: 1/t/true/0/f/
// false, etc.), falling back to def when unset.
func boolDefault(name string, def bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

// splitList parses a comma-separated env var into a slice, trimming spaces and
// dropping empties. It returns nil when the var is unset/empty.
func splitList(name string) []string {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Central holds the configuration for Postgres-backed central commands
// (add/remove/list). It requires KNIT_DB_URL.
type Central struct {
	DBURL string
}

// LoadCentral reads the configuration for add/remove/list.
func LoadCentral() (*Central, error) {
	dbURL, err := required("KNIT_DB_URL")
	if err != nil {
		return nil, err
	}
	return &Central{DBURL: dbURL}, nil
}

// Renew holds the configuration for the renew command. It is the only command
// that touches Postgres, Valkey, and ACME together.
type Renew struct {
	DBURL         string
	ValkeyURL     string
	IndexKey      string
	ACMEDirectory string
	ACMEEmail     string
	ThresholdDays int
	Interval      time.Duration

	// DNS-01 propagation-precheck controls (all optional). DNSResolvers and
	// DNSTimeout configure lego's process-global recursive resolver used by the
	// precheck and zone/CNAME lookups; DNSDisableRecursiveCheck drops the
	// cache-prone recursive check entirely and relies on the authoritative one.
	DNSResolvers             []string
	DNSTimeout               time.Duration
	DNSDisableRecursiveCheck bool
}

// LoadRenew reads the configuration for renew.
func LoadRenew() (*Renew, error) {
	dbURL, err := required("KNIT_DB_URL")
	if err != nil {
		return nil, err
	}
	valkeyURL, err := required("KNIT_VALKEY_URL")
	if err != nil {
		return nil, err
	}
	threshold, err := intDefault("KNIT_RENEW_THRESHOLD_DAYS", DefaultRenewThresholdDays)
	if err != nil {
		return nil, err
	}
	interval, err := durationDefault("KNIT_RENEW_INTERVAL", DefaultRenewInterval)
	if err != nil {
		return nil, err
	}
	dnsTimeout, err := durationDefault("KNIT_DNS_TIMEOUT", 0)
	if err != nil {
		return nil, err
	}
	disableRecursive, err := boolDefault("KNIT_DNS_DISABLE_RECURSIVE_CHECK", false)
	if err != nil {
		return nil, err
	}
	return &Renew{
		DBURL:                    dbURL,
		ValkeyURL:                valkeyURL,
		IndexKey:                 stringDefault("KNIT_INDEX_KEY", DefaultIndexKey),
		ACMEDirectory:            stringDefault("KNIT_ACME_DIRECTORY", DefaultACMEDirectory),
		ACMEEmail:                os.Getenv("KNIT_ACME_EMAIL"),
		ThresholdDays:            threshold,
		Interval:                 interval,
		DNSResolvers:             splitList("KNIT_DNS_RESOLVERS"),
		DNSTimeout:               dnsTimeout,
		DNSDisableRecursiveCheck: disableRecursive,
	}, nil
}

// Watch holds the configuration for the watch command. It deliberately requires
// no Postgres configuration: only Valkey, the index key, the poll interval, and
// an optional reload command.
type Watch struct {
	ValkeyURL string
	IndexKey  string
	Interval  time.Duration
	ReloadCmd string
}

// LoadWatch reads the configuration for watch.
func LoadWatch() (*Watch, error) {
	valkeyURL, err := required("KNIT_VALKEY_URL")
	if err != nil {
		return nil, err
	}
	interval, err := durationDefault("KNIT_WATCH_INTERVAL", DefaultWatchInterval)
	if err != nil {
		return nil, err
	}
	return &Watch{
		ValkeyURL: valkeyURL,
		IndexKey:  stringDefault("KNIT_INDEX_KEY", DefaultIndexKey),
		Interval:  interval,
		ReloadCmd: os.Getenv("KNIT_RELOAD_CMD"),
	}, nil
}
