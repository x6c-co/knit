// Package config loads knit configuration from the environment. Configuration
// is loaded per-subcommand so that, for example, `watch` never requires
// KNIT_DB_URL or any Postgres setting — only its local Valkey.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
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
	return &Renew{
		DBURL:         dbURL,
		ValkeyURL:     valkeyURL,
		IndexKey:      stringDefault("KNIT_INDEX_KEY", DefaultIndexKey),
		ACMEDirectory: stringDefault("KNIT_ACME_DIRECTORY", DefaultACMEDirectory),
		ACMEEmail:     os.Getenv("KNIT_ACME_EMAIL"),
		ThresholdDays: threshold,
		Interval:      interval,
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
