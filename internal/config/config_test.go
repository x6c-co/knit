package config

import (
	"testing"
	"time"
)

func TestLoadWatchNeedsNoPostgres(t *testing.T) {
	// Acceptance criterion #3: watch runs with only KNIT_VALKEY_URL (+ reload),
	// no Postgres configuration present at all.
	t.Setenv("KNIT_VALKEY_URL", "redis://localhost:6379")
	t.Setenv("KNIT_RELOAD_CMD", "caddy reload")

	w, err := LoadWatch()
	if err != nil {
		t.Fatalf("LoadWatch: %v", err)
	}
	if w.IndexKey != DefaultIndexKey {
		t.Errorf("IndexKey = %q, want default", w.IndexKey)
	}
	if w.Interval != DefaultWatchInterval {
		t.Errorf("Interval = %v, want %v", w.Interval, DefaultWatchInterval)
	}
	if w.ReloadCmd != "caddy reload" {
		t.Errorf("ReloadCmd = %q", w.ReloadCmd)
	}
}

func TestLoadWatchRequiresValkey(t *testing.T) {
	if _, err := LoadWatch(); err == nil {
		t.Fatal("expected error when KNIT_VALKEY_URL unset")
	}
}

func TestLoadRenewDefaultsAndOverrides(t *testing.T) {
	t.Setenv("KNIT_DB_URL", "postgres://x")
	t.Setenv("KNIT_VALKEY_URL", "redis://x")

	r, err := LoadRenew()
	if err != nil {
		t.Fatalf("LoadRenew: %v", err)
	}
	if r.ThresholdDays != DefaultRenewThresholdDays {
		t.Errorf("ThresholdDays = %d, want %d", r.ThresholdDays, DefaultRenewThresholdDays)
	}
	if r.Interval != DefaultRenewInterval {
		t.Errorf("Interval = %v", r.Interval)
	}
	if r.ACMEDirectory != DefaultACMEDirectory {
		t.Errorf("ACMEDirectory = %q", r.ACMEDirectory)
	}

	t.Setenv("KNIT_RENEW_THRESHOLD_DAYS", "7")
	t.Setenv("KNIT_RENEW_INTERVAL", "1h")
	r, err = LoadRenew()
	if err != nil {
		t.Fatalf("LoadRenew override: %v", err)
	}
	if r.ThresholdDays != 7 {
		t.Errorf("ThresholdDays = %d, want 7", r.ThresholdDays)
	}
	if r.Interval != time.Hour {
		t.Errorf("Interval = %v, want 1h", r.Interval)
	}
}

func TestLoadRenewBadDuration(t *testing.T) {
	t.Setenv("KNIT_DB_URL", "postgres://x")
	t.Setenv("KNIT_VALKEY_URL", "redis://x")
	t.Setenv("KNIT_RENEW_INTERVAL", "not-a-duration")
	if _, err := LoadRenew(); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoadCentralRequiresDBURL(t *testing.T) {
	if _, err := LoadCentral(); err == nil {
		t.Fatal("expected error when KNIT_DB_URL unset")
	}
	t.Setenv("KNIT_DB_URL", "postgres://x")
	if _, err := LoadCentral(); err != nil {
		t.Fatalf("LoadCentral: %v", err)
	}
}
