package main

import (
	"context"
	"flag"
	"log/slog"

	"github.com/x6c-co/knit/internal/config"
	"github.com/x6c-co/knit/internal/renew"
	"github.com/x6c-co/knit/internal/store"
	"github.com/x6c-co/knit/internal/valkey"
	"github.com/x6c-co/knit/internal/watch"
)

func runRenew(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	once := fs.Bool("once", false, "perform a single reconcile pass and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadRenew()
	if err != nil {
		return err
	}

	ctx := context.Background()
	s, err := store.Open(ctx, cfg.DBURL)
	if err != nil {
		return err
	}
	defer s.Close()

	vk, err := valkey.New(cfg.ValkeyURL, cfg.IndexKey)
	if err != nil {
		return err
	}
	defer vk.Close()

	runner := renew.NewRunner(s, vk, log, cfg.ThresholdDays,
		renew.ACMEIssuerFactory(s, cfg.ACMEDirectory, cfg.ACMEEmail, log))

	runDaemon("renew", cfg.Interval, *once, log, runner.Run)
	return nil
}

func runWatch(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	once := fs.Bool("once", false, "perform a single watch pass and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadWatch()
	if err != nil {
		return err
	}

	vk, err := valkey.New(cfg.ValkeyURL, cfg.IndexKey)
	if err != nil {
		return err
	}
	defer vk.Close()

	w := watch.New(vk, cfg.ReloadCmd, log)
	runDaemon("watch", cfg.Interval, *once, log, w.RunOnce)
	return nil
}
