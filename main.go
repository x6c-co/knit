// Command knit manages ACME certificates from a central host (add/remove/list/
// renew over Postgres + Valkey) and distributes them to consuming nodes (watch
// over Valkey only). See README.md for usage.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/x6c-co/knit/internal/config"
)

const usage = `knit — ACME cert management and distribution

Usage: knit <command> [flags]

Central commands (require KNIT_DB_URL):
  add      Add or update a managed cert in Postgres
  remove   Remove a managed cert from Postgres
  list     List managed certs and their state
  renew    Reconcile Postgres -> Valkey: issue/renew certs and publish them
           (the only writer to Valkey). Daemon by default; --once for one pass.

Node command (requires only KNIT_VALKEY_URL):
  watch    Poll Valkey and write changed certs to disk, running KNIT_RELOAD_CMD
           on change. Daemon by default; --once for one pass.

Run "knit <command> -h" for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	log := config.SetupLogger()
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "add":
		err = runAdd(args)
	case "remove":
		err = runRemove(args)
	case "list":
		err = runList(args)
	case "renew":
		err = runRenew(args, log)
	case "watch":
		err = runWatch(args, log)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		log.Error("command failed", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

// runDaemon runs pass immediately, then (unless once) every interval until a
// SIGINT/SIGTERM arrives. Each pass runs with a non-cancelled context so an
// in-flight operation finishes before shutdown, per the graceful-shutdown
// requirement. Errors from a pass are logged, never fatal.
func runDaemon(name string, interval time.Duration, once bool, log loggerLike, pass func(context.Context) error) {
	doPass := func() {
		if err := pass(context.Background()); err != nil {
			log.Error("pass failed", "cmd", name, "err", err)
		}
	}

	// Install the signal handler before the first pass so that a signal arriving
	// during it (e.g. a multi-minute initial ACME issuance) is handled
	// gracefully: the in-flight pass runs on a non-cancelled context and
	// finishes, then we exit. Without this, a signal during the first pass would
	// hit Go's default behavior and kill the process mid-operation.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	doPass()
	if once || sigCtx.Err() != nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info("daemon started", "cmd", name, "interval", interval)
	for {
		select {
		case <-sigCtx.Done():
			log.Info("received signal, shutting down", "cmd", name)
			return
		case <-ticker.C:
			doPass()
			// If a signal arrived during the pass, exit now rather than waiting
			// for the next tick.
			if sigCtx.Err() != nil {
				log.Info("received signal, shutting down", "cmd", name)
				return
			}
		}
	}
}

// loggerLike is the slice of *slog.Logger used by runDaemon.
type loggerLike interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}
