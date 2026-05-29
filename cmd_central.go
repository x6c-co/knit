package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/x6c-co/knit/internal/config"
	"github.com/x6c-co/knit/internal/store"
)

// openStore loads central config and opens the Postgres store with schema
// ensured. The caller must Close it.
func openStore(ctx context.Context) (*store.Store, error) {
	cfg, err := config.LoadCentral()
	if err != nil {
		return nil, err
	}
	s, err := store.Open(ctx, cfg.DBURL)
	if err != nil {
		return nil, err
	}
	if err := s.EnsureSchema(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	domains := fs.String("domains", "", "comma-separated SANs; first is the primary/CN (required)")
	provider := fs.String("provider", "", "lego DNS provider code, e.g. desec, cloudflare (required)")
	valkeyKey := fs.String("valkey-key", "", "Valkey key holding this cert's bundle (required)")
	certPath := fs.String("cert-path", "", "where watch writes the fullchain PEM (required)")
	keyPath := fs.String("key-path", "", "where watch writes the private key PEM (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	missing := []string{}
	for name, v := range map[string]string{
		"--domains": *domains, "--provider": *provider, "--valkey-key": *valkeyKey,
		"--cert-path": *certPath, "--key-path": *keyPath,
	} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	ctx := context.Background()
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Upsert(ctx, store.Cert{
		Domains:   *domains,
		Provider:  *provider,
		ValkeyKey: *valkeyKey,
		CertPath:  *certPath,
		KeyPath:   *keyPath,
	}); err != nil {
		return err
	}
	fmt.Printf("added/updated cert for %s\n", *domains)
	return nil
}

func runRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	id := fs.Int64("id", 0, "cert id to remove")
	domains := fs.String("domains", "", "exact domains set to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 && *domains == "" {
		return errors.New("provide --id or --domains")
	}
	if *id != 0 && *domains != "" {
		return errors.New("provide only one of --id or --domains")
	}

	ctx := context.Background()
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	var removed bool
	if *id != 0 {
		removed, err = s.RemoveByID(ctx, *id)
	} else {
		removed, err = s.RemoveByDomains(ctx, *domains)
	}
	if err != nil {
		return err
	}
	if !removed {
		return errors.New("no matching cert found")
	}
	fmt.Println("removed; Valkey will be cleaned up on the next renew pass")
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	certs, err := s.List(ctx)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		fmt.Println("no managed certs")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tENABLED\tDOMAINS\tPROVIDER\tVALKEY_KEY\tCERT_PATH\tKEY_PATH\tNOT_AFTER\tLAST_RENEWED\tLAST_ERROR")
	for _, c := range certs {
		fmt.Fprintf(w, "%d\t%t\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.ID, c.Enabled, c.Domains, c.Provider, c.ValkeyKey, c.CertPath, c.KeyPath,
			fmtTime(c.NotAfter), fmtTime(c.LastRenewed), c.LastError)
	}
	return w.Flush()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
