package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/subregator/subregator-backend/internal/history"
)

func migrateSQLite(args []string) error {
	fs := flag.NewFlagSet("migrate-sqlite", flag.ContinueOnError)
	source := fs.String("source", "", "Existing SQLite v1 database; read-only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || fs.NArg() != 0 {
		return errors.New("usage: subregator migrate-sqlite -source PATH; set SUBREGATOR_DATABASE_URL")
	}
	target := os.Getenv("SUBREGATOR_DATABASE_URL")
	if target == "" {
		return errors.New("SUBREGATOR_DATABASE_URL required for migration")
	}
	d, err := history.Open(target)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	report, err := d.ImportSQLite(ctx, *source)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
