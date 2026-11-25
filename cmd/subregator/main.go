package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/subregator/subregator-backend/internal/api"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"github.com/subregator/subregator-backend/internal/providers"
)

var version = "dev"
var revision = "unknown"

func main() {
	if e := run(); e != nil && !errors.Is(e, flag.ErrHelp) {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "revision": revision, "go": runtime.Version()})
	}
	if len(args) > 0 && args[0] == "migrate-sqlite" {
		return migrateSQLite(args[1:])
	}
	healthcheck := len(args) > 0 && args[0] == "healthcheck"
	if healthcheck {
		args = args[1:]
	}
	cfg, e := loadConfig(args, os.Getenv, os.Stderr)
	if e != nil {
		return e
	}
	if healthcheck {
		return probe(cfg.Addr)
	}
	options := slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stdout, &options)
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &options)
	}
	slog.SetDefault(slog.New(handler))
	p := catalog.Providers()
	if cfg.Providers != "" {
		b, e := os.ReadFile(cfg.Providers)
		if e != nil {
			return fmt.Errorf("read providers: %w", e)
		}
		if e = json.Unmarshal(b, &p); e != nil {
			return fmt.Errorf("decode providers: %w", e)
		}
	}
	database, e := history.Open(cfg.DatabaseURL)
	if e != nil {
		return fmt.Errorf("open history database: %w", e)
	}
	defer database.Close()
	if e = database.AcquireWriter(context.Background()); e != nil {
		return e
	}
	store, e := catalog.NewPersistentStore(database, cfg.Snapshot, p)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	checks := intelligence.New(database, cfg.Network, cfg.IPinfoLiteToken, cfg.ChecksRPM)
	if cfg.AbuseIPDB {
		checks.EnableAbuseIPDB(cfg.AbuseIPDBKey)
	}
	if cfg.IRR {
		checks.EnableIRR()
	}
	automatic := intelligence.NewAutomatic(checks)
	checksDone := make(chan struct{})
	go func() { defer close(checksDone); automatic.Run(ctx, store) }()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); providers.Run(ctx, store, cfg.FeedsDir, cfg.Network) }()
	server := &http.Server{Addr: cfg.Addr, Handler: api.Handler(store, cfg.CORSOrigin, api.Services{Limits: api.NewRequestLimits(cfg.RequestsRPS, cfg.MaxConcurrent), History: database, Intelligence: checks, Automatic: automatic}), BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() {
		slog.Info("API listening", "address", cfg.Addr, "version", version, "revision", revision, "requests_rps", cfg.RequestsRPS, "max_concurrent", cfg.MaxConcurrent)
		done <- server.ListenAndServe()
	}()
	select {
	case e := <-done:
		stop()
		<-workerDone
		<-checksDone
		return e
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e = server.Shutdown(shutdown)
	<-workerDone
	<-checksDone
	return e
}
