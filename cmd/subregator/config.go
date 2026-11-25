package main

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/url"

	"strconv"
	"strings"
)

type config struct {
	RequestsRPS     int
	MaxConcurrent   int
	DatabaseURL     string
	ChecksRPM       int
	IPinfoLiteToken string
	Addr            string
	Snapshot        string
	FeedsDir        string
	Providers       string
	Network         bool
	CORSOrigin      string
	LogFormat       string
	LogLevel        slog.Level
}

func loadConfig(args []string, getenv func(string) string, output io.Writer) (config, error) {
	env := func(key, fallback string) string {
		if value := getenv("SUBREGATOR_" + key); value != "" {
			return value
		}
		return fallback
	}
	c := config{}
	fs := flag.NewFlagSet("subregator", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&c.Addr, "addr", env("ADDR", "127.0.0.1:8080"), "HTTP listen address (SUBREGATOR_ADDR)")
	c.DatabaseURL = env("DATABASE_URL", "postgresql://subregator@127.0.0.1:5432/subregator?sslmode=disable")
	requestsRPS := fs.String("requests-rps", env("REQUESTS_RPS", "100"), "Global HTTP requests per second and burst (SUBREGATOR_REQUESTS_RPS)")
	maxConcurrent := fs.String("max-concurrent", env("MAX_CONCURRENT", "32"), "Maximum simultaneous HTTP operations (SUBREGATOR_MAX_CONCURRENT)")
	checksRPM := fs.String("checks-rpm", env("CHECKS_RPM", "120"), "Maximum free upstream requests per minute (SUBREGATOR_CHECKS_RPM)")
	fs.StringVar(&c.Snapshot, "snapshot", env("SNAPSHOT", "var/catalog.json"), "Legacy snapshot import path (SUBREGATOR_SNAPSHOT)")
	fs.StringVar(&c.FeedsDir, "feeds-dir", env("FEEDS_DIR", ""), "Canonical feed directory (SUBREGATOR_FEEDS_DIR)")
	fs.StringVar(&c.Providers, "providers", env("PROVIDERS", ""), "Provider registry JSON (SUBREGATOR_PROVIDERS)")
	fs.BoolVar(&c.Network, "network", true, "Enable public source polling (SUBREGATOR_NETWORK)")
	fs.StringVar(&c.CORSOrigin, "cors-origin", env("CORS_ORIGIN", ""), "Exact frontend origin (SUBREGATOR_CORS_ORIGIN)")
	fs.StringVar(&c.LogFormat, "log-format", env("LOG_FORMAT", "text"), "Log format: json or text (SUBREGATOR_LOG_FORMAT)")
	level := fs.String("log-level", env("LOG_LEVEL", "info"), "Log level: debug, info, warn, error (SUBREGATOR_LOG_LEVEL)")
	if e := fs.Parse(args); e != nil {
		return c, e
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	networkFlag := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "network" {
			networkFlag = true
		}
	})
	if !networkFlag {
		if value := getenv("SUBREGATOR_NETWORK"); value != "" {
			n, e := strconv.ParseBool(value)
			if e != nil {
				return c, errors.New("invalid SUBREGATOR_NETWORK")
			}
			c.Network = n
		}
	}
	host, port, e := net.SplitHostPort(c.Addr)
	if e != nil {
		return c, errors.New("invalid listen address")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strings.TrimSpace(host) != host {
		return c, errors.New("invalid listen address")
	}
	c.RequestsRPS, e = strconv.Atoi(*requestsRPS)
	if e != nil || c.RequestsRPS < 1 || c.RequestsRPS > 10000 {
		return c, errors.New("requests-rps must be between 1 and 10000")
	}
	c.MaxConcurrent, e = strconv.Atoi(*maxConcurrent)
	if e != nil || c.MaxConcurrent < 1 || c.MaxConcurrent > 1024 {
		return c, errors.New("max-concurrent must be between 1 and 1024")
	}
	c.ChecksRPM, e = strconv.Atoi(*checksRPM)
	if e != nil || c.ChecksRPM < 1 || c.ChecksRPM > 600 {
		return c, errors.New("checks-rpm must be between 1 and 600")
	}
	c.IPinfoLiteToken = getenv("SUBREGATOR_IPINFO_LITE_TOKEN")
	if len(c.IPinfoLiteToken) > 1024 || strings.ContainsAny(c.IPinfoLiteToken, "\r\n") {
		return c, errors.New("invalid IPinfo Lite token format")
	}
	if getenv("SUBREGATOR_DATABASE") != "" {
		return c, errors.New("SUBREGATOR_DATABASE is retired; migrate SQLite and use SUBREGATOR_DATABASE_URL")
	}
	if !strings.HasPrefix(c.DatabaseURL, "postgresql://") && !strings.HasPrefix(c.DatabaseURL, "postgres://") {
		return c, errors.New("PostgreSQL URL required in SUBREGATOR_DATABASE_URL")
	}
	if strings.TrimSpace(c.Snapshot) == "" {
		return c, errors.New("snapshot path must not be empty")
	}
	if c.CORSOrigin != "" {
		u, e := url.Parse(c.CORSOrigin)
		if e != nil || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
			return c, errors.New("CORS origin must be an http(s) scheme and host, with optional port")
		}
	}
	if c.CORSOrigin != "" {
		u, _ := url.Parse(c.CORSOrigin)
		if strings.ContainsAny(c.CORSOrigin, "?#") || strings.HasSuffix(u.Host, ":") {
			return c, errors.New("invalid CORS origin")
		}
		if u.Port() != "" {
			n, e := strconv.Atoi(u.Port())
			if e != nil || n < 1 || n > 65535 {
				return c, errors.New("invalid CORS port")
			}
		}
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return c, errors.New("invalid log format")
	}
	switch strings.ToLower(*level) {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return c, errors.New("invalid log level")
	}
	return c, nil
}
