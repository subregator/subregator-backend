package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}
func TestConfigDefaults(t *testing.T) {
	c, e := loadConfig(nil, envMap(nil), io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	if c.Addr != "127.0.0.1:8080" || c.Snapshot != "var/catalog.json" || !c.Network || c.FeedsDir != "" || c.Providers != "" || c.CORSOrigin != "" || c.LogFormat != "text" || c.LogLevel != slog.LevelInfo {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}
func TestEnvironmentAndFlagPrecedence(t *testing.T) {
	env := envMap(map[string]string{"SUBREGATOR_ADDR": "0.0.0.0:9000", "SUBREGATOR_SNAPSHOT": "/data/catalog.json", "SUBREGATOR_FEEDS_DIR": "/feeds", "SUBREGATOR_PROVIDERS": "/config/providers.json", "SUBREGATOR_NETWORK": "false", "SUBREGATOR_CORS_ORIGIN": "https://example.com:444", "SUBREGATOR_LOG_FORMAT": "json", "SUBREGATOR_LOG_LEVEL": "warn"})
	c, e := loadConfig(nil, env, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	if c.Addr != "0.0.0.0:9000" || c.Network || c.Snapshot != "/data/catalog.json" || c.FeedsDir != "/feeds" || c.Providers != "/config/providers.json" || c.CORSOrigin != "https://example.com:444" || c.LogFormat != "json" || c.LogLevel != slog.LevelWarn {
		t.Fatalf("environment ignored: %+v", c)
	}
	c, e = loadConfig([]string{"-addr", "127.0.0.1:8081", "-network=true", "-cors-origin=", "-log-format=text", "-log-level=debug"}, env, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	if c.Addr != "127.0.0.1:8081" || !c.Network || c.CORSOrigin != "" || c.LogFormat != "text" || c.LogLevel != slog.LevelDebug {
		t.Fatal("CLI flags did not override environment")
	}
	c, e = loadConfig([]string{"-network=false"}, envMap(map[string]string{"SUBREGATOR_NETWORK": "invalid"}), io.Discard)
	if e != nil || c.Network {
		t.Fatal("explicit boolean flag must override invalid environment", e)
	}
}
func TestInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "boolean", env: map[string]string{"SUBREGATOR_NETWORK": "not-a-bool"}},
		{name: "address", args: []string{"-addr=http://localhost:8080"}},
		{name: "port", args: []string{"-addr=127.0.0.1:65536"}},
		{name: "zero port", args: []string{"-addr=127.0.0.1:0"}},
		{name: "empty snapshot", args: []string{"-snapshot="}},
		{name: "level", args: []string{"-log-level=verbose"}},
		{name: "format", args: []string{"-log-format=xml"}},
		{name: "positionals", args: []string{"unexpected"}},
		{name: "unknown flag", args: []string{"-missing=value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := loadConfig(tc.args, envMap(tc.env), io.Discard); e == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, origin := range []string{"*", "https://user:password@example.com", "https://example.com/", "https://example.com/path", "https://example.com?x=1", "https://example.com?", "https://example.com#", "https://example.com#x", "ftp://example.com", "null", "https://example.com:65536", "https://example.com:"} {
		if _, e := loadConfig([]string{"-cors-origin=" + origin}, envMap(nil), io.Discard); e == nil {
			t.Errorf("invalid CORS origin accepted: %s", origin)
		}
	}
	_, e := loadConfig(nil, envMap(map[string]string{"SUBREGATOR_NETWORK": "sensitive-input"}), io.Discard)
	if e == nil || strings.Contains(e.Error(), "sensitive-input") {
		t.Fatal("environment value exposed in error")
	}
	if _, e = loadConfig([]string{"-h"}, envMap(nil), io.Discard); !errors.Is(e, flag.ErrHelp) {
		t.Fatal("help handling changed", e)
	}
}

func TestHistoryConfigurationAndFreeToken(t *testing.T) {
	env := envMap(map[string]string{"SUBREGATOR_DATABASE_URL": "postgresql://localhost/test", "SUBREGATOR_CHECKS_RPM": "90", "SUBREGATOR_IPINFO_LITE_TOKEN": "test-free-token"})
	c, e := loadConfig(nil, env, io.Discard)
	if e != nil || c.DatabaseURL != "postgresql://localhost/test" || c.ChecksRPM != 90 || c.IPinfoLiteToken != "test-free-token" {
		t.Fatal("history configuration failed", e)
	}
	for _, args := range [][]string{{"-checks-rpm=0"}, {"-checks-rpm=601"}} {
		if _, e := loadConfig(args, envMap(nil), io.Discard); e == nil {
			t.Fatal("invalid history settings accepted")
		}
	}
}

func TestRequestLimitConfiguration(t *testing.T) {
	c, e := loadConfig(nil, envMap(nil), io.Discard)
	if e != nil || c.RequestsRPS != 100 || c.MaxConcurrent != 32 {
		t.Fatal("unsafe request limit defaults", c, e)
	}
	env := envMap(map[string]string{"SUBREGATOR_REQUESTS_RPS": "50", "SUBREGATOR_MAX_CONCURRENT": "8"})
	c, e = loadConfig(nil, env, io.Discard)
	if e != nil || c.RequestsRPS != 50 || c.MaxConcurrent != 8 {
		t.Fatal("request limit environment ignored", e)
	}
	c, e = loadConfig([]string{"-requests-rps=75", "-max-concurrent=16"}, env, io.Discard)
	if e != nil || c.RequestsRPS != 75 || c.MaxConcurrent != 16 {
		t.Fatal("request limit flags ignored", e)
	}
	for _, args := range [][]string{{"-requests-rps=0"}, {"-requests-rps=-1"}, {"-requests-rps=10001"}, {"-requests-rps=bad"}, {"-max-concurrent=0"}, {"-max-concurrent=-1"}, {"-max-concurrent=1025"}, {"-max-concurrent=bad"}} {
		if _, e := loadConfig(args, envMap(nil), io.Discard); e == nil {
			t.Fatal("invalid request limits accepted", args)
		}
	}
}

func TestPostgreSQLConfigurationDoesNotExposeCredentials(t *testing.T) {
	secretURL := "postgresql://user:configuration-test-secret@localhost/db"
	var output bytes.Buffer
	_, err := loadConfig([]string{"-help"}, envMap(map[string]string{"SUBREGATOR_DATABASE_URL": secretURL}), &output)
	if err == nil || strings.Contains(err.Error(), "configuration-test-secret") || strings.Contains(output.String(), "configuration-test-secret") {
		t.Fatal("database URL exposed in help")
	}
	if _, err = loadConfig(nil, envMap(map[string]string{"SUBREGATOR_DATABASE": "legacy.db"}), io.Discard); err == nil {
		t.Fatal("legacy SQLite setting silently accepted")
	}
	if _, err = loadConfig(nil, envMap(map[string]string{"SUBREGATOR_DATABASE_URL": "sqlite://old.db"}), io.Discard); err == nil {
		t.Fatal("non-PostgreSQL runtime accepted")
	}
}

func TestIRRConfigurationGate(t *testing.T) {
	c, err := loadConfig(nil, envMap(nil), io.Discard)
	if err != nil || c.IRR {
		t.Fatal("IRR must be off by default", err)
	}
	c, err = loadConfig(nil, envMap(map[string]string{"SUBREGATOR_IRR": "true"}), io.Discard)
	if err != nil || !c.IRR {
		t.Fatal("IRR environment ignored", err)
	}
	c, err = loadConfig([]string{"-irr=false"}, envMap(map[string]string{"SUBREGATOR_IRR": "invalid"}), io.Discard)
	if err != nil || c.IRR {
		t.Fatal("IRR flag precedence broken", err)
	}
	if _, err = loadConfig(nil, envMap(map[string]string{"SUBREGATOR_IRR": "private-value"}), io.Discard); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("invalid IRR setting exposed or accepted")
	}
}

func TestAbuseIPDBConfigurationGateAndKeyPrivacy(t *testing.T) {
	c, err := loadConfig(nil, envMap(nil), io.Discard)
	if err != nil || c.AbuseIPDB || c.AbuseIPDBKey != "" {
		t.Fatal("abuse must be off by default")
	}
	values := map[string]string{"SUBREGATOR_ABUSEIPDB": "true", "SUBREGATOR_ABUSEIPDB_KEY": "fixture-private-key"}
	c, err = loadConfig(nil, envMap(values), io.Discard)
	if err != nil || !c.AbuseIPDB || c.AbuseIPDBKey != "fixture-private-key" {
		t.Fatal("abuse environment ignored", err)
	}
	values["SUBREGATOR_ABUSEIPDB"] = "invalid"
	c, err = loadConfig([]string{"-abuseipdb=false"}, envMap(values), io.Discard)
	if err != nil || c.AbuseIPDB {
		t.Fatal("abuse flag precedence broken", err)
	}
	var out bytes.Buffer
	loadConfig([]string{"-h"}, envMap(values), &out)
	if strings.Contains(out.String(), "fixture-private-key") {
		t.Fatal("key exposed in help")
	}
	values["SUBREGATOR_ABUSEIPDB"] = "false"
	values["SUBREGATOR_ABUSEIPDB_KEY"] = "fixture-private-key\n"
	if _, err := loadConfig(nil, envMap(values), io.Discard); err == nil || strings.Contains(err.Error(), "fixture-private-key") {
		t.Fatal("invalid key exposed or accepted")
	}
}

func TestSpamhausConfigurationAndKeyPrivacy(t *testing.T) {
	c, err := loadConfig(nil, envMap(nil), io.Discard)
	if err != nil || c.Spamhaus || c.SpamhausKey != "" {
		t.Fatal(c.Spamhaus, err)
	}
	values := map[string]string{"SUBREGATOR_SPAMHAUS": "true", "SUBREGATOR_SPAMHAUS_KEY": "fixture-private-key"}
	c, err = loadConfig(nil, envMap(values), io.Discard)
	if err != nil || !c.Spamhaus || c.SpamhausKey != "fixture-private-key" {
		t.Fatal("gate/key not loaded", err)
	}
	c, err = loadConfig([]string{"-spamhaus=false"}, envMap(values), io.Discard)
	if err != nil || c.Spamhaus {
		t.Fatal("flag override failed", err)
	}
	for _, value := range []string{"fixture-private\nkey", " fixture-private-key", strings.Repeat("x", 1025)} {
		values["SUBREGATOR_SPAMHAUS_KEY"] = value
		_, err = loadConfig(nil, envMap(values), io.Discard)
		if err == nil || strings.Contains(err.Error(), value) {
			t.Fatal("key validation leak")
		}
	}
}

func TestHistoryConfigDefaultAndPrecedence(t *testing.T) {
	c, e := loadConfig(nil, envMap(nil), io.Discard)
	if e != nil || c.HistoryChecks != "" {
		t.Fatal(e, c.HistoryChecks)
	}
	c, e = loadConfig(nil, envMap(map[string]string{"SUBREGATOR_HISTORY_CHECKS": "rpki"}), io.Discard)
	if e != nil || c.HistoryChecks != "rpki" {
		t.Fatal(e, c.HistoryChecks)
	}
	c, e = loadConfig([]string{"-history-checks="}, envMap(map[string]string{"SUBREGATOR_HISTORY_CHECKS": "rpki"}), io.Discard)
	if e != nil || c.HistoryChecks != "" {
		t.Fatal(e, c.HistoryChecks)
	}
}
