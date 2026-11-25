package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/subregator/subregator-backend/internal/catalog"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Feed struct {
	SchemaVersion int             `json:"schema_version"`
	ProviderID    string          `json:"provider_id"`
	Complete      bool            `json:"complete"`
	Offers        []catalog.Offer `json:"offers"`
}

func ReadFeed(path, id string) ([]catalog.Offer, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxBody+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxBody {
		return nil, errors.New("feed exceeds limit")
	}
	var feed Feed
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&feed); e != nil {
		return nil, errors.New("invalid feed")
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return nil, errors.New("trailing feed data")
	}
	if feed.SchemaVersion != 1 || feed.ProviderID != id || !feed.Complete || feed.Offers == nil {
		return nil, errors.New("invalid or incomplete feed")
	}
	for _, o := range feed.Offers {
		if o.ObservedAt.IsZero() {
			return nil, errors.New("feed observation timestamp missing")
		}
	}
	return feed.Offers, nil
}
func Run(ctx context.Context, s *catalog.Store, feedsDir string, network bool) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	client := Client()
	refresh := func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 3)
		for _, p := range s.View().Providers {
			builtIn := p.ID == "onie" || p.ID == "peaktera" || p.ID == "prefix-broker" || p.ID == "obhost"
			file := filepath.Join(feedsDir, p.ID+".json")
			_, fileErr := os.Stat(file)
			hasFeed := feedsDir != "" && fileErr == nil
			if !hasFeed && (!network || !builtIn) {
				continue
			}
			if p.Policy.Publication != "approved" && p.Policy.Publication != "public_source" {
				continue
			}
			due := true
			for _, x := range s.View().Sources {
				if x.ProviderID == p.ID && x.LastAttempt != nil && time.Since(*x.LastAttempt) < time.Duration(p.Policy.MinRefreshSeconds)*time.Second {
					due = false
				}
			}
			if !due {
				continue
			}
			wg.Add(1)
			go func(p catalog.Provider, file string, hasFeed bool) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				at := time.Now().UTC()
				var offers []catalog.Offer
				var e error
				if hasFeed {
					offers, e = ReadFeed(file, p.ID)
				} else {
					switch p.ID {
					case "onie":
						offers, e = LoadOnie(ctx, client, "https://api.onie.net/v1/public/ip-subnets", at)
					case "peaktera":
						var b []byte
						b, e = fetch(ctx, client, "https://www.peaktera.com/ip-ranges")
						if e == nil {
							offers, e = ParsePeaktera(b, at)
						}
					case "obhost":
						var b []byte
						b, e = fetch(ctx, client, "https://www.obhost.net/ip-subnet-leasing")
						if e == nil {
							offers, e = ParseOBHost(b, at)
						}
					case "prefix-broker":
						var b []byte
						b, e = fetch(ctx, client, "https://www.prefixbroker.com/buy-ipv4/offers/")
						if e == nil {
							offers, e = ParsePrefixBroker(b, at)
						}
					}
				}
				if ctx.Err() != nil {
					return
				}
				if e = s.Apply(p.ID, offers, e, at); e != nil {
					slog.Warn("catalog refresh failed", "provider", p.ID)
				} else {
					slog.Info("catalog refreshed", "provider", p.ID, "offers", len(offers))
				}
			}(p, file, hasFeed)
		}
		wg.Wait()
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			refresh()
		}
	}
}
