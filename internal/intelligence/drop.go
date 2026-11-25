package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

type DropMatch struct {
	Prefix    string `json:"prefix"`
	Reference string `json:"reference"`
}
type dropFeed struct {
	Records     []DropMatch `json:"records"`
	Updated     time.Time   `json:"updated"`
	Fetched     time.Time   `json:"fetched"`
	Next        time.Time   `json:"next"`
	Copyright   string      `json:"copyright"`
	Failed      bool        `json:"failed"`
	loaded      bool
	pendingSave bool
	retrySave   time.Time
}

func parseDrop(b []byte, ipv4 bool, now time.Time) (dropFeed, error) {
	bad := errors.New("invalid or incomplete DROP dataset")
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 4096), 1<<20)
	feed := dropFeed{}
	metadata := false
	for scan.Scan() {
		if len(bytes.TrimSpace(scan.Bytes())) == 0 {
			continue
		}
		if metadata {
			return feed, bad
		}
		var row struct {
			CIDR      string `json:"cidr"`
			ID        string `json:"sblid"`
			Type      string `json:"type"`
			Timestamp int64  `json:"timestamp"`
			Copyright string `json:"copyright"`
			Records   *int   `json:"records"`
		}
		if json.Unmarshal(scan.Bytes(), &row) != nil {
			return feed, bad
		}
		if row.Type == "metadata" {
			if row.Timestamp <= 0 || row.Copyright == "" || row.Records == nil || *row.Records != len(feed.Records) {
				return feed, bad
			}
			feed.Updated = time.Unix(row.Timestamp, 0).UTC()
			feed.Copyright = row.Copyright
			if feed.Updated.After(now.Add(5 * time.Minute)) {
				return feed, bad
			}
			metadata = true
			continue
		}
		p, e := netip.ParsePrefix(row.CIDR)
		if e != nil || p != p.Masked() || p.Addr().Is4() != ipv4 || p.Addr().Is4In6() || row.ID == "" {
			return feed, bad
		}
		feed.Records = append(feed.Records, DropMatch{row.CIDR, row.ID})
	}
	if scan.Err() != nil || !metadata || len(feed.Records) == 0 {
		return feed, bad
	}
	return feed, nil
}
func (f *dropFeed) check(ctx context.Context, s *Service, prefix netip.Prefix, now time.Time) Check {
	family := "v6"
	if prefix.Addr().Is4() {
		family = "v4"
	}
	key := "drop:" + family
	source := "https://www.spamhaus.org/drop/drop_" + family + ".json"
	c := Check{Status: "unavailable", Freshness: "unknown", Source: "The Spamhaus Project · DROP IPv" + family[1:], SourceURL: source, Coverage: "Any overlapping address in DROP only; not SBL/XBL/PBL or every blocklist", Reason: "No complete current DROP dataset"}
	if !f.loaded {
		if s.cache != nil {
			b, _, found, e := s.cache.CacheGet(ctx, key)
			if e != nil {
				c.Reason = "Stored DROP schedule unavailable; refresh deferred"
				return c
			}
			if found {
				var stored dropFeed
				if json.Unmarshal(b, &stored) != nil || stored.Next.IsZero() {
					c.Reason = "Stored DROP schedule invalid; refresh deferred"
					return c
				}
				*f = stored
			}
		}

		f.loaded = true
	}

	persist := func() error {
		if s.cache == nil {
			return nil
		}
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return s.cache.CachePut(ctx, key, b, f.Next)
	}
	if f.pendingSave && !now.Before(f.retrySave) {
		f.pendingSave = persist() != nil
		f.retrySave = now.Add(time.Minute)
	}

	if s.network && !f.pendingSave && !now.Before(f.Next) {
		release, err := s.acquireRequest(ctx)
		if err != nil {
			f.Next = now.Add(time.Minute)
		} else {
			defer release()
			f.Next = now.Add(24 * time.Hour)
			f.Failed = true
			// Reserve durably before downloading; a database failure permits a short retry without a download.
			if persist() != nil {
				f.Next = now.Add(time.Minute)
			} else {
				b, e := s.readSource(ctx, source, "", 4<<20, false)
				if e == nil {
					if fresh, e := parseDrop(b, prefix.Addr().Is4(), now); e == nil {
						fresh.Fetched = now
						fresh.Next = f.Next
						fresh.loaded = true
						*f = fresh
					}
				}
				if persist() != nil {
					f.pendingSave = true
					f.retrySave = now.Add(time.Minute)
				}
			}
		}
	}

	if len(f.Records) == 0 {
		return c
	}
	expires := minTime(f.Fetched.Add(24*time.Hour), f.Updated.Add(26*time.Hour))
	observed, updated := f.Fetched, f.Updated
	c.ObservedAt = &observed
	c.SourceUpdatedAt = &updated
	c.ExpiresAt = &expires
	c.Copyright = f.Copyright
	c.Freshness = "stale"
	if !f.Failed && !f.pendingSave && !now.Before(f.Fetched.Add(-time.Minute)) && now.Before(expires) {
		c.Freshness = "fresh"
	}
	c.Status = "not_listed"
	c.Reason = "No overlap in the complete checked DROP dataset"
	for _, r := range f.Records {
		if p, e := netip.ParsePrefix(r.Prefix); e == nil && p.Overlaps(prefix) {
			c.Matches = append(c.Matches, r)
		}
	}
	if len(c.Matches) > 0 {
		c.Status = "listed"
		c.Reason = "An overlapping range is listed in DROP"
	}
	return c
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
