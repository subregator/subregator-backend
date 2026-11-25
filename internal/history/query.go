package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type Query struct {
	Providers  []string
	ListingID  string
	Resource   string
	ResourceID string
	Type       string
	Since      *time.Time
	Until      *time.Time
	AfterID    int64
	Limit      int
}
type Event struct {
	ResourceReappeared bool           `json:"resource_reappeared"`
	ID                 int64          `json:"id"`
	ListingID          string         `json:"listing_id"`
	ProviderID         string         `json:"provider_id"`
	ResourceID         string         `json:"resource_id"`
	NextResourceID     string         `json:"next_resource_id"`
	Type               string         `json:"type"`
	ObservedAt         time.Time      `json:"observed_at"`
	Before             *catalog.Offer `json:"before"`
	After              *catalog.Offer `json:"after"`
	ChangedFields      []string       `json:"changed_fields"`
}
type EventResult struct {
	Items             []Event   `json:"items"`
	NextAfterID       *int64    `json:"next_after_id"`
	TrackingStartedAt time.Time `json:"tracking_started_at"`
	Semantics         string    `json:"semantics"`
}
type Listing struct {
	ID          string        `json:"id"`
	ProviderID  string        `json:"provider_id"`
	ResourceID  string        `json:"resource_id"`
	FirstSeen   time.Time     `json:"first_observed_at"`
	LastSeen    time.Time     `json:"last_observed_at"`
	RemovedAt   *time.Time    `json:"removed_at"`
	Appearances int           `json:"appearances"`
	Active      bool          `json:"active"`
	Offer       catalog.Offer `json:"last_offer"`
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }
func resourceFilter(resource string) (string, []any) {
	if p, e := netip.ParsePrefix(resource); e == nil {
		return "r.id=?", []any{catalog.StableID("net", p.Masked().String())}
	}
	ip, err := netip.ParseAddr(resource)
	if err != nil {
		return "FALSE", nil
	}
	ip = ip.Unmap()
	return "r.prefix >>= ?::inet", []any{ip.String()}
}
func (d *DB) Events(ctx context.Context, q Query) (EventResult, error) {
	out := EventResult{Items: []Event{}, Semantics: "provider_listing_observations"}
	var began int64
	if e := d.sql.QueryRowContext(ctx, "SELECT tracking_started FROM state WHERE id=1").Scan(&began); e != nil {
		return out, e
	}
	out.TrackingStartedAt = time.UnixMilli(began).UTC()
	if len(q.Providers) == 0 {
		return out, nil
	}
	args := []any{q.AfterID}
	where := "e.id>? AND e.provider_id IN (" + placeholders(len(q.Providers)) + ")"
	for _, p := range q.Providers {
		args = append(args, p)
	}
	for _, filter := range []struct {
		value  string
		column string
	}{{q.ListingID, "e.listing_id"}, {q.Type, "e.type"}} {
		if filter.value != "" {
			where += " AND " + filter.column + "=?"
			args = append(args, filter.value)
		}
	}
	if q.ResourceID != "" {
		where += " AND (e.resource_id=? OR e.next_resource_id=?)"
		args = append(args, q.ResourceID, q.ResourceID)
	}
	if q.Since != nil {
		where += " AND e.observed_at>=?"
		args = append(args, q.Since.UnixMilli())
	}
	if q.Until != nil {
		where += " AND e.observed_at<=?"
		args = append(args, q.Until.UnixMilli())
	}
	selectEvents := "SELECT e.id,e.listing_id,e.provider_id,e.resource_id,e.next_resource_id,e.type,e.observed_at,e.resource_reappeared,e.before,e.after,e.changed_fields FROM events e"
	statement := selectEvents + " WHERE " + where + " ORDER BY e.id LIMIT ?"
	if q.Resource != "" {
		condition, values := resourceFilter(q.Resource)
		left := "e.resource_id IN (SELECT r.id FROM resources r WHERE " + condition + ")"
		right := "e.next_resource_id IN (SELECT r.id FROM resources r WHERE " + condition + ")"
		if prefix, err := netip.ParsePrefix(q.Resource); err == nil {
			values = []any{catalog.StableID("net", prefix.Masked().String())}
			left, right = "e.resource_id=?", "e.next_resource_id=?"
		}
		statement = "(" + selectEvents + " WHERE " + where + " AND " + left + " ORDER BY e.id LIMIT ?) UNION (" + selectEvents + " WHERE " + where + " AND " + right + " ORDER BY e.id LIMIT ?) ORDER BY id LIMIT ?"
		shared := append([]any(nil), args...)
		args = append(args, values...)
		args = append(args, q.Limit+1)
		args = append(args, shared...)
		args = append(args, values...)
		args = append(args, q.Limit+1)
	}
	args = append(args, q.Limit+1)
	rows, e := d.sql.QueryContext(ctx, bind(statement), args...)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var event Event
		var at int64
		var before, after, fields []byte
		if e = rows.Scan(&event.ID, &event.ListingID, &event.ProviderID, &event.ResourceID, &event.NextResourceID, &event.Type, &at, &event.ResourceReappeared, &before, &after, &fields); e != nil {
			return out, e
		}
		event.ObservedAt = time.UnixMilli(at).UTC()
		if len(before) > 0 {
			if e = json.Unmarshal(before, &event.Before); e != nil {
				return out, e
			}
		}
		if len(after) > 0 {
			if e = json.Unmarshal(after, &event.After); e != nil {
				return out, e
			}
		}
		if e = json.Unmarshal(fields, &event.ChangedFields); e != nil {
			return out, e
		}
		out.Items = append(out.Items, event)
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		id := out.Items[len(out.Items)-1].ID
		out.NextAfterID = &id
	}
	return out, rows.Err()
}
func (d *DB) Listing(ctx context.Context, id string) (Listing, error) {
	var out Listing
	var first, last int64
	var removed sql.NullInt64
	var payload []byte
	e := d.sql.QueryRowContext(ctx, "SELECT id,provider_id,resource_id,first_seen,last_seen,removed_at,appearances,active,payload FROM listings WHERE id=$1", id).Scan(&out.ID, &out.ProviderID, &out.ResourceID, &first, &last, &removed, &out.Appearances, &out.Active, &payload)
	if e != nil {
		return out, e
	}
	out.FirstSeen = time.UnixMilli(first).UTC()
	out.LastSeen = time.UnixMilli(last).UTC()
	if removed.Valid {
		t := time.UnixMilli(removed.Int64).UTC()
		out.RemovedAt = &t
	}
	e = json.Unmarshal(payload, &out.Offer)
	return out, e
}

type Resource struct {
	ID           string    `json:"id"`
	Prefix       string    `json:"prefix"`
	Family       int       `json:"family"`
	PrefixLength int       `json:"prefix_length"`
	AddressCount string    `json:"address_count"`
	FirstSeen    time.Time `json:"first_observed_at"`
	LastSeen     time.Time `json:"last_observed_at"`
	ProviderIDs  []string  `json:"provider_ids"`
	ActiveOffers int       `json:"active_offers"`
}
type ResourceQuery struct {
	Providers []string
	Resource  string
	AfterID   string
	Limit     int
}
type ResourceResult struct {
	Items       []Resource `json:"items"`
	NextAfterID *string    `json:"next_after_id"`
	Correlation string     `json:"correlation"`
}

func (d *DB) Resources(ctx context.Context, q ResourceQuery) (ResourceResult, error) {
	out := ResourceResult{Items: []Resource{}, Correlation: "exact_public_prefix_only"}
	if len(q.Providers) == 0 {
		return out, nil
	}
	where := "r.prefix IS NOT NULL AND r.id>? AND p.provider_id IN (" + placeholders(len(q.Providers)) + ")"
	args := []any{q.AfterID}
	for _, p := range q.Providers {
		args = append(args, p)
	}
	if q.Resource != "" {
		condition, values := resourceFilter(q.Resource)
		where += " AND " + condition
		args = append(args, values...)
	}
	args = append(args, q.Limit+1)
	rows, e := d.sql.QueryContext(ctx, bind(`SELECT r.id,r.prefix::text,r.family,r.prefix_length,r.address_count,MIN(p.first_seen),MAX(p.last_seen),STRING_AGG(p.provider_id,',') FROM resources r JOIN resource_providers p ON p.resource_id=r.id WHERE `+where+` GROUP BY r.id ORDER BY r.id LIMIT ?`), args...)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var r Resource
		var first, last int64
		var providers string
		if e = rows.Scan(&r.ID, &r.Prefix, &r.Family, &r.PrefixLength, &r.AddressCount, &first, &last, &providers); e != nil {
			return out, e
		}
		r.FirstSeen = time.UnixMilli(first).UTC()
		r.LastSeen = time.UnixMilli(last).UTC()
		r.ProviderIDs = strings.Split(providers, ",")
		sort.Strings(r.ProviderIDs)
		out.Items = append(out.Items, r)
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		id := out.Items[len(out.Items)-1].ID
		out.NextAfterID = &id
	}
	return out, rows.Err()
}
