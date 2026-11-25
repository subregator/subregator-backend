package history

import (
	"context"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type Association struct {
	ProviderID string    `json:"provider_id"`
	FirstSeen  time.Time `json:"first_observed_at"`
	LastSeen   time.Time `json:"last_observed_at"`
}

func (d *DB) Associations(ctx context.Context, resource string, providers []string) ([]Association, error) {
	out := []Association{}
	if len(providers) == 0 {
		return out, nil
	}
	args := []any{catalog.StableID("net", resource)}
	for _, p := range providers {
		args = append(args, p)
	}
	rows, err := d.sql.QueryContext(ctx, bind(`SELECT provider_id,first_seen,last_seen FROM resource_providers WHERE resource_id=? AND provider_id IN (`+placeholders(len(providers))+`) ORDER BY provider_id`), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Association
		var first, last int64
		if err = rows.Scan(&a.ProviderID, &first, &last); err != nil {
			return out, err
		}
		a.FirstSeen = time.UnixMilli(first).UTC()
		a.LastSeen = time.UnixMilli(last).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

type Poll struct {
	ID         int64     `json:"id"`
	ProviderID string    `json:"provider_id"`
	ObservedAt time.Time `json:"observed_at"`
	Complete   bool      `json:"complete"`
}
type PollResult struct {
	Items       []Poll `json:"items"`
	NextAfterID *int64 `json:"next_after_id"`
}

func (d *DB) MarketPolls(ctx context.Context, resource string, providers []string, after int64, limit int) (PollResult, error) {
	out := PollResult{Items: []Poll{}}
	if len(providers) == 0 {
		return out, nil
	}
	args := []any{after, catalog.StableID("net", resource)}
	for _, p := range providers {
		args = append(args, p)
	}
	args = append(args, limit+1)
	rows, err := d.sql.QueryContext(ctx, bind(`SELECT id,provider_id,observed_at,complete FROM polls WHERE id>? AND provider_id IN (SELECT provider_id FROM resource_providers WHERE resource_id=? AND provider_id IN (`+placeholders(len(providers))+`)) ORDER BY id LIMIT ?`), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Poll
		var at int64
		if err = rows.Scan(&p.ID, &p.ProviderID, &at, &p.Complete); err != nil {
			return out, err
		}
		p.ObservedAt = time.UnixMilli(at).UTC()
		out.Items = append(out.Items, p)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		id := out.Items[limit-1].ID
		out.NextAfterID = &id
	}
	return out, rows.Err()
}
