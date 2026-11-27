package history

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

type TimelineEntry struct {
	ID              string                            `json:"id"`
	Kind            string                            `json:"kind"`
	Event           string                            `json:"event"`
	OrderedAt       time.Time                         `json:"ordered_at"`
	ObservedAt      *time.Time                        `json:"observed_at"`
	SourceUpdatedAt *time.Time                        `json:"source_updated_at"`
	IngestedAt      *time.Time                        `json:"ingested_at"`
	Source          string                            `json:"source"`
	SourceURL       string                            `json:"source_url,omitempty"`
	EvidenceURL     string                            `json:"evidence_url"`
	Scope           intelligence.ObservationScope     `json:"scope"`
	Gap             bool                              `json:"gap"`
	Listing         *Event                            `json:"listing,omitempty"`
	Observation     *intelligence.ArchivedObservation `json:"observation,omitempty"`
}

type TimelineResult struct {
	Items             []TimelineEntry `json:"items"`
	NextCursor        string          `json:"next_cursor,omitempty"`
	TrackingStartedAt *time.Time      `json:"tracking_started_at"`
	ArchiveStartedAt  *time.Time      `json:"archive_started_at"`
	Unavailable       []string        `json:"unavailable"`
	Semantics         string          `json:"semantics"`
}

type timelineCursor struct {
	Resource     string    `json:"r"`
	Policy       string    `json:"p"`
	Time         time.Time `json:"t"`
	Kind         int       `json:"k"`
	ID           int64     `json:"i"`
	Events       int64     `json:"e"`
	Observations int64     `json:"o"`
}

func (d *DB) Timeline(ctx context.Context, resource, cursor string, limit int, providers, checks []string) (TimelineResult, error) {
	out := TimelineResult{Items: []TimelineEntry{}, Unavailable: []string{"abuse", "irr", "spamhaus_zen"}, Semantics: "ordered_by_listing_observation_or_network_ingestion; source_dates_are_not_ingestion_dates; listing_ingestion_and_legacy_import_provenance_unknown; no_history_before_tracking_implied; registry_events_not_ownership_changes"}
	if limit < 1 || limit > 200 {
		return out, errors.New("invalid timeline limit")
	}
	target, err := intelligence.ParseTarget(resource)
	if err != nil || target.Kind != "prefix" || target.Value != resource {
		return out, errors.New("canonical public prefix required")
	}
	sortedProviders, sortedChecks := slices.Clone(providers), slices.Clone(checks)
	slices.Sort(sortedProviders)
	slices.Sort(sortedChecks)
	policyBytes, _ := json.Marshal([][]string{sortedProviders, sortedChecks})
	policy := fmt.Sprintf("%x", sha256.Sum256(policyBytes))
	c := timelineCursor{Resource: resource, Policy: policy, Time: time.Unix(0, 0).UTC()}
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &c) != nil || c.Resource != resource || c.Policy != policy || c.Time.IsZero() || c.Kind < 0 || c.Kind > 1 || c.ID < 0 || c.Events < 0 || c.Observations < 0 {
			return out, errors.New("invalid timeline cursor")
		}
	}
	allowed, err := d.PublicObservationResource(ctx, resource, providers)
	if err != nil || !allowed {
		return out, err
	}
	if cursor == "" {
		if err = d.sql.QueryRowContext(ctx, `SELECT COALESCE((SELECT MAX(id) FROM events),0),COALESCE((SELECT MAX(id) FROM check_observations),0)`).Scan(&c.Events, &c.Observations); err != nil {
			return out, err
		}
	}
	var began int64
	if err = d.sql.QueryRowContext(ctx, `SELECT tracking_started FROM state WHERE id=1`).Scan(&began); err != nil {
		return out, err
	}
	start := time.UnixMilli(began).UTC()
	out.TrackingStartedAt = &start
	args := []any{catalog.StableID("net", resource), resource, c.Events, c.Observations, c.Time, c.Kind, c.ID, limit + 1}
	placeholdersFor := func(values []string) string {
		if len(values) == 0 {
			return "NULL"
		}
		slots := make([]string, len(values))
		for i, v := range values {
			args = append(args, v)
			slots[i] = fmt.Sprintf("$%d", len(args))
		}
		return strings.Join(slots, ",")
	}
	ps := placeholdersFor(providers)
	cs := placeholdersFor(checks)
	query := `SELECT kind,id,at,payload FROM (
 SELECT 0 AS kind,e.id,to_timestamp(e.observed_at/1000.0) AS at,jsonb_build_object('id',e.id,'listing_id',e.listing_id,'provider_id',e.provider_id,'resource_id',e.resource_id,'next_resource_id',e.next_resource_id,'type',e.type,'observed_at',to_timestamp(e.observed_at/1000.0),'resource_reappeared',e.resource_reappeared,'before',convert_from(e.before,'UTF8')::jsonb,'after',convert_from(e.after,'UTF8')::jsonb,'changed_fields',convert_from(e.changed_fields,'UTF8')::jsonb)::text AS payload
 FROM events e WHERE e.id<=$3 AND (e.resource_id=$1 OR e.next_resource_id=$1) AND e.provider_id IN (` + ps + `)
 UNION ALL SELECT 1,id,ingested_at,convert_from(payload,'UTF8') FROM check_observations WHERE resource=$2 AND id<=$4 AND check_name IN (` + cs + `)
 ) t WHERE (at,kind,id)>($5,$6,$7) ORDER BY at,kind,id LIMIT $8`
	rows, err := d.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var last timelineCursor
	for rows.Next() {
		var kind int
		var id int64
		var at time.Time
		var payload []byte
		if err = rows.Scan(&kind, &id, &at, &payload); err != nil {
			return out, err
		}
		if len(out.Items) == limit {
			raw, _ := json.Marshal(last)
			out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
			break
		}
		entry := TimelineEntry{OrderedAt: at, Scope: intelligence.ObservationScope{Requested: resource, Resource: resource, Kind: "prefix", Relation: "exact"}}
		if kind == 0 {
			var e Event
			if err = json.Unmarshal(payload, &e); err != nil {
				return out, err
			}
			entry.Listing = &e
			entry.Kind = "listing"
			entry.ID = "listing:" + strconv.FormatInt(id, 10)
			entry.Event = e.Type
			entry.ObservedAt = &e.ObservedAt
			entry.Source = e.ProviderID
			offer := e.After
			if offer == nil {
				offer = e.Before
			}
			if offer != nil {
				entry.SourceURL = offer.URL
				entry.SourceUpdatedAt = offer.SourceUpdatedAt
			}
			entry.EvidenceURL = "/api/v1/history?listing_id=" + url.QueryEscape(e.ListingID) + "&after_id=" + strconv.FormatInt(max(0, id-1), 10) + "&limit=1"
		} else {
			var o intelligence.ArchivedObservation
			if err = json.Unmarshal(payload, &o); err != nil {
				return out, err
			}
			o.ID = id
			entry.Observation = &o
			entry.Kind = "network"
			entry.ID = "network:" + strconv.FormatInt(id, 10)
			entry.Event = o.Event
			entry.ObservedAt = o.ObservedAt
			entry.SourceUpdatedAt = o.SourceUpdatedAt
			entry.IngestedAt = &o.IngestedAt
			entry.Source = o.Source
			entry.SourceURL = o.SourceURL
			entry.Scope = o.Observation.Scope
			entry.Gap = o.Gap
			entry.EvidenceURL = "/api/v1/network/history?resource=" + url.QueryEscape(resource) + "&after_id=" + strconv.FormatInt(max(0, id-1), 10) + "&limit=1"
		}
		out.Items = append(out.Items, entry)
		last = c
		last.Time = at
		last.Kind = kind
		last.ID = id
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	if len(checks) > 0 {
		boundaryArgs := []any{resource, c.Observations}
		slots := make([]string, len(checks))
		for i, check := range checks {
			boundaryArgs = append(boundaryArgs, check)
			slots[i] = fmt.Sprintf("$%d", len(boundaryArgs))
		}
		if err = d.sql.QueryRowContext(ctx, `SELECT MIN(ingested_at) FROM check_observations WHERE resource=$1 AND id<=$2 AND check_name IN (`+strings.Join(slots, ",")+`)`, boundaryArgs...).Scan(&out.ArchiveStartedAt); err != nil {
			return out, err
		}
	}
	return out, nil
}
