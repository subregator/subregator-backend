package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/subregator/subregator-backend/internal/intelligence"
)

const observationSchema = `
 CREATE TABLE IF NOT EXISTS check_observations (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 identity TEXT NOT NULL UNIQUE,
 resource TEXT NOT NULL, check_name TEXT NOT NULL, source TEXT NOT NULL,
 collected_at TIMESTAMPTZ NOT NULL, ingested_at TIMESTAMPTZ NOT NULL,
 comparable BOOLEAN NOT NULL, scope BYTEA NOT NULL, state BYTEA NOT NULL, payload BYTEA NOT NULL);
 CREATE INDEX IF NOT EXISTS check_observation_history ON check_observations(resource, id);
 CREATE INDEX IF NOT EXISTS check_observation_sequence ON check_observations(resource, check_name, source, collected_at DESC, id DESC);
 CREATE INDEX IF NOT EXISTS check_observation_baseline ON check_observations(resource,check_name,source,scope,collected_at DESC,id DESC) WHERE comparable;
 INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING;`

func (d *DB) SaveObservation(ctx context.Context, r intelligence.ArchivedObservation) error {
	if r.Resource == "" || r.Source == "" || r.IngestedAt.IsZero() || !json.Valid(r.Evidence) || !json.Valid(r.State) || len(r.Evidence) > 64<<10 || len(r.State) > 64<<10 {
		return errors.New("invalid archived observation")
	}
	switch r.Check {
	case "prefix_overview", "rpki", "registration", "rdap", "spamhaus_drop":
	default:
		return errors.New("source history not approved")
	}
	if target, err := intelligence.ParseTarget(r.Resource); err != nil || target.Kind != "prefix" || target.Value != r.Resource {
		return errors.New("canonical prefix required")
	}
	collected := r.IngestedAt
	if r.ObservedAt != nil && r.Observation.CollectionStatus == "succeeded" && r.Observation.Freshness == "fresh" {
		collected = *r.ObservedAt
	}
	if collected.After(r.IngestedAt.Add(time.Minute)) {
		return errors.New("future observation")
	}
	r.Comparable = r.Comparable && r.ObservedAt != nil && r.ExpiresAt != nil && r.IngestedAt.Before(*r.ExpiresAt) && !r.ObservedAt.After(*r.ExpiresAt) && r.Observation.CollectionStatus == "succeeded" && r.Observation.Freshness == "fresh" && r.Observation.Completeness == "complete" && r.Observation.Scope.Resource != "" && r.Observation.Scope.Relation != "unknown"
	scope, _ := json.Marshal(r.Observation.Scope)
	identity, err := json.Marshal(struct {
		Resource, Check, Source string
		Collected               time.Time
		SourceUpdated           *time.Time
		Observation             intelligence.Observation
		Evidence                json.RawMessage
	}{r.Resource, r.Check, r.Source, collected, r.SourceUpdatedAt, r.Observation, r.Evidence})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(identity)
	r.Identity = hex.EncodeToString(sum[:])
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1,hashtext(current_schema()))", transactionLock+2); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM check_observations WHERE identity=$1)", r.Identity).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return tx.Commit()
	}
	r.FirstSeen = r.ObservedAt
	r.LastSeen = r.ObservedAt
	r.Event = "observation"
	var previousPayload, previousScope []byte
	var previousTime time.Time
	var previousComparable bool
	err = tx.QueryRowContext(ctx, `SELECT payload,scope,collected_at,comparable FROM check_observations WHERE resource=$1 AND check_name=$2 AND source=$3 ORDER BY collected_at DESC,id DESC LIMIT 1`, r.Resource, r.Check, r.Source).Scan(&previousPayload, &previousScope, &previousTime, &previousComparable)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		var previous intelligence.ArchivedObservation
		if err = json.Unmarshal(previousPayload, &previous); err != nil {
			return err
		}
		r.Gap = !bytes.Equal(scope, previousScope) || !previousComparable || !r.Comparable || previous.ExpiresAt == nil || !collected.Before(*previous.ExpiresAt)
		if !collected.After(previousTime) {
			r.Event = "out_of_order"
			r.Comparable = false
			r.Gap = true
		} else if r.Comparable {
			var baselinePayload, baselineState []byte
			err = tx.QueryRowContext(ctx, `SELECT payload,state FROM check_observations WHERE resource=$1 AND check_name=$2 AND source=$3 AND comparable AND scope=$4 ORDER BY collected_at DESC,id DESC LIMIT 1`, r.Resource, r.Check, r.Source, scope).Scan(&baselinePayload, &baselineState)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if errors.Is(err, sql.ErrNoRows) {
				r.Gap = true
			}
			if err == nil {
				var baseline intelligence.ArchivedObservation
				if err = json.Unmarshal(baselinePayload, &baseline); err != nil {
					return err
				}
				r.PreviousSeen = baseline.ObservedAt
				if bytes.Equal(r.State, baselineState) {
					r.FirstSeen = baseline.FirstSeen
				} else {
					switch r.Check {
					case "prefix_overview":
						r.Event = "bgp_origins_changed"
					case "rpki":
						r.Event = "rpki_transition"
					case "registration", "rdap":
						r.Event = "registry_changed"
					case "spamhaus_drop":
						if string(r.State) == `"not_listed"` {
							r.Event = "delisted"
						} else if string(r.State) == `"listed"` {
							r.Event = "listed"
						}
					}
				}
			}
		}
	} else {
		r.Gap = true
	}
	if !r.Comparable && r.Event != "out_of_order" {
		r.Event = "gap"
		r.Gap = true
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO check_observations(identity,resource,check_name,source,collected_at,ingested_at,comparable,scope,state,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.Identity, r.Resource, r.Check, r.Source, collected, r.IngestedAt, r.Comparable, scope, []byte(r.State), payload)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type ObservationResult struct {
	Items      []intelligence.ArchivedObservation `json:"items"`
	NextCursor int64                              `json:"next_cursor,omitempty"`
	Semantics  string                             `json:"semantics"`
}

func (d *DB) Observations(ctx context.Context, resource string, after int64, limit int, checks ...string) (ObservationResult, error) {
	out := ObservationResult{Items: []intelligence.ArchivedObservation{}, Semantics: "poll_bounds_not_exact_event_dates; registry_changes_not_ownership_or_tenant_changes"}
	if limit < 1 || limit > 200 || after < 0 || resource == "" {
		return out, errors.New("invalid observation query")
	}
	args := []any{resource, after, limit + 1}
	query := `SELECT id,payload FROM check_observations WHERE resource=$1 AND id>$2`
	if len(checks) > 0 {
		query += " AND check_name IN ("
		for i, check := range checks {
			if i > 0 {
				query += ","
			}
			query += fmt.Sprintf("$%d", i+4)
			args = append(args, check)
		}
		query += ")"
	}
	rows, err := d.sql.QueryContext(ctx, query+` ORDER BY id LIMIT $3`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var payload []byte
		if err = rows.Scan(&id, &payload); err != nil {
			return out, err
		}
		if len(out.Items) == limit {
			out.NextCursor = out.Items[len(out.Items)-1].ID
			break
		}
		var r intelligence.ArchivedObservation
		if err = json.Unmarshal(payload, &r); err != nil {
			return out, err
		}
		r.ID = id
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}

func (d *DB) PublicObservationResource(ctx context.Context, resource string, providers []string) (bool, error) {
	if _, err := netip.ParsePrefix(resource); err != nil {
		return false, err
	}
	if len(providers) == 0 {
		return false, nil
	}
	args := []any{resource}
	for _, p := range providers {
		args = append(args, p)
	}
	var found bool
	err := d.sql.QueryRowContext(ctx, bind(`SELECT EXISTS(SELECT 1 FROM resources r JOIN resource_providers p ON r.id=p.resource_id WHERE r.prefix=?::cidr AND p.provider_id IN (`+placeholders(len(providers))+`))`), args...).Scan(&found)
	return found, err
}
