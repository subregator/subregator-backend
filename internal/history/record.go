package history

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func ResourceID(o catalog.Offer) string {
	if o.Resource.Prefix == nil {
		return catalog.StableID("masked", o.ID)
	}
	return catalog.StableID("net", *o.Resource.Prefix)
}
func networkRange(prefix string) ([]byte, []byte) {
	p, _ := netip.ParsePrefix(prefix)
	start := p.Addr().As16()
	end := start
	offset := 0
	if p.Addr().Is4() {
		offset = 96
	}
	for bit := p.Bits() + offset; bit < 128; bit++ {
		end[bit/8] |= 1 << uint(7-bit%8)
	}
	return start[:], end[:]
}
func hashOffer(o catalog.Offer) string {
	o.ObservedAt = time.Time{}
	o.SourceUpdatedAt = nil
	o.Quotes = append([]catalog.Quote{}, o.Quotes...)
	sort.Slice(o.Quotes, func(i, j int) bool { return o.Quotes[i].ID < o.Quotes[j].ID })
	b, _ := json.Marshal(o)
	return catalog.StableID("content", string(b))
}
func changedFields(before, after catalog.Offer) []string {
	var a, b map[string]json.RawMessage
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	json.Unmarshal(x, &a)
	json.Unmarshal(y, &b)
	fields := []string{}
	for _, k := range []string{"resource", "model", "availability", "available_at", "geography", "routing", "quotes", "terms", "url"} {
		if !bytes.Equal(a[k], b[k]) {
			fields = append(fields, k)
		}
	}
	return fields
}
func (d *DB) Save(state catalog.State, provider string, at time.Time, complete bool) error {
	var tx *sql.Tx
	var e error
	if d.writer != nil {
		tx, e = d.writer.BeginTx(context.Background(), nil)
	} else {
		tx, e = d.sql.Begin()
	}
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("SELECT pg_advisory_xact_lock($1,hashtext(current_schema()))", transactionLock); e != nil {
		return e
	}
	payload, e := json.Marshal(state)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO state(id,payload,tracking_started) VALUES(1,$1,$2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload`, payload, at.UnixMilli()); e != nil {
		return e
	}
	if provider != "" {
		count := 0
		for _, s := range state.Sources {
			if s.ProviderID == provider {
				count = s.Count
			}
		}
		if _, e = tx.Exec("INSERT INTO polls(provider_id,observed_at,complete,count) VALUES($1,$2,$3,$4)", provider, at.UnixMilli(), complete, count); e != nil {
			return e
		}
	}
	if complete {
		seen := map[string]bool{}
		priorPresence := map[string]bool{}
		knownResources := map[string]bool{}
		knownChecked := map[string]bool{}
		query := "SELECT provider_id,resource_id FROM listings WHERE active=TRUE"
		args := []any{}
		if provider != "" {
			query += " AND provider_id=?"
			args = append(args, provider)
		}
		priorRows, err := tx.Query(bind(query), args...)
		if err != nil {
			return err
		}
		for priorRows.Next() {
			var p, r string
			if err = priorRows.Scan(&p, &r); err != nil {
				priorRows.Close()
				return err
			}
			priorPresence[p+"\x00"+r] = true
		}
		err = priorRows.Err()
		priorRows.Close()
		if err != nil {
			return err
		}
		for _, o := range state.Offers {
			if provider != "" && o.ProviderID != provider {
				continue
			}
			seen[o.ID] = true
			resource := ResourceID(o)
			key := o.ProviderID + "\x00" + resource
			if !knownChecked[key] {
				var count int
				if e = tx.QueryRow("SELECT COUNT(*) FROM resource_providers WHERE resource_id=$1 AND provider_id=$2", resource, o.ProviderID).Scan(&count); e != nil {
					return e
				}
				knownResources[key] = count > 0
				knownChecked[key] = true
			}
			reappeared := provider != "" && o.Resource.Prefix != nil && knownResources[key] && !priorPresence[key]
			if e = recordOffer(tx, o, at, provider == "", reappeared); e != nil {
				return e
			}
		}
		if provider != "" {
			rows, e := tx.Query("SELECT id,payload,resource_id FROM listings WHERE provider_id=$1 AND active=TRUE", provider)
			if e != nil {
				return e
			}
			type removed struct {
				id       string
				payload  []byte
				resource string
			}
			missing := []removed{}
			for rows.Next() {
				var r removed
				if e = rows.Scan(&r.id, &r.payload, &r.resource); e != nil {
					rows.Close()
					return e
				}
				if !seen[r.id] {
					missing = append(missing, r)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, r := range missing {
				if _, e = tx.Exec("UPDATE listings SET active=FALSE,removed_at=$1 WHERE id=$2", at.UnixMilli(), r.id); e != nil {
					return e
				}
				if _, e = tx.Exec(`INSERT INTO events(listing_id,provider_id,resource_id,next_resource_id,type,observed_at,before,changed_fields) VALUES($1,$2,$3,$4,'removed',$5,$6, '[]')`, r.id, provider, r.resource, r.resource, at.UnixMilli(), r.payload); e != nil {
					return e
				}
			}
		}
	}
	return tx.Commit()
}
func recordOffer(tx *sql.Tx, o catalog.Offer, at time.Time, baseline bool, reappeared bool) error {
	resource := ResourceID(o)
	var start, end []byte
	var prefix any
	if o.Resource.Prefix != nil {
		prefix = *o.Resource.Prefix
		start, end = networkRange(*o.Resource.Prefix)
	}
	if _, e := tx.Exec(`INSERT INTO resources(id,prefix,family,prefix_length,address_count,start,"end") VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING`, resource, prefix, o.Resource.Family, o.Resource.PrefixLength, o.Resource.AddressCount, start, end); e != nil {
		return e
	}
	if _, e := tx.Exec(`INSERT INTO resource_providers(resource_id,provider_id,first_seen,last_seen) VALUES($1,$2,$3,$4) ON CONFLICT(resource_id,provider_id) DO UPDATE SET last_seen=GREATEST(resource_providers.last_seen,excluded.last_seen)`, resource, o.ProviderID, at.UnixMilli(), at.UnixMilli()); e != nil {
		return e
	}
	var previous []byte
	var previousHash, oldResource string
	var active bool
	var appearances int
	e := tx.QueryRow("SELECT payload,hash,resource_id,active,appearances FROM listings WHERE id=$1", o.ID).Scan(&previous, &previousHash, &oldResource, &active, &appearances)
	exists := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	next, e := json.Marshal(o)
	if e != nil {
		return e
	}
	hash := hashOffer(o)
	kind := ""
	fields := []string{}
	if !exists {
		kind = "listed"
		if baseline {
			kind = "baseline"
		}
		appearances = 1
		oldResource = resource
	} else if !active {
		kind = "relisted"
		appearances++
	} else if previousHash != hash {
		kind = "changed"
	}
	if exists {
		var before catalog.Offer
		if e = json.Unmarshal(previous, &before); e != nil {
			return e
		}
		fields = changedFields(before, o)
		if oldResource != resource {
			kind = "resource_changed"
		}
	}
	if _, e = tx.Exec(`INSERT INTO listings(id,provider_id,resource_id,first_seen,last_seen,appearances,active,payload,hash) VALUES($1,$2,$3,$4,$5,$6,TRUE,$7,$8) ON CONFLICT(id) DO UPDATE SET resource_id=excluded.resource_id,last_seen=GREATEST(listings.last_seen,excluded.last_seen),removed_at=NULL,appearances=excluded.appearances,active=TRUE,payload=excluded.payload,hash=excluded.hash`, o.ID, o.ProviderID, resource, at.UnixMilli(), at.UnixMilli(), appearances, next, hash); e != nil {
		return e
	}
	if kind != "" {
		changed, _ := json.Marshal(fields)
		if _, e = tx.Exec(`INSERT INTO events(listing_id,provider_id,resource_id,next_resource_id,type,observed_at,resource_reappeared,before,after,changed_fields) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, o.ID, o.ProviderID, oldResource, resource, kind, at.UnixMilli(), reappeared, previous, next, changed); e != nil {
			return e
		}
	}
	return nil
}
