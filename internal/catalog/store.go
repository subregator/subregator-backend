package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Source struct {
	ProviderID  string     `json:"provider_id"`
	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	Error       string     `json:"error,omitempty"`
	Count       int        `json:"count"`
	Complete    bool       `json:"complete"`
}
type State struct {
	Version int      `json:"version"`
	Offers  []Offer  `json:"offers"`
	Sources []Source `json:"sources"`
}
type View struct {
	Offers     []Offer
	Providers  []Provider
	Sources    []Source
	ByID       map[string]int
	Generation string
}
type Store struct {
	mu          sync.Mutex
	view        atomic.Pointer[View]
	path        string
	providers   []Provider
	persistence Persistence
}

func NewStore(path string, providers []Provider) (*Store, error) {
	s := &Store{path: path, providers: providers}
	state := State{Version: 1, Offers: []Offer{}, Sources: []Source{}}
	for _, p := range providers {
		if p.ID == "prefix-broker" && (p.Policy.PrefixVisibility != "hidden" || p.Policy.MinRefreshSeconds < 86400) {
			return nil, errors.New("Prefix Broker requires hidden prefixes and at least daily refresh interval")
		}
		if !ValidToken(p.ID) || !WebURL(p.URL) || p.Policy.MinRefreshSeconds < 60 || p.Policy.MinRefreshSeconds > 30*86400 || !contains(p.Policy.Publication, "pending", "approved", "public_source") || !contains(p.Policy.PrefixVisibility, "full", "hidden") {
			return nil, errors.New("invalid provider configuration")
		}
	}
	seen := map[string]bool{}
	for _, p := range providers {
		if seen[p.ID] {
			return nil, errors.New("duplicate provider")
		}
		seen[p.ID] = true
	}
	if path != "" {
		b, e := os.ReadFile(path)
		if e == nil {
			if e = json.Unmarshal(b, &state); e != nil {
				return nil, fmt.Errorf("read snapshot: %w", e)
			}
			if state.Version != 1 {
				return nil, errors.New("unsupported snapshot version")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	if e := s.restore(state); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Store) restore(state State) error {
	if state.Version != 1 {
		return errors.New("unsupported snapshot version")
	}
	normalized := make([]Offer, 0, len(state.Offers))
	ids := map[string]bool{}
	for _, o := range state.Offers {
		p, ok := s.Provider(o.ProviderID)
		if !ok {
			return errors.New("unknown provider in snapshot")
		}
		// Hidden snapshots already contain opaque external IDs; preserve them on reload.
		policy := p.Policy.PrefixVisibility
		p.Policy.PrefixVisibility = "full"
		n, e := Normalize(o, p, time.Now())
		if e != nil {
			return e
		}
		if policy == "hidden" && n.Resource.Prefix != nil {
			return errors.New("hidden prefix in persisted snapshot")
		}
		if ids[n.ID] {
			return errors.New("duplicate offer in snapshot")
		}
		ids[n.ID] = true
		normalized = append(normalized, n)
	}
	state.Offers = normalized
	s.publish(state)
	return nil
}
func (s *Store) Provider(id string) (Provider, bool) {
	for _, p := range s.providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}
func (s *Store) View() *View { return s.view.Load() }
func (s *Store) publish(state State) {
	sort.Slice(state.Offers, func(i, j int) bool { return state.Offers[i].ID < state.Offers[j].ID })
	sort.Slice(state.Sources, func(i, j int) bool { return state.Sources[i].ProviderID < state.Sources[j].ProviderID })
	by := make(map[string]int, len(state.Offers))
	for i, o := range state.Offers {
		by[o.ID] = i
	}
	b, _ := json.Marshal(state)
	gen := StableID("snapshot", string(b))
	s.view.Store(&View{Offers: state.Offers, Providers: s.providers, Sources: state.Sources, ByID: by, Generation: gen})
}
func (s *Store) Apply(id string, offers []Offer, fetchErr error, at time.Time) error {
	p, ok := s.Provider(id)
	if !ok {
		return errors.New("unknown provider")
	}
	normalized := make([]Offer, 0, len(offers))
	seen := map[string]bool{}
	if fetchErr == nil {
		if len(offers) > 100000 {
			return errors.New("provider catalog too large")
		}
		for _, o := range offers {
			n, e := Normalize(o, p, at)
			if e != nil {
				fetchErr = e
				break
			}
			if seen[n.ID] {
				fetchErr = errors.New("duplicate provider offer")
				break
			}
			seen[n.ID] = true
			normalized = append(normalized, n)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.View()
	state := State{Version: 1, Offers: make([]Offer, 0, len(v.Offers)+len(normalized)), Sources: append([]Source{}, v.Sources...)}
	source := Source{ProviderID: id}
	index := -1
	for i, x := range state.Sources {
		if x.ProviderID == id {
			source = x
			index = i
			break
		}
	}
	source.LastAttempt = &at
	if fetchErr != nil {
		source.Error = "Provider refresh failed; retained offers may be outdated."
		source.Complete = false
		state.Offers = append(state.Offers, v.Offers...)
	} else {
		for _, o := range v.Offers {
			if o.ProviderID != id {
				state.Offers = append(state.Offers, o)
			}
		}
		state.Offers = append(state.Offers, normalized...)
		source.LastSuccess = &at
		source.Error = ""
		source.Count = len(normalized)
		source.Complete = true
	}
	if index < 0 {
		state.Sources = append(state.Sources, source)
	} else {
		state.Sources[index] = source
	}
	if s.persistence != nil {
		if e := s.persistence.Save(state, id, at, fetchErr == nil); e != nil {
			return fmt.Errorf("commit catalog: %w", e)
		}
	} else if s.path != "" {
		if e := saveState(s.path, state); e != nil {
			return fmt.Errorf("save snapshot: %w", e)
		}
	}
	s.publish(state)
	return fetchErr
}
func saveState(path string, state State) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".catalog-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = json.NewEncoder(f).Encode(state); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
func (v *View) Freshness(id string, now time.Time) string {
	p := Provider{}
	for _, x := range v.Providers {
		if x.ID == id {
			p = x
			break
		}
	}
	for _, s := range v.Sources {
		if s.ProviderID == id {
			if s.LastSuccess == nil {
				return "unavailable"
			}
			if s.Error != "" || now.Sub(*s.LastSuccess) > time.Duration(p.Policy.MinRefreshSeconds)*time.Second*2 {
				return "stale"
			}
			return "fresh"
		}
	}
	return "not_connected"
}

func (v *View) OfferFreshness(o Offer, now time.Time) string {
	state := v.Freshness(o.ProviderID, now)
	if state != "fresh" {
		return state
	}
	for _, p := range v.Providers {
		if p.ID == o.ProviderID && now.Sub(o.ObservedAt) > time.Duration(p.Policy.MinRefreshSeconds)*2*time.Second {
			return "stale"
		}
	}
	return state
}

type Persistence interface {
	Load() (State, bool, error)
	Save(State, string, time.Time, bool) error
}

func NewPersistentStore(p Persistence, legacyPath string, providers []Provider) (*Store, error) {
	s, e := NewStore("", providers)
	if e != nil {
		return nil, e
	}
	state, found, e := p.Load()
	if e != nil {
		return nil, e
	}
	if !found {
		legacy, e := NewStore(legacyPath, providers)
		if e != nil {
			return nil, e
		}
		v := legacy.View()
		state = State{Version: 1, Offers: v.Offers, Sources: v.Sources}
		if e = p.Save(state, "", time.Now().UTC(), true); e != nil {
			return nil, e
		}
	}
	if e = s.restore(state); e != nil {
		return nil, e
	}
	s.persistence = p
	return s, nil
}
