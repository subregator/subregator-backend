package catalog

import "testing"

func TestElistekaPolicyRestrictions(t *testing.T) {
	var original Provider
	for _, p := range Providers() {
		if p.ID == "elisteka" {
			original = p
		}
	}
	if _, err := NewStore("", []Provider{original}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Policy){
		"prefix disclosure": func(p *Policy) { p.PrefixVisibility = "full" },
		"frequent polling":  func(p *Policy) { p.MinRefreshSeconds = 3600 },
		"no window":         func(p *Policy) { p.RefreshAfterUTC = "" },
		"early window":      func(p *Policy) { p.RefreshAfterUTC = "03:59" },
		"malformed window":  func(p *Policy) { p.RefreshAfterUTC = "25:00" },
		"unpadded window":   func(p *Policy) { p.RefreshAfterUTC = "4:05" },
		"no expiry":         func(p *Policy) { p.MaxCurrentAgeSeconds = 0 },
		"negative expiry":   func(p *Policy) { p.MaxCurrentAgeSeconds = -1 },
		"long expiry":       func(p *Policy) { p.MaxCurrentAgeSeconds = 36*3600 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			p := original
			change(&p.Policy)
			if _, err := NewStore("", []Provider{p}); err == nil {
				t.Fatal("provider restriction relaxed")
			}
		})
	}
}
