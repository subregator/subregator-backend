package catalog

import (
	_ "embed"
	"encoding/json"
)

//go:embed providers.json
var providerData []byte

func Providers() []Provider {
	var p []Provider
	if e := json.Unmarshal(providerData, &p); e != nil {
		panic(e)
	}
	return p
}
