package providers

import (
	"context"
	"net/http"

	"github.com/subregator/subregator-backend/internal/catalog"
)

const ElistekaFeedURL = "https://elisteka.com/feeds/subregator.json"

func LoadElisteka(ctx context.Context, client *http.Client, url string) ([]catalog.Offer, error) {
	b, err := fetch(ctx, client, url)
	if err != nil {
		return nil, err
	}
	return ParseFeed(b, "elisteka")
}
