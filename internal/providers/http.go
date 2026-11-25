package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxBody = 8 << 20

func Client() *http.Client {
	return &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirect refused") }}
}
func fetch(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("User-Agent", "Subregator/0.1 (+https://github.com/subregator/subregator-backend)")
	res, e := c.Do(r)
	if e != nil {
		return nil, errors.New("provider request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil {
		return nil, errors.New("provider body read failed")
	}
	if len(b) > maxBody {
		return nil, errors.New("provider response exceeds limit")
	}
	return b, nil
}
func decode(b []byte, out any) error {
	if e := json.Unmarshal(b, out); e != nil {
		return errors.New("invalid provider JSON")
	}
	return nil
}
