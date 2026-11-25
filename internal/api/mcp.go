package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

type filterInput struct {
	Filters map[string]string `json:"filters,omitempty" jsonschema:"REST query parameters as key/value pairs; get_api_schema lists all available filters"`
}
type idInput struct {
	ID string `json:"id" jsonschema:"Stable offer or listing identifier"`
}
type emptyInput struct{}

func values(input filterInput) url.Values {
	v := url.Values{}
	for k, x := range input.Filters {
		v.Set(k, x)
	}
	return v
}
func (s *service) mcpHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "subregator", Version: "0.2.0"}, nil)
	tool := func(name, description string) *mcp.Tool {
		return &mcp.Tool{Name: name, Description: description, OutputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}}
	}
	mcp.AddTool(server, tool("search_offers", "Search current provider listings with every REST filter, currency-safe sorting and pagination"), func(_ context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		r, e := s.offers(values(in))
		return nil, r, e
	})
	mcp.AddTool(server, tool("get_offer", "Get a current offer including all quotes and freshness"), func(_ context.Context, _ *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, any, error) {
		r, e := s.offer(in.ID)
		return nil, r, e
	})
	mcp.AddTool(server, tool("list_providers", "Get providers, publication policies and collection status"), func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return nil, s.providers(), nil
	})
	mcp.AddTool(server, tool("get_listing", "Get a listing lifecycle, including removed listings and appearance count"), func(ctx context.Context, _ *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, any, error) {
		r, e := s.listing(ctx, in.ID)
		return nil, r, e
	})
	mcp.AddTool(server, tool("subnet_market", "Compare current observed offers by exact public subnet or explicit parent/child relation; read exact-prefix provider associations, listing/price changes and collection gaps without external requests; no ownership or sale inference"), func(ctx context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		r, e := s.market(ctx, values(in))
		return nil, r, e
	})
	mcp.AddTool(server, tool("listing_history", "Read append-only listing events by resource, provider, listing, event type, time or cursor"), func(ctx context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		r, e := s.events(ctx, values(in))
		return nil, r, e
	})
	mcp.AddTool(server, tool("known_resources", "Find known public prefixes and which providers listed them; hidden prefixes cannot be correlated"), func(ctx context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		r, e := s.resources(ctx, values(in))
		return nil, r, e
	})
	mcp.AddTool(server, tool("inspect_network", "Read cached BGP scope, RIS visibility, per-origin RPKI explanations, optional IRR consistency, source abuse observations, optional separate Spamhaus SBL/XBL/PBL IP findings and registry observations; proposed ASN validation is separate from observed origins; never start or refresh external checks"), func(ctx context.Context, _ *mcp.CallToolRequest, in intelligence.Query) (*mcp.CallToolResult, any, error) {
		r, e := s.inspect(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(server, tool("lookup_network", "Look up a public IP, prefix or ASN using free BGP, topology, RPKI and registry sources; reuse fresh cache and enforce shared upstream limits"), func(ctx context.Context, _ *mcp.CallToolRequest, in intelligence.Query) (*mcp.CallToolResult, any, error) {
		r, e := s.lookup(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(server, tool("network_history", "Read durable normalized observations and conservative change bounds for a known public prefix; no external collection; optional unapproved source histories excluded"), func(ctx context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		r, e := s.observations(ctx, values(in))
		return nil, r, e
	})
	mcp.AddTool(server, tool("network_checks", "List available free checks, input types, cache TTLs and source coverage limitations"), func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"items": intelligence.Capabilities()}, nil
	})
	mcp.AddTool(server, tool("network_status", "Read aggregate process-local check coverage, freshness, scheduling lag and upstream request counters; never trigger collection"), func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		r, e := s.collectionStatus()
		return nil, r, e
	})
	mcp.AddTool(server, tool("get_api_schema", "Get the complete public REST API contract and filter definitions"), func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return nil, schema(), nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: false, MaxRequestBodyBytes: 1 << 20, PropagateRequestCancellation: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body := http.MaxBytesReader(w, r.Body, 1<<20)
			defer body.Close()
			reader := bufio.NewReader(body)
			for {
				first, err := reader.Peek(1)
				if err != nil {
					break
				}
				if first[0] == '[' {
					problem(w, r, http.StatusBadRequest, "batch_unsupported", "Send one JSON-RPC message per HTTP request")
					return
				}
				if first[0] != ' ' && first[0] != '\n' && first[0] != '\r' && first[0] != '\t' {
					break
				}
				reader.ReadByte()
			}
			r.Body = io.NopCloser(reader)
		}
		handler.ServeHTTP(w, r)
	})
}
