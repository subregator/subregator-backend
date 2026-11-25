package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func TestCachedRegistrationRESTMCPAndSchema(t *testing.T) {
	d, err := history.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	metric := intelligence.Metric{Name: "rdap", Status: "ok", Source: "RIR RDAP", SourceURL: "https://rdap.apnic.net/ip/1.1.1.0", ObservedAt: &now, ExpiresAt: &expires, Data: json.RawMessage(`{"handle":"NET-EXAMPLE","name":"NETWORK-LABEL","startAddress":"1.1.1.0","endAddress":"1.1.1.255","entities":[{"handle":"ORG-EXAMPLE","roles":["registrant"],"vcardArray":["vcard",[["kind",{},"text","org"],["fn",{},"text","Example Ltd"]]]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}`)}
	b, _ := json.Marshal(metric)
	key := `{"Resource":"1.1.1.0/24","Name":"rdap","Start":"","End":"","Version":"","ASN":0}`
	if err := d.CachePut(context.Background(), key, b, expires); err != nil {
		t.Fatal(err)
	}
	h := Handler(store(t, 1), "", Services{Intelligence: intelligence.New(d, false, "", 120)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=rdap", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest intelligence.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rest); err != nil {
		t.Fatal(err)
	}
	if rest.Metrics[0].Registration == nil || rest.Metrics[0].Registration.RIR != "APNIC" || rest.Metrics[0].Observation.Scope.Relation != "exact" || len(rest.Metrics[0].Registration.AbuseContacts) != 1 {
		t.Fatalf("missing cached normalization: %+v", rest)
	}
	validateOpenAPI(t, "NetworkReport", rest)
	server := httptest.NewServer(h)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "inspect_network", Arguments: map[string]any{"resource": "1.1.1.0/24", "checks": []string{"rdap"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var actual intelligence.Report
	json.Unmarshal(data, &actual)
	if actual.Metrics[0].Registration.RIR != rest.Metrics[0].Registration.RIR || actual.Metrics[0].Registration.Records[0].Entities[0].Organization != "Example Ltd" {
		t.Fatalf("MCP differs: %s", data)
	}
	validateOpenAPI(t, "NetworkReport", actual)
}
