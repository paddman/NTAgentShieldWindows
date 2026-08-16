package protection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReputationLookupSendsHashOnly(t *testing.T) {
	sha := strings.Repeat("a", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if len(body) != 1 || body["sha256"] != sha {
			t.Errorf("reputation request leaked fields: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"verdict": "malicious", "confidence": 99, "threat": "test_hash"})
	}))
	defer server.Close()
	client, err := newReputationClient(server.URL, "", time.Second, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()
	client.http.Timeout = time.Second
	signal, err := client.lookup(context.Background(), sha)
	if err != nil {
		t.Fatal(err)
	}
	if signal == nil || !signal.Authoritative || signal.Confidence != 99 {
		t.Fatalf("unexpected reputation signal: %#v", signal)
	}
}
