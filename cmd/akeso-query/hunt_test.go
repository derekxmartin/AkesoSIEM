package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/config"
	"github.com/derekxmartin/akeso-siem/internal/query"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// A loopback ES stand-in exercises the real Store -> storeAdapter -> HTTP response.
// It never connects to a configured lab and accepts only this test's index pattern.
func TestHuntEvidenceContract(t *testing.T) {
	fixture, err := os.ReadFile("../../internal/query/testdata/hunt-events.json")
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	if err := json.Unmarshal(fixture, &events); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/akeso-events-*/_search" {
			t.Errorf("unexpected index path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		hits := []map[string]any{}
		// Evaluate the two predicates independently; removing either must expose decoys.
		encoded, _ := json.Marshal(body["query"])
		hasHosts := bytes.Contains(encoded, []byte(`"terms":{"host.name":["alpha","bravo"]}`))
		var bounds map[string]any
		if q, ok := body["query"].(map[string]any); ok {
			if b, ok := q["bool"].(map[string]any); ok {
				if filters, ok := b["filter"].([]any); ok {
					for _, f := range filters {
						if rng, ok := f.(map[string]any)["range"].(map[string]any); ok {
							bounds, _ = rng["@timestamp"].(map[string]any)
						}
					}
				}
			}
		}
		for _, hit := range events {
			source := hit["_source"].(map[string]any)
			host := source["host"].(map[string]any)["name"]
			if hasHosts && host != "alpha" && host != "bravo" {
				continue
			}
			if bounds != nil {
				ts, _ := time.Parse(time.RFC3339Nano, source["@timestamp"].(string))
				from, _ := time.Parse(time.RFC3339Nano, bounds["gte"].(string))
				to, _ := time.Parse(time.RFC3339Nano, bounds["lt"].(string))
				if ts.Before(from) || !ts.Before(to) {
					continue
				}
			}
			hits = append(hits, hit)
		}
		json.NewEncoder(w).Encode(map[string]any{"took": 3, "hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits}})
	}))
	defer es.Close()
	s, err := store.New(config.ElasticsearchConfig{Addresses: []string{es.URL}})
	if err != nil {
		t.Fatal(err)
	}
	handler := query.NewAPIHandler(&storeAdapter{store: s}, "akeso-events-*")
	request := map[string]any{"query": `host.name IN ("alpha", "bravo") | sort @timestamp asc`, "time_range": map[string]any{"from": "2026-10-03T07:00:00-04:00", "to": "2026-10-03T12:00:00Z"}}
	raw, _ := json.Marshal(request)
	rec := httptest.NewRecorder()
	handler.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewReader(raw)))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Hits       []map[string]any  `json:"hits"`
		ResultType string            `json:"result_type"`
		TimeRange  map[string]string `json:"time_range"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, hit := range response.Hits {
		id, _ := hit["_id"].(string)
		ids = append(ids, id)
		for _, original := range events {
			if original["_id"] == id && !reflect.DeepEqual(hit, original) {
				t.Errorf("metadata/source changed for %s: %#v", id, hit)
			}
		}
	}
	if !reflect.DeepEqual(ids, []string{"alpha-start", "alpha-end", "bravo-inside"}) {
		t.Errorf("query/time intersection IDs: %v", ids)
	}
	if response.ResultType != "events" {
		t.Errorf("result_type = %q", response.ResultType)
	}
	if !reflect.DeepEqual(response.TimeRange, map[string]string{"from": "2026-10-03T11:00:00Z", "to": "2026-10-03T12:00:00Z"}) {
		t.Errorf("UTC bounds: %v", response.TimeRange)
	}
}

func TestHuntAdapterPreservesFieldsAndMissingMetadata(t *testing.T) {
	original := []json.RawMessage{
		json.RawMessage(`{"_index":"akeso-events-test","_id":"fields","fields":{"host.name":["alpha"]}}`),
		json.RawMessage(`{"_source":{"host":{"name":"bravo"},"message":"No timestamp or identity supplied"}}`),
	}
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"total": map[string]int{"value": 2}, "hits": original}})
	}))
	defer es.Close()
	s, err := store.New(config.ElasticsearchConfig{Addresses: []string{es.URL}})
	if err != nil {
		t.Fatal(err)
	}
	handler := query.NewAPIHandler(&storeAdapter{store: s}, "akeso-events-*")
	rec := httptest.NewRecorder()
	handler.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewBufferString(`{"query":"host.name exists | fields host.name"}`)))
	var response struct {
		Hits       []json.RawMessage
		ResultType string `json:"result_type"`
	}
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ResultType != "fields" {
		t.Errorf("kind %q", response.ResultType)
	}
	if len(response.Hits) != len(original) {
		t.Fatalf("hits %s", rec.Body)
	}
	for i := range original {
		var want, got any
		json.Unmarshal(original[i], &want)
		json.Unmarshal(response.Hits[i], &got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("hit %d changed: %s", i, response.Hits[i])
		}
	}
}

func TestHuntUpstreamFailuresAreNotEmptySuccess(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"http_failure", `{"error":{"reason":"fixture failure"}}`, 500},
		{"invalid_json", "not-json", 200},
		{"missing_hits", "{}", 200},
		{"timeout", `{"timed_out":true,"hits":{"total":{"value":0},"hits":[]}}`, 200},
		{"failed_shards", `{"_shards":{"failed":1},"hits":{"total":{"value":0},"hits":[]}}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Elastic-Product", "Elasticsearch")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer es.Close()
			s, err := store.New(config.ElasticsearchConfig{Addresses: []string{es.URL}})
			if err != nil {
				t.Fatal(err)
			}
			h := query.NewAPIHandler(&storeAdapter{store: s}, "akeso-events-*")
			rec := httptest.NewRecorder()
			h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewBufferString(`{"query":"host.name exists","time_range":{"relative":"1h"}}`)))
			if rec.Code != 502 {
				t.Fatalf("failure became %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestHuntAggregateSurvivesAdapterWithoutEventRecords(t *testing.T) {
	aggs := json.RawMessage(`{"group_by":{"buckets":[{"key":"alpha","doc_count":2}]}}`)
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["size"] != float64(0) {
			t.Errorf("aggregate requested hits: %v", body["size"])
		}
		if body["track_total_hits"] != true {
			t.Error("total count may be a lower bound")
		}
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"aggregations": aggs, "hits": map[string]any{"total": map[string]int{"value": 2}, "hits": []any{}}})
	}))
	defer es.Close()
	s, err := store.New(config.ElasticsearchConfig{Addresses: []string{es.URL}})
	if err != nil {
		t.Fatal(err)
	}
	h := query.NewAPIHandler(&storeAdapter{store: s}, "akeso-events-*")
	rec := httptest.NewRecorder()
	h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewBufferString(`{"query":"count() by host.name","time_range":{"relative":"1h"}}`)))
	var resp query.QueryResponse
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ResultType != "aggregation" || len(resp.Hits) != 0 || !bytes.Equal(resp.Aggs, aggs) {
		t.Fatalf("aggregate changed: %s", rec.Body)
	}
}
