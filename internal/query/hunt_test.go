package query

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHuntRelativeBoundsResolvedOncePerRequest(t *testing.T) {
	for _, relative := range []string{"15m", "1h", "4h", "24h", "7d", "30d"} {
		t.Run(relative, func(t *testing.T) {
			mock := newMockSearcher(0)
			h := NewAPIHandler(mock, "akeso-events-*")
			now := time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC)
			calls := 0
			h.now = func() time.Time { calls++; return now }
			var previousTo string
			for i := 0; i < 2; i++ {
				body, _ := json.Marshal(map[string]any{"query": "host.name = alpha", "time_range": map[string]string{"relative": relative}})
				rec := httptest.NewRecorder()
				h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewReader(body)))
				if rec.Code != 200 {
					t.Fatal(rec.Body)
				}
				var resp QueryResponse
				json.Unmarshal(rec.Body.Bytes(), &resp)
				durations := map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "4h": 4 * time.Hour, "24h": 24 * time.Hour, "7d": 168 * time.Hour, "30d": 720 * time.Hour}
				if resp.TimeRange == nil {
					t.Fatal("missing effective bounds")
				}
				if resp.TimeRange.To != now.Format(time.RFC3339Nano) || resp.TimeRange.From != now.Add(-durations[relative]).Format(time.RFC3339Nano) {
					t.Fatalf("bounds %#v", resp.TimeRange)
				}
				encoded, _ := json.Marshal(mock.lastBody)
				if !bytes.Contains(encoded, []byte(resp.TimeRange.From)) || !bytes.Contains(encoded, []byte(resp.TimeRange.To)) {
					t.Fatal("reported bounds differ from request")
				}
				if previousTo == resp.TimeRange.To {
					t.Fatal("refresh reused frozen relative bounds")
				}
				previousTo = resp.TimeRange.To
				now = now.Add(time.Second)
			}
			if calls != 2 {
				t.Fatalf("clock called %d times for two requests", calls)
			}
		})
	}
}

func TestHuntInvalidBoundsNeverSearch(t *testing.T) {
	for _, bounds := range []string{
		"{}",
		`{"relative":"nonsense"}`,
		`{"relative":"1h","from":"2026-10-03T11:00:00Z"}`,
		`{"from":"2026-10-03T11:00:00","to":"2026-10-03T12:00:00Z"}`,
		`{"from":"2026-10-03T12:00:00Z","to":"2026-10-03T11:00:00Z"}`,
		`{"from":"2026-10-03T12:00:00Z","to":"2026-10-03T12:00:00Z"}`,
		`{"from":"invalid","to":"2026-10-03T12:00:00Z"}`,
	} {
		mock := newMockSearcher(0)
		h := NewAPIHandler(mock, "akeso-events-*")
		rec := httptest.NewRecorder()
		h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", strings.NewReader(`{"query":"host.name exists","time_range":`+bounds+"}")))
		if rec.Code != 400 || mock.lastBody != nil {
			t.Errorf("bounds %s: status %d / search %#v", bounds, rec.Code, mock.lastBody)
		}
	}
}

func TestHuntTimePreservesExistingOperatorsAndPipes(t *testing.T) {
	for _, text := range []string{
		`host.name = "alpha"`, `host.name != "alpha"`,
		`host.name = "a*"`, `host.name = "a?"`,
		"event.severity > 2", "event.severity >= 2", "event.severity < 4", "event.severity <= 4",
		"host.name exists", `host.name IN ("alpha","bravo")`,
		"NOT host.name = alpha", "host.name = alpha OR host.name = bravo AND event.action = logon",
		"host.name = alpha | sort @timestamp desc | head 5 | fields host.name",
		"host.name = alpha | tail 5", "host.name = alpha | limit 5",
		"count() by host.name where host.name = alpha",
		"sum(event.duration) by host.name", "avg(event.duration) by host.name", "min(event.duration) by host.name", "max(event.duration) by host.name",
	} {
		t.Run(text, func(t *testing.T) {
			ast, err := Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			translated, err := Translate(ast)
			if err != nil {
				t.Fatal(err)
			}
			mock := newMockSearcher(1, `{"_id":"unused","_source":{"host":{"name":"alpha"}}}`)
			mock.result.Aggs = json.RawMessage(`{"group_by":{"buckets":[]}}`)
			h := NewAPIHandler(mock, "akeso-events-*")
			body, _ := json.Marshal(map[string]any{"query": text, "time_range": map[string]string{"relative": "1h"}})
			rec := httptest.NewRecorder()
			h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewReader(body)))
			if rec.Code != 200 {
				t.Fatal(rec.Body)
			}
			q := mock.lastBody["query"].(map[string]any)["bool"].(map[string]any)
			if !reflect.DeepEqual(q["must"], []any{translated.Query}) {
				t.Fatalf("original query changed: %#v", q)
			}
			for _, key := range []string{"sort", "_source", "aggs"} {
				if !reflect.DeepEqual(mock.lastBody[key], BuildSearchBody(translated)[key]) {
					t.Errorf("pipe changed: %s", key)
				}
			}
			if ast.Agg != nil {
				var resp QueryResponse
				json.Unmarshal(rec.Body.Bytes(), &resp)
				if resp.ResultType != "aggregation" || len(resp.Hits) != 0 || resp.Size != 0 || mock.lastBody["size"] != 0 || len(resp.Aggs) == 0 {
					t.Fatalf("aggregate misrepresented: %s", rec.Body)
				}
			}
		})
	}
}

func TestHuntGeneratedFiltersDecodeExactValues(t *testing.T) {
	raw, err := os.ReadFile("testdata/hunt-filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Query, Expected, Field, Value string }
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	// Execute the actual frontend generator, then parse/translate its output in Go.
	// Node is already required by the frontend; no package install or live API is used.
	script := `import {readFileSync} from "node:fs"; import {appendFilter} from "./src/lib/hunt.js";
 const cases=JSON.parse(readFileSync(0,"utf8"));
 process.stdout.write(JSON.stringify(cases.map(c=>appendFilter(c.query,c.field,c.value,c.exclude))));`
	cmd := exec.Command("node", "--input-type=module", "-e", script)
	cmd.Dir = "../../web"
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("running frontend filter generator (Node required): %v", err)
	}
	var generated []string
	if err := json.Unmarshal(output, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated) != len(cases) {
		t.Fatalf("generated %d queries for %d cases", len(generated), len(cases))
	}
	for i, tc := range cases {
		actual := generated[i]
		if actual != tc.Expected {
			t.Errorf("generated expression for %q: got %q, want %q", tc.Query, actual, tc.Expected)
		}
		ast, err := Parse(actual)
		if err != nil {
			t.Errorf("parse generated %q: %v", actual, err)
			continue
		}
		translated, err := Translate(ast)
		if err != nil {
			t.Errorf("translate generated %q: %v", actual, err)
			continue
		}
		encoded, _ := json.Marshal(translated.Query)
		expected, _ := json.Marshal(map[string]any{"terms": map[string]any{tc.Field: []string{tc.Value}}})
		if !bytes.Contains(encoded, expected) {
			t.Errorf("literal changed: %s; want %s", encoded, expected)
		}
		expectedAST, err := Parse(tc.Expected)
		if err != nil {
			t.Fatal(err)
		}
		expectedDSL, err := Translate(expectedAST)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(translated.Query, expectedDSL.Query) {
			t.Errorf("predicate weakened: %#v", translated.Query)
		}
		originalAST, err := Parse(tc.Query)
		if err != nil {
			t.Fatal(err)
		}
		originalDSL, err := Translate(originalAST)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(translated.Sort, originalDSL.Sort) || !reflect.DeepEqual(translated.Source, originalDSL.Source) || !reflect.DeepEqual(translated.Aggs, originalDSL.Aggs) || translated.Size != originalDSL.Size {
			t.Errorf("pipeline changed for %q", tc.Query)
		}
		mock := newMockSearcher(0)
		h := NewAPIHandler(mock, "akeso-events-*")
		body, _ := json.Marshal(map[string]any{"query": actual, "time_range": map[string]string{"from": "2026-10-03T11:00:00Z", "to": "2026-10-03T12:00:00Z"}})
		rec := httptest.NewRecorder()
		h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewReader(body)))
		if rec.Code != 200 {
			t.Errorf("generated query HTTP %d: %s", rec.Code, rec.Body)
			continue
		}
		scoped := mock.lastBody["query"].(map[string]any)["bool"].(map[string]any)
		wantFilter := []any{map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "2026-10-03T11:00:00Z", "lt": "2026-10-03T12:00:00Z"}}}}
		if !reflect.DeepEqual(scoped["must"], []any{expectedDSL.Query}) || !reflect.DeepEqual(scoped["filter"], wantFilter) {
			t.Errorf("filter/time intersection changed: %#v", scoped)
		}
	}
	for _, text := range []string{`host.name = "unterminated`, `host.name IN ("alpha)`} {
		if _, err := Parse(text); err == nil {
			t.Errorf("accepted incomplete query: %s", text)
		}
	}
}
