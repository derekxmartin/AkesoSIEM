package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/config"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
	"github.com/derekxmartin/akeso-siem/internal/ingest"
	"github.com/derekxmartin/akeso-siem/internal/normalize"
	"github.com/derekxmartin/akeso-siem/internal/normalize/parsers"
	"github.com/derekxmartin/akeso-siem/internal/query"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

var exampleInputs = Inputs{Seed: 73, Start: "2026-10-04T12:00:00Z", RunID: "I2604A"}

func fixture(t *testing.T) *Bundle {
	t.Helper()
	b, err := generate(exampleInputs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func engine() *normalize.Engine {
	r := normalize.NewRegistry()
	r.Register(parsers.Newakeso_edrParser())
	return normalize.NewEngine(r)
}

func TestDeterministicCompleteBundle(t *testing.T) {
	a, b := fixture(t), fixture(t)
	af, err := renderFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	bf, err := renderFiles(b)
	if err != nil || !reflect.DeepEqual(af, bf) {
		t.Fatalf("non-deterministic files: %v", err)
	}
	digest := sha256.Sum256(a.NDJSON)
	if hex.EncodeToString(digest[:]) != a.Info.SHA256 {
		t.Fatal("digest mismatch")
	}
	if !bytes.Equal(a.NDJSON, af["events.ndjson"]) || len(bytes.Split(bytes.TrimSpace(a.NDJSON), []byte("\n"))) != 400 {
		t.Fatal("NDJSON framing/count mismatch")
	}
	for _, in := range []Inputs{{74, exampleInputs.Start, exampleInputs.RunID}, {73, "2026-10-05T12:00:00Z", exampleInputs.RunID}, {73, exampleInputs.Start, "I2604B"}} {
		other, err := generate(in)
		if err != nil || bytes.Equal(a.NDJSON, other.NDJSON) || a.Info.SeedID == other.Info.SeedID {
			t.Fatalf("input change did not affect bytes/ID: %+v, %v", in, err)
		}
	}
}

func TestStrictTimestampsAndRequiredCLIInputs(t *testing.T) {
	for _, timestamp := range []string{"", "tomorrow", "2026-10-04T12:00:00", "2026-02-30T12:00:00Z", "2026-10-04T25:00:00Z", "2026-10-04T12:00:00-04:00", "2026-10-04T12:00:00+00:00"} {
		t.Run(timestamp, func(t *testing.T) {
			in := exampleInputs
			in.Start = timestamp
			if _, err := generate(in); err == nil {
				t.Fatal("accepted invalid/non-canonical UTC start")
			}
		})
	}
	for _, runID := range []string{"", "toolong12X", "../x", "host name", "lowercase"} {
		in := exampleInputs
		in.RunID = runID
		if _, err := generate(in); err == nil {
			t.Fatalf("accepted unsafe run ID %q", runID)
		}
	}
	base := []string{"--seed", "73", "--start", exampleInputs.Start, "--run-id", exampleInputs.RunID, "--out", filepath.Join(t.TempDir(), "run")}
	for i := 0; i < len(base); i += 2 {
		args := append(append([]string{}, base[:i]...), base[i+2:]...)
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted missing flag %s", base[i])
		}
	}
	for _, seed := range []string{"-1", "abc", "18446744073709551616"} {
		args := append([]string{}, base...)
		args[1] = seed
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid seed accepted")
		}
	}
}

func TestRejectsInvalidEnvelopeBeforeNormalization(t *testing.T) {
	original := fixture(t).Events[0]
	mutations := []func(*Record){
		func(r *Record) { r.Timestamp = "invalid" },
		func(r *Record) { r.Event.Timestamp = "invalid" },
		func(r *Record) { r.Event.Timestamp = "2026-10-04T12:01:00Z" },
		func(r *Record) { r.SourceType = "other" },
		func(r *Record) { r.Schema = "other/v1" },
		func(r *Record) { r.Event.Source = "unknown" },
		func(r *Record) { r.Event.Payload.NewProcessID++ },
		func(r *Record) { r.Event.Payload.ParentProcessID++ },
		func(r *Record) { r.Event.Payload.ImagePath = unusualPath },
		func(r *Record) { r.Event.Payload.CommandLine = nil },
	}
	for i, mutate := range mutations {
		r := original
		mutate(&r)
		if err := validateRecord(r); err == nil {
			t.Fatalf("invalid envelope mutation %d accepted", i)
		}
	}
}

func TestCLIRefusesOverwriteAndHasNoIngestOption(t *testing.T) {
	out := filepath.Join(t.TempDir(), "run")
	args := []string{"--seed", "73", "--start", exampleInputs.Start, "--run-id", exampleInputs.RunID, "--out", out}
	if err := run(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, "events.ndjson"))
	if err := run(args, &bytes.Buffer{}); err == nil {
		t.Fatal("existing output overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(out, "events.ndjson"))
	if !bytes.Equal(before, after) {
		t.Fatal("prior output changed")
	}
	if err := run(append(args, "--ingest"), &bytes.Buffer{}); err == nil {
		t.Fatal("unexpected ingestion flag")
	}
}

func TestCoherentProcessRelationshipsAndBackground(t *testing.T) {
	b := fixture(t)
	seen, active, agents, counts, commonNames := map[string]bool{}, map[string]Record{}, map[string]string{}, map[string]int{}, map[string]int{}
	last := ""
	for _, r := range b.Events {
		if err := validateRecord(r); err != nil {
			t.Fatal(err)
		}
		if len(r.Host) > 15 || !strings.HasPrefix(r.Host, "SYN-"+exampleInputs.RunID+"-") || seen[r.Event.ID] || r.Timestamp < last {
			t.Fatal("invalid identity/order")
		}
		seen[r.Event.ID], last = true, r.Timestamp
		if old := agents[r.Host]; old != "" && old != r.AgentID {
			t.Fatal("agent changed within host")
		}
		agents[r.Host] = r.AgentID
		p := r.Event.Process
		key := fmt.Sprintf("%s/%d", r.Host, p.PID)
		if _, exists := active[key]; exists {
			t.Fatal("PID reuse in capture")
		}
		if p.ParentPID > 0 {
			parent, ok := active[fmt.Sprintf("%s/%d", r.Host, p.ParentPID)]
			if !ok || parent.Timestamp >= r.Timestamp || parent.Event.Process.ImagePath != p.ParentImagePath {
				t.Fatalf("incoherent parent: %s", r.Event.ID)
			}
		} else if p.ParentImagePath != "" {
			t.Fatal("fabricated root parent")
		}
		active[key] = r
		if p.UserSID != nil && *p.UserSID == "S-1-5-18" && (p.SessionID != 0 || p.IntegrityLevel != 16384 || !p.IsElevated) {
			t.Fatal("inconsistent SYSTEM process context")
		}
		counts[r.Host]++
		if p.ImagePath == cmdPath && p.ParentImagePath == explorer {
			commonNames[r.Host]++
		}
	}
	for i, host := range b.Info.Hosts {
		if counts[host] != []int{190, 90, 65, 55}[i] || commonNames[host] == 0 {
			t.Fatalf("bad host/background counts: %s", host)
		}
	}
	if len(seen) != 400 || len(agents) != 4 || counts[b.Info.SeedHost] <= 100 {
		t.Fatal("exercise bounds changed")
	}
	for _, forbidden := range []string{"attacker", "malware", "benign", "answer_key", "classification"} {
		if bytes.Contains(bytes.ToLower(b.NDJSON), []byte(forbidden)) {
			t.Fatalf("spoiler in telemetry: %s", forbidden)
		}
	}
}

func TestActualEDRNormalizationAndGenuineMissingFields(t *testing.T) {
	b, normalizer := fixture(t), engine()
	missingCommand, missingUser := 0, 0
	for _, r := range b.Events {
		raw, _ := json.Marshal(r)
		e, err := normalizer.Normalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		p := r.Event.Process
		if e.Timestamp.Format(time.RFC3339) != r.Timestamp || e.Host.Name != r.Host || e.Process.PID != p.PID || e.Process.Executable != p.ImagePath || e.SourceType != "akeso_edr" {
			t.Fatalf("lost context %s", r.Event.ID)
		}
		name := p.ImagePath[strings.LastIndex(p.ImagePath, `\`)+1:]
		if e.Process.Name != name || e.Event.Action != "process_created" || !reflect.DeepEqual(e.Event.Type, []string{"start"}) || !reflect.DeepEqual(e.Event.Category, []string{"process"}) || !bytes.Equal(e.Raw, raw) {
			t.Fatal("normalization semantics/raw changed")
		}
		if p.ParentPID > 0 && (e.Process.Parent == nil || e.Process.Parent.PID != p.ParentPID || e.Process.Parent.Executable != p.ParentImagePath || e.Process.Parent.Name != p.ParentImagePath[strings.LastIndex(p.ParentImagePath, `\`)+1:]) {
			t.Fatal("lost parent")
		}
		encoded, _ := json.Marshal(e)
		var doc map[string]any
		json.Unmarshal(encoded, &doc)
		proc := doc["process"].(map[string]any)
		if _, exists := doc["source_type"]; exists {
			t.Fatal("unexpected searchable source_type")
		}
		if _, exists := proc["path"]; exists {
			t.Fatal("wrong path field")
		}
		if p.CommandLine == nil {
			missingCommand++
			if _, exists := proc["command_line"]; exists || bytes.Contains(raw, []byte(`"commandLine"`)) {
				t.Fatal("missing command line was supplied")
			}
		} else if e.Process.CommandLine != *p.CommandLine {
			t.Fatal("lost command line")
		}
		if p.UserSID == nil {
			missingUser++
			if e.User != nil || bytes.Contains(raw, []byte(`"userSid"`)) {
				t.Fatal("missing user supplied")
			}
		} else if e.User == nil || e.User.ID != *p.UserSID || e.User.Name != "" {
			t.Fatal("SID lost or name fabricated")
		}
	}
	if missingCommand != 2 || missingUser != 3 {
		t.Fatalf("missing command/user counts %d/%d", missingCommand, missingUser)
	}
}

type memoryIndexer struct{ batches map[string][]common.ECSEvent }

func (m *memoryIndexer) BulkIndex(_ context.Context, index string, events []common.ECSEvent) error {
	m.batches[index] = append(m.batches[index], events...)
	return nil
}

func candidateEngine(t *testing.T) *correlate.RuleEngine {
	t.Helper()
	rules, err := correlate.ParseSigmaFile("../../rules/sigma_curated/proc_creation_cmd_office_spawn.yml")
	if err != nil || len(rules) != 1 || rules[0].ID != ruleID {
		t.Fatalf("candidate: %v", err)
	}
	ls, err := correlate.LoadLogsourceMap("../../parsers/logsource_map.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := correlate.NewRuleEngine(correlate.NewRuleRegistry(rules), ls)
	if e.Stats().RulesCompiled != 1 || e.Stats().RulesSkipped != 0 {
		t.Fatalf("candidate did not compile: %+v", e.Stats())
	}
	return e
}

func TestActualIngestRouteNormalizationAndSeedAlert(t *testing.T) {
	b := fixture(t)
	indexer := &memoryIndexer{batches: map[string][]common.ECSEvent{}}
	rules := candidateEngine(t)
	pipeline := ingest.NewPipeline(engine(), indexer, "fixture", nil, rules, nil)
	listener := ingest.NewHTTPListener(config.IngestConfig{APIKeys: []string{"local-test-only"}}, pipeline.Handle)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(b.NDJSON))
	req.Header.Set("X-API-Key", "local-test-only")
	req.Header.Set("Content-Type", "application/x-ndjson")
	listener.Router().ServeHTTP(recorder, req) // In-process only: no listener/socket/ES client.
	pipeline.Drain()
	if recorder.Code != 202 || !strings.Contains(recorder.Body.String(), `"accepted":400`) {
		t.Fatalf("ingest rejected: %d %s", recorder.Code, recorder.Body)
	}
	events := indexer.batches["fixture-events-akeso_edr-2026.10.04"]
	alerts := indexer.batches["fixture-alerts-2026.10.04"]
	if len(events) != 400 || len(alerts) != 1 || pipeline.Processed() != 400 {
		t.Fatalf("not just 202: indexed %d events, %d candidate alerts", len(events), len(alerts))
	}
	alert := alerts[0]
	var raw Record
	json.Unmarshal(alert.Raw, &raw)
	if alert.Rule.ID != ruleID || alert.Rule.Name != ruleTitle || alert.Rule.Severity != "high" || alert.Event.Severity != 4 || alert.Event.Kind != "alert" || raw.Event.ID != b.Info.SeedID || alert.Host.Name != b.Info.SeedHost || alert.Timestamp.Format(time.RFC3339) != b.Info.SeedTime {
		t.Fatal("wrong alert evidence")
	}
	normalized, _ := engine().Normalize(alert.Raw)
	normalized.Process.Parent.Name = "explorer.exe"
	if len(rules.Evaluate(normalized)) != 0 {
		t.Fatal("candidate falsely matched non-Office parent")
	}
}

func TestGuideQueriesParseTranslateAndPathRoundTrip(t *testing.T) {
	b := fixture(t)
	files, err := renderFiles(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range b.Queries {
		t.Run(q.ID, func(t *testing.T) {
			ast, err := query.Parse(q.Text)
			if err != nil {
				t.Fatal(err)
			}
			tr, err := query.Translate(ast)
			if err != nil || tr.Query == nil {
				t.Fatalf("translation: %v", err)
			}
			if q.ID == "path" {
				in := ast.Filter.(*query.BoolExpr).Right.(*query.InExpr)
				if in.Field != "process.executable" || !reflect.DeepEqual(in.Values, []string{unusualPath}) {
					t.Fatalf("Windows escaping altered: %#v", in)
				}
				encoded, _ := json.Marshal(tr.Query)
				if !bytes.Contains(encoded, []byte(quote(unusualPath))) {
					t.Fatal("translation lost path")
				}
			}
		})
	}
	blocks := regexp.MustCompile("(?s)```hunt\n(.*?)\n```")
	documented := 0
	for name, data := range files {
		if strings.HasSuffix(name, ".md") {
			for _, block := range blocks.FindAllSubmatch(data, -1) {
				ast, err := query.Parse(string(block[1]))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if _, err := query.Translate(ast); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				documented++
			}
		}
		if strings.HasSuffix(name, "-request.json") {
			var req query.QueryRequest
			if err := json.Unmarshal(data, &req); err != nil {
				t.Fatal(err)
			}
			ast, err := query.Parse(req.Query)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := query.Translate(ast); err != nil {
				t.Fatal(err)
			}
			if name == "collision-request.json" && req.TimeRange != nil {
				t.Fatal("collision check must be all-time")
			}
			if name == "path-request.json" && !bytes.Contains(data, []byte(`C:\\\\Users`)) {
				t.Fatal("JSON transport layer escaping is wrong")
			}
		}
	}
	if documented != 16 {
		t.Fatalf("documented query count changed: %d", documented)
	}
}

// Test-only evaluation of the guide's exact keyword/range/exists ASTs. This is
// not an Elasticsearch substitute; translation and API time-filter shape are
// checked separately, and live storage/search checks remain explicitly unrun.
func field(doc map[string]any, name string) any {
	var current any = doc
	for _, part := range strings.Split(name, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = obj[part]
	}
	return current
}

func matches(t *testing.T, n query.Node, doc map[string]any) bool {
	t.Helper()
	switch x := n.(type) {
	case nil:
		return true
	case *query.BoolExpr:
		switch x.Op {
		case query.BoolAnd:
			return matches(t, x.Left, doc) && matches(t, x.Right, doc)
		case query.BoolOr:
			return matches(t, x.Left, doc) || matches(t, x.Right, doc)
		case query.BoolNot:
			return !matches(t, x.Left, doc)
		}
	case *query.InExpr:
		for _, v := range x.Values {
			if fmt.Sprint(field(doc, x.Field)) == v {
				return true
			}
		}
		return false
	case *query.ExistsExpr:
		return field(doc, x.Field) != nil
	case *query.CompareExpr:
		v := fmt.Sprint(field(doc, x.Field))
		switch x.Operator {
		case query.OpEquals:
			return v == x.Value
		case query.OpGTE_Q:
			return v >= x.Value
		case query.OpLess:
			return v < x.Value
		}
	}
	t.Fatalf("test evaluator does not support %T", n)
	return false
}

func TestGuideFixturePivotsAndBoundaryIDs(t *testing.T) {
	b := fixture(t)
	wantCounts := map[string]int{"timeline": 190, "basename": 3, "path": 2, "parent-path": 4, "pid-pivot": 4, "missing-command": 2, "missing-user": 3, "boundary": 2, "boundary-picker": 2, "seed-event": 1, "all": 400}
	for _, q := range b.Queries {
		want, check := wantCounts[q.ID]
		if !check {
			continue
		}
		ast, _ := query.Parse(q.Text)
		var ids []string
		for _, e := range b.Expected {
			ts := field(e.Normalized, "@timestamp").(string)
			w := b.Info.Windows[q.Window]
			if matches(t, ast.Filter, e.Normalized) && ts >= w.From && ts < w.To {
				ids = append(ids, e.ID)
			}
		}
		if len(ids) != want {
			t.Fatalf("%s got %d want %d", q.ID, len(ids), want)
		}
		if strings.HasPrefix(q.ID, "boundary") {
			var expected []string
			for _, e := range b.Expected {
				if e.Label == "at-start" || e.Label == "before-end" {
					expected = append(expected, e.ID)
				}
			}
			if !reflect.DeepEqual(ids, expected) {
				t.Fatalf("wrong boundary IDs: %v", ids)
			}
		}
	}
}

type capturingSearch struct{ body map[string]any }

func (s *capturingSearch) SearchRaw(_ context.Context, _ string, body map[string]any) (*query.SearchRawResult, error) {
	s.body = body
	return &query.SearchRawResult{}, nil
}

func TestQueryAPIKeepsGuideFilterAndHalfOpenTimeBounds(t *testing.T) {
	b := fixture(t)
	for _, q := range b.Queries {
		if q.Window == "none" {
			continue
		}
		w := b.Info.Windows[q.Window]
		req, _ := json.Marshal(map[string]any{"query": q.Text, "size": 100, "time_range": w})
		search := &capturingSearch{}
		h := query.NewAPIHandler(search, "fixture-events-*")
		rec := httptest.NewRecorder()
		h.HandleQuery(rec, httptest.NewRequest("POST", "/api/v1/query", bytes.NewReader(req)))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", q.ID, rec.Code, rec.Body)
		}
		ast, _ := query.Parse(q.Text)
		tr, _ := query.Translate(ast)
		boolQuery := search.body["query"].(map[string]any)["bool"].(map[string]any)
		if !reflect.DeepEqual(boolQuery["must"], []any{tr.Query}) {
			t.Fatal("user query replaced by time")
		}
		filter := boolQuery["filter"].([]any)[0].(map[string]any)["range"].(map[string]any)["@timestamp"]
		if !reflect.DeepEqual(filter, map[string]any{"gte": w.From, "lt": w.To}) {
			t.Fatal("bounds changed")
		}
	}
}

func TestGuideFieldsExistInActualMapping(t *testing.T) {
	m := store.ECSIndexTemplate("fixture")["template"].(map[string]any)["mappings"].(map[string]any)
	props := m["properties"].(map[string]any)
	for _, name := range []string{"@timestamp", "host.name", "process.pid", "process.name", "process.executable", "process.command_line", "process.parent.pid", "process.parent.name", "process.parent.executable", "user.id", "rule.id"} {
		current := props
		parts := strings.Split(name, ".")
		for i, part := range parts {
			mapping, ok := current[part].(map[string]any)
			if !ok {
				t.Fatalf("unmapped guide field %s", name)
			}
			if i < len(parts)-1 {
				current = mapping["properties"].(map[string]any)
			}
		}
	}
	if props["source_type"] != nil || props["raw"].(map[string]any)["enabled"] != false {
		t.Fatal("documented searchability assumptions changed")
	}
}

func TestExampleMatchesGenerator(t *testing.T) {
	b := fixture(t)
	files, err := renderFiles(b)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("example", filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("example %s differs from generator: %v", name, err)
		}
	}
	t.Logf("%d generated artifacts, %d raw records, %d parser-checked queries, seed %s", len(files), len(b.Events), len(b.Queries), strconv.FormatUint(b.Info.Seed, 10))
}
