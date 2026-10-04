package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/derekxmartin/akeso-siem/internal/query"
)

//go:embed templates/*.md
var templates embed.FS

type GuideQuery struct {
	ID     string `json:"id"`
	Text   string `json:"hunt_text"`
	Window string `json:"window"`
}

// JSON quoting also supplies exactly the escaping the current Hunt lexer expects.
// A JSON HTTP body adds another serialization layer; never paste that body into Hunt.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func guideQueries(info RunInfo) []GuideQuery {
	var quoted []string
	for _, h := range info.Hosts {
		quoted = append(quoted, quote(h))
	}
	scope := "host.name IN (" + strings.Join(quoted, ", ") + ")"
	initial := "host.name IN (" + quote(info.SeedHost) + ")"
	path := scope + " AND process.executable IN (" + quote(unusualPath) + ")"
	return []GuideQuery{
		{"collision", scope, "none"},
		{"all", scope + " | sort @timestamp asc", "all"},
		{"timeline", initial + " | sort @timestamp asc", "all"},
		{"near-alert", initial + " | sort @timestamp asc", "initial"},
		{"common-name", scope + ` AND process.name IN ("cmd.exe", "whoami.exe") | sort @timestamp asc`, "all"},
		{"basename", scope + ` AND process.name IN ("syncsvc.exe") | sort @timestamp asc`, "all"},
		{"path", path + " | sort @timestamp asc", "all"},
		{"parent-path", scope + " AND process.parent.executable IN (" + quote(unusualPath) + ") | sort @timestamp asc", "all"},
		{"pid-pivot", initial + " AND (process.pid = 1200 OR process.parent.pid = 1200) | sort @timestamp asc", "initial"},
		{"missing-command", scope + " AND NOT process.command_line exists | sort @timestamp asc", "all"},
		{"missing-user", scope + " AND NOT user.id exists | sort @timestamp asc", "all"},
		{"host-counts", "count() by host.name where " + scope, "all"},
		{"path-counts", "count() by host.name where " + path, "all"},
		{"projection", scope + ` AND process.name IN ("syncsvc.exe") | sort @timestamp asc | fields @timestamp, host.name, process.pid, process.parent, process.executable, process.command_line, user.id`, "all"},
		{"boundary", initial + " AND process.pid IN (9000, 9004, 9008, 9012) AND @timestamp >= " + quote(info.Windows["boundary"].From) + " AND @timestamp < " + quote(info.Windows["boundary"].To) + " | sort @timestamp asc", "all"},
		{"boundary-picker", initial + " AND process.pid IN (9000, 9004, 9008, 9012) | sort @timestamp asc", "boundary"},
		{"seed-event", initial + " AND process.pid = 1100 AND @timestamp = " + quote(info.SeedTime), "all"},
		{"seed-alert", initial + " AND event.kind = \"alert\" AND rule.id = " + quote(ruleID) + " AND @timestamp = " + quote(info.SeedTime), "all"},
	}
}

func renderFiles(b *Bundle) (map[string][]byte, error) {
	files := map[string][]byte{"events.ndjson": b.NDJSON}
	queries := map[string]GuideQuery{}
	for _, q := range b.Queries {
		ast, err := query.Parse(q.Text)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", q.ID, err)
		}
		if _, err := query.Translate(ast); err != nil {
			return nil, fmt.Errorf("query %s: %w", q.ID, err)
		}
		queries[q.ID] = q
	}
	encode := func(name string, value any) error {
		body, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		files[name] = append(body, '\n')
		return nil
	}
	manifest := struct {
		RunInfo
		Roles       map[string]string `json:"answer_key_roles"`
		Expected    []Expected        `json:"expected_events"`
		Limitations []string          `json:"limitations"`
	}{b.Info, map[string]string{
		b.Info.Hosts[0]: "initial host; prioritize investigation of Office-child chain",
		b.Info.Hosts[1]: "related-path follow-up with incomplete context; association is not proof of spread",
		b.Info.Hosts[2]: "basename lookalike; different path and service parent; validate deployment before disposition",
		b.Info.Hosts[3]: "no specific supporting chain in this capture; absence is not proof of safety",
	}, b.Expected, []string{
		"Local expectation only; live mappings, loaded engine, indexed events and seed alert must be verified later.",
		"No hashes, signers, network, file-write or logon telemetry; no basis to assert lateral movement.",
		"Raw event IDs are not ES IDs. Normalizer keeps inner eventId/agent_id in raw only; source_type is excluded from stored JSON.",
		"PID 0 on capture roots denotes an unknown ancestor outside this capture; no PID reuse or exit events are modeled.",
		"EDR Informational maps to zero and is omitted in ECS event.severity; candidate Sigma alert is high (4) separately.",
	}}
	for name, value := range map[string]any{"run.json": b.Info, "queries.json": b.Queries, "facilitator/manifest.json": manifest} {
		if err := encode(name, value); err != nil {
			return nil, err
		}
	}
	requests := map[string]any{
		"collision-request.json":  map[string]any{"query": queries["collision"].Text, "size": 1},
		"records-request.json":    map[string]any{"query": queries["all"].Text, "size": 1000, "time_range": b.Info.Windows["all"]},
		"seed-alert-request.json": map[string]any{"query": queries["seed-alert"].Text, "size": 100, "time_range": b.Info.Windows["all"]},
		"path-request.json":       map[string]any{"query": queries["path"].Text, "size": 100, "time_range": b.Info.Windows["all"]},
	}
	for name, value := range requests {
		if err := encode(name, value); err != nil {
			return nil, err
		}
	}
	funcs := template.FuncMap{
		"q": func(id string) (string, error) {
			q, ok := queries[id]
			if !ok {
				return "", fmt.Errorf("unknown query %q", id)
			}
			return q.Text, nil
		},
		"window": func(id string) Window { return b.Info.Windows[id] },
		"evidence": func(label string) string {
			var lines []string
			for _, e := range b.Expected {
				if e.Label == label {
					lines = append(lines, "`"+e.ID+"`")
				}
			}
			return strings.Join(lines, ", ")
		},
	}
	for _, name := range []string{"ANALYST-BRIEF", "GUIDE", "WORKSHEET", "PREPARE", "ANSWER-KEY", "SOLVED-WALKTHROUGH"} {
		source, err := templates.ReadFile("templates/" + name + ".md")
		if err != nil {
			return nil, err
		}
		t, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(string(source))
		if err != nil {
			return nil, err
		}
		var rendered bytes.Buffer
		if err := t.Execute(&rendered, b.Info); err != nil {
			return nil, err
		}
		path := name + ".md"
		if name == "ANSWER-KEY" || name == "SOLVED-WALKTHROUGH" {
			path = "facilitator/" + path
		}
		files[path] = rendered.Bytes()
	}
	return files, nil
}
