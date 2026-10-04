package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/normalize"
	"github.com/derekxmartin/akeso-siem/internal/normalize/parsers"
)

const ruleID = "a1b2c3d4-1012-4a1b-9c12-000000000012"
const ruleTitle = "Command Prompt Spawned by Office Application"
const explorer = `C:\Windows\explorer.exe`
const services = `C:\Windows\System32\services.exe`
const office = `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
const cmdPath = `C:\Windows\System32\cmd.exe`
const unusualPath = `C:\Users\lab.user\AppData\Local\Cedar\syncsvc.exe`
const installedPath = `C:\Program Files\Cedar Tools\syncsvc.exe`

type Inputs struct {
	Seed  uint64 `json:"seed"`
	Start string `json:"start_utc"`
	RunID string `json:"run_id"`
}

type Context struct {
	PID             int     `json:"pid"`
	ParentPID       int     `json:"parentPid"`
	SessionID       int     `json:"sessionId"`
	ImagePath       string  `json:"imagePath"`
	CommandLine     *string `json:"commandLine,omitempty"`
	UserSID         *string `json:"userSid,omitempty"`
	IntegrityLevel  int     `json:"integrityLevel"`
	IsElevated      bool    `json:"isElevated"`
	ParentImagePath string  `json:"parentImagePath,omitempty"`
}

type Payload struct {
	IsCreate        bool    `json:"isCreate"`
	NewProcessID    int     `json:"newProcessId"`
	ParentProcessID int     `json:"parentProcessId"`
	ImagePath       string  `json:"imagePath"`
	CommandLine     *string `json:"commandLine,omitempty"`
	IntegrityLevel  int     `json:"integrityLevel"`
	IsElevated      bool    `json:"isElevated"`
}

type Record struct {
	SourceType string `json:"source_type"`
	Schema     string `json:"schema"`
	Host       string `json:"host"`
	AgentID    string `json:"agent_id"`
	Timestamp  string `json:"timestamp"`
	Event      struct {
		ID        string  `json:"eventId"`
		Timestamp string  `json:"timestamp"`
		Source    string  `json:"source"`
		Severity  string  `json:"severity"`
		Process   Context `json:"process"`
		Payload   Payload `json:"payload"`
	} `json:"event"`
}

type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type RunInfo struct {
	Inputs
	SHA256    string            `json:"ndjson_sha256"`
	Count     int               `json:"count"`
	Hosts     []string          `json:"hosts"`
	Counts    map[string]int    `json:"counts_by_host"`
	Windows   map[string]Window `json:"windows_utc_start_inclusive_end_exclusive"`
	SeedHost  string            `json:"starting_host"`
	SeedTime  string            `json:"starting_event_utc"`
	SeedID    string            `json:"starting_raw_event_id"`
	RuleID    string            `json:"candidate_rule_id"`
	RuleTitle string            `json:"candidate_rule_title"`
}

type Expected struct {
	ID         string         `json:"raw_event_id"`
	Label      string         `json:"answer_key_label"`
	Normalized map[string]any `json:"normalized"`
}

type Bundle struct {
	Info     RunInfo
	Events   []Record
	Expected []Expected
	Queries  []GuideQuery
	NDJSON   []byte
}

func utcStart(s string) (time.Time, error) {
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`).MatchString(s) {
		return time.Time{}, fmt.Errorf("start must be an explicit UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() < 1970 || t.Year() > 9998 {
		return time.Time{}, fmt.Errorf("invalid exercise timestamp %q", s)
	}
	return t, nil
}

func eventID(key string) string {
	digest := sha256.Sum256([]byte(key))
	// Version 8 UUID: deterministic custom SHA-256 derivation, not an ES _id.
	digest[6] = (digest[6] & 0x0f) | 0x80
	digest[8] = (digest[8] & 0x3f) | 0x80
	s := hex.EncodeToString(digest[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func ptr(s string) *string { return &s }

func generate(in Inputs) (*Bundle, error) {
	start, err := utcStart(in.Start)
	if err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^[A-Z0-9]{1,8}$`).MatchString(in.RunID) {
		return nil, fmt.Errorf("run ID must be 1-8 uppercase letters/digits (Windows names <=15 characters)")
	}
	at := func(seconds int) string { return start.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339) }
	b := &Bundle{Info: RunInfo{Inputs: in, Count: 400, Counts: map[string]int{}, RuleID: ruleID, RuleTitle: ruleTitle}}
	for h := 1; h <= 4; h++ {
		b.Info.Hosts = append(b.Info.Hosts, fmt.Sprintf("SYN-%s-%02d", in.RunID, h))
	}
	b.Info.SeedHost, b.Info.SeedTime = b.Info.Hosts[0], at(1800)
	b.Info.Windows = map[string]Window{
		"all": {at(0), at(7201)}, "initial": {at(1740), at(2220)},
		"boundary": {at(1800), at(2100)},
	}
	labels := map[string]string{}
	add := func(h, seconds, pid, ppid int, path, parent string, command, user *string, label string) {
		host := b.Info.Hosts[h]
		id := eventID(fmt.Sprintf("hunt-exercise-v1|%d|%s|%s|%s|%d|%d", in.Seed, in.Start, in.RunID, host, seconds, pid))
		r := Record{SourceType: "akeso_edr", Schema: "akesoedr/v1", Host: host,
			AgentID: "synthetic-" + eventID(in.RunID+"|"+host), Timestamp: at(seconds)}
		r.Event.ID, r.Event.Timestamp, r.Event.Source, r.Event.Severity = id, r.Timestamp, "DriverProcess", "Informational"
		r.Event.Process = Context{PID: pid, ParentPID: ppid, SessionID: 1, ImagePath: path,
			CommandLine: command, UserSID: user, IntegrityLevel: 8192, ParentImagePath: parent}
		if user != nil && *user == "S-1-5-18" {
			r.Event.Process.SessionID, r.Event.Process.IntegrityLevel, r.Event.Process.IsElevated = 0, 16384, true
		}
		r.Event.Payload = Payload{IsCreate: true, NewProcessID: pid, ParentProcessID: ppid, ImagePath: path,
			CommandLine: command, IntegrityLevel: r.Event.Process.IntegrityLevel, IsElevated: r.Event.Process.IsElevated}
		b.Events = append(b.Events, r)
		labels[id] = label
		b.Info.Counts[host]++
		if label == "seed" {
			b.Info.SeedID = id
		}
	}
	user := func(h int) *string { return ptr(fmt.Sprintf("S-1-5-21-2400000000-2400000001-2400000002-%d", 1001+h)) }
	for h := 0; h < 4; h++ {
		// PID 0 is an explicit capture boundary; no invented ancestor/image.
		add(h, h*2, 100, 0, services, "", ptr(`services.exe`), ptr("S-1-5-18"), "capture-root")
		add(h, h*2+1, 200, 0, explorer, "", ptr(`explorer.exe`), user(h), "capture-root")
	}
	add(0, 1770, 1000, 200, office, explorer, ptr(`WINWORD.EXE "C:\Users\lab.user\Documents\Quarterly Notes.docx"`), user(0), "office")
	add(0, 1800, 1100, 1000, cmdPath, office, ptr(`cmd.exe /c "C:\Users\lab.user\AppData\Local\Cedar\syncsvc.exe" --profile daily`), user(0), "seed")
	add(0, 1802, 1200, 1100, unusualPath, cmdPath, ptr(`"C:\Users\lab.user\AppData\Local\Cedar\syncsvc.exe" --profile daily`), user(0), "initial-path")
	add(0, 1805, 1300, 1200, `C:\Windows\System32\whoami.exe`, unusualPath, ptr(`whoami.exe /user`), user(0), "initial-child")
	add(0, 1820, 1304, 1200, `C:\Windows\System32\hostname.exe`, unusualPath, ptr(`hostname.exe`), user(0), "initial-child")
	add(0, 1890, 1308, 1200, `C:\Windows\System32\cmd.exe`, unusualPath, ptr(`cmd.exe /c ver`), user(0), "initial-child")
	add(1, 1980, 1000, 200, cmdPath, explorer, nil, nil, "second-parent-missing")
	add(1, 1983, 1100, 1000, unusualPath, cmdPath, nil, nil, "second-path-missing")
	add(1, 1987, 1200, 1100, `C:\Windows\System32\whoami.exe`, unusualPath, ptr(`whoami.exe /user`), nil, "second-child-missing")
	add(2, 1810, 1000, 100, installedPath, services, ptr(`"C:\Program Files\Cedar Tools\syncsvc.exe" --service`), ptr("S-1-5-18"), "lookalike-path")
	add(2, 1840, 1100, 1000, `C:\Program Files\Cedar Tools\status.exe`, installedPath, ptr(`status.exe --summary`), ptr("S-1-5-18"), "lookalike-child")
	// Four known endpoints around a five-minute window, independently of the seed.
	for i, sec := range []int{1799, 1800, 2099, 2100} {
		add(0, sec, 9000+i*4, 200, `C:\Windows\System32\notepad.exe`, explorer, ptr(`notepad.exe`), user(0), []string{"before-start", "at-start", "before-end", "at-end"}[i])
	}
	paths := []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Windows\System32\notepad.exe`, cmdPath, `C:\Windows\System32\RuntimeBroker.exe`, `C:\Windows\System32\whoami.exe`}
	commands := []string{`msedge.exe --profile-directory=Default`, `notepad.exe "C:\Users\lab.user\Documents\notes.txt"`, `cmd.exe /c echo daily-check`, `RuntimeBroker.exe -Embedding`, `whoami.exe`}
	// Explicit SHA-derived choices make the output independent of PRNG/global state.
	for h, target := range []int{190, 90, 65, 55} {
		remaining := target - b.Info.Counts[b.Info.Hosts[h]]
		for j := 0; j < remaining; j++ {
			d := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%d|%d", in.Seed, in.Start, in.RunID, h, j)))
			choice := int(d[0]) % len(paths)
			seconds := 60 + j*7000/remaining + int(d[1])%13
			add(h, seconds, 20000+j*4, 200, paths[choice], explorer, ptr(commands[choice]), user(h), "background")
		}
	}
	sort.Slice(b.Events, func(i, j int) bool {
		if b.Events[i].Timestamp == b.Events[j].Timestamp {
			return b.Events[i].Event.ID < b.Events[j].Event.ID
		}
		return b.Events[i].Timestamp < b.Events[j].Timestamp
	})
	reg := normalize.NewRegistry()
	reg.Register(parsers.Newakeso_edrParser())
	engine := normalize.NewEngine(reg)
	var data bytes.Buffer
	for _, r := range b.Events {
		if err := validateRecord(r); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		data.Write(raw)
		data.WriteByte('\n')
		event, err := engine.Normalize(raw)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		var normalized map[string]any
		if err := json.Unmarshal(encoded, &normalized); err != nil {
			return nil, err
		}
		delete(normalized, "raw")
		b.Expected = append(b.Expected, Expected{r.Event.ID, labels[r.Event.ID], normalized})
	}
	b.NDJSON = data.Bytes()
	digest := sha256.Sum256(b.NDJSON)
	b.Info.SHA256 = hex.EncodeToString(digest[:])
	b.Queries = guideQueries(b.Info)
	return b, nil
}

func validateRecord(r Record) error {
	if _, err := utcStart(r.Timestamp); err != nil {
		return err
	}
	if _, err := utcStart(r.Event.Timestamp); err != nil {
		return err
	}
	if r.Timestamp != r.Event.Timestamp || r.SourceType != "akeso_edr" || r.Schema != "akesoedr/v1" || r.Event.Source != "DriverProcess" || r.Host == "" || r.AgentID == "" || r.Event.ID == "" {
		return fmt.Errorf("invalid envelope for %q", r.Event.ID)
	}
	p, q := r.Event.Process, r.Event.Payload
	if !q.IsCreate || p.PID <= 0 || p.PID != q.NewProcessID || p.ParentPID != q.ParentProcessID || p.ImagePath == "" || p.ImagePath != q.ImagePath || !strings.HasSuffix(p.ImagePath, ".exe") && !strings.HasSuffix(p.ImagePath, ".EXE") || p.IntegrityLevel != q.IntegrityLevel || p.IsElevated != q.IsElevated {
		return fmt.Errorf("inconsistent process/payload for %s", r.Event.ID)
	}
	if (p.CommandLine == nil) != (q.CommandLine == nil) || p.CommandLine != nil && *p.CommandLine != *q.CommandLine {
		return fmt.Errorf("inconsistent command line for %s", r.Event.ID)
	}
	return nil
}
