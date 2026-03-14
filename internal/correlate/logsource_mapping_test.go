package correlate

import (
	"os"
	"testing"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
)

const testLogsourceMap = `
mappings:
  - logsource:
      product: sentineledr
    conditions:
      source_type: sentineledr

  - logsource:
      product: sentinel_av
    conditions:
      source_type: sentinel_av

  - logsource:
      product: sentinel_dlp
    conditions:
      source_type: sentinel_dlp

  - logsource:
      category: malware
    conditions:
      event.category: malware

  - logsource:
      category: process_creation
    conditions:
      event.category: process
      event.type: start

  - logsource:
      category: network_connection
    conditions:
      event.category: network
      event.type: connection

  - logsource:
      category: file_event
    conditions:
      event.category: file

  - logsource:
      product: windows
      service: security
    conditions:
      source_type: winevt
      winevt.channel: Security

  - logsource:
      product: windows
      service: sysmon
    conditions:
      source_type: winevt
      winevt.channel: Microsoft-Windows-Sysmon/Operational
`

func loadTestMap(t *testing.T) *LogsourceMap {
	t.Helper()
	lm, err := ParseLogsourceMap([]byte(testLogsourceMap))
	if err != nil {
		t.Fatalf("ParseLogsourceMap failed: %v", err)
	}
	return lm
}

func TestParseLogsourceMap(t *testing.T) {
	lm := loadTestMap(t)
	if lm.MappingCount() != 9 {
		t.Errorf("MappingCount() = %d, want 9", lm.MappingCount())
	}
}

func TestParseEmptyMappings(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`mappings: []`))
	if err == nil {
		t.Error("expected error for empty mappings")
	}
}

func TestParseNoLogsourceFields(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`
mappings:
  - logsource: {}
    conditions:
      source_type: test
`))
	if err == nil {
		t.Error("expected error for mapping with no logsource fields")
	}
}

func TestParseNoConditions(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`
mappings:
  - logsource:
      product: test
    conditions: {}
`))
	if err == nil {
		t.Error("expected error for mapping with no conditions")
	}
}

func TestResolveProductSentinelAV(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "sentinel_av", "")
	if conds == nil {
		t.Fatal("expected conditions for product: sentinel_av")
	}
	if conds["source_type"] != "sentinel_av" {
		t.Errorf("source_type = %q, want sentinel_av", conds["source_type"])
	}
}

func TestResolveProductSentinelDLP(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "sentinel_dlp", "")
	if conds == nil {
		t.Fatal("expected conditions for product: sentinel_dlp")
	}
	if conds["source_type"] != "sentinel_dlp" {
		t.Errorf("source_type = %q, want sentinel_dlp", conds["source_type"])
	}
}

func TestResolveProductSentinelEDR(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "sentineledr", "")
	if conds == nil {
		t.Fatal("expected conditions for product: sentineledr")
	}
	if conds["source_type"] != "sentineledr" {
		t.Errorf("source_type = %q, want sentineledr", conds["source_type"])
	}
}

func TestResolveCategoryMalware(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("malware", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: malware")
	}
	if conds["event.category"] != "malware" {
		t.Errorf("event.category = %q, want malware", conds["event.category"])
	}
}

func TestResolveCategoryProcessCreation(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("process_creation", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: process_creation")
	}
	if conds["event.category"] != "process" {
		t.Errorf("event.category = %q, want process", conds["event.category"])
	}
	if conds["event.type"] != "start" {
		t.Errorf("event.type = %q, want start", conds["event.type"])
	}
}

func TestResolveProductServiceWindowsSecurity(t *testing.T) {
	lm := loadTestMap(t)
	// product+service is more specific than product alone.
	conds := lm.Resolve("", "windows", "security")
	if conds == nil {
		t.Fatal("expected conditions for product: windows, service: security")
	}
	if conds["source_type"] != "winevt" {
		t.Errorf("source_type = %q, want winevt", conds["source_type"])
	}
	if conds["winevt.channel"] != "Security" {
		t.Errorf("winevt.channel = %q, want Security", conds["winevt.channel"])
	}
}

func TestResolveProductServiceWindowsSysmon(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "windows", "sysmon")
	if conds == nil {
		t.Fatal("expected conditions for product: windows, service: sysmon")
	}
	if conds["winevt.channel"] != "Microsoft-Windows-Sysmon/Operational" {
		t.Errorf("winevt.channel = %q", conds["winevt.channel"])
	}
}

func TestResolveNoMatch(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "unknown_product", "")
	if conds != nil {
		t.Errorf("expected nil for unknown product, got %v", conds)
	}
}

func TestResolveSpecificityPriority(t *testing.T) {
	// product+service (score 2) should beat product alone (score 1).
	lm := loadTestMap(t)
	conds := lm.Resolve("", "windows", "security")
	if conds == nil {
		t.Fatal("expected match")
	}
	// Should pick the product+service mapping, not just product.
	if conds["winevt.channel"] != "Security" {
		t.Errorf("expected specific mapping, got %v", conds)
	}
}

func TestResolveAllCategoryMalware(t *testing.T) {
	lm := loadTestMap(t)
	// category: malware should return only the malware mapping.
	results := lm.ResolveAll("malware", "", "")
	if len(results) != 1 {
		t.Fatalf("expected 1 result for category: malware, got %d", len(results))
	}
	if results[0]["event.category"] != "malware" {
		t.Errorf("expected event.category: malware, got %v", results[0])
	}
}

// --- Event matching tests ---

func TestMatchesEventAVScanResult(t *testing.T) {
	// An AV malicious scan result should match both product:sentinel_av AND category:malware.
	lm := loadTestMap(t)

	avEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentinel_av",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"malware"},
			Type:     []string{"info"},
			Action:   "scan_result",
		},
	}

	// Should match product: sentinel_av conditions.
	productConds := lm.Resolve("", "sentinel_av", "")
	if !MatchesEvent(productConds, avEvent) {
		t.Error("AV event should match product: sentinel_av conditions")
	}

	// Should also match category: malware conditions.
	categoryConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(categoryConds, avEvent) {
		t.Error("AV malware event should match category: malware conditions")
	}
}

func TestMatchesEventEDRMalwareDetection(t *testing.T) {
	// An EDR scanner detection (event.category: malware) should match category:malware.
	lm := loadTestMap(t)

	edrEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentineledr",
		Event: &common.EventFields{
			Kind:     "alert",
			Category: []string{"malware"},
			Type:     []string{"info"},
			Action:   "scanner_match",
		},
	}

	// Should match category: malware.
	categoryConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(categoryConds, edrEvent) {
		t.Error("EDR malware detection should match category: malware conditions")
	}

	// Should NOT match product: sentinel_av.
	avConds := lm.Resolve("", "sentinel_av", "")
	if MatchesEvent(avConds, edrEvent) {
		t.Error("EDR event should NOT match product: sentinel_av conditions")
	}
}

func TestMatchesEventDLPPolicyViolation(t *testing.T) {
	lm := loadTestMap(t)

	dlpEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentinel_dlp",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"file"},
			Type:     []string{"access"},
			Action:   "violation",
		},
	}

	// Should match product: sentinel_dlp.
	dlpConds := lm.Resolve("", "sentinel_dlp", "")
	if !MatchesEvent(dlpConds, dlpEvent) {
		t.Error("DLP event should match product: sentinel_dlp conditions")
	}

	// Should match category: file_event.
	fileConds := lm.Resolve("file_event", "", "")
	if !MatchesEvent(fileConds, dlpEvent) {
		t.Error("DLP file event should match category: file_event conditions")
	}

	// Should NOT match product: sentinel_av.
	avConds := lm.Resolve("", "sentinel_av", "")
	if MatchesEvent(avConds, dlpEvent) {
		t.Error("DLP event should NOT match product: sentinel_av conditions")
	}
}

func TestMatchesEventProcessCreation(t *testing.T) {
	lm := loadTestMap(t)

	procEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentineledr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
	}

	// Should match category: process_creation.
	procConds := lm.Resolve("process_creation", "", "")
	if !MatchesEvent(procConds, procEvent) {
		t.Error("process start event should match category: process_creation")
	}

	// Should NOT match category: malware.
	malwareConds := lm.Resolve("malware", "", "")
	if MatchesEvent(malwareConds, procEvent) {
		t.Error("process event should NOT match category: malware")
	}
}

func TestMatchesEventCrossProductMalware(t *testing.T) {
	// The key acceptance criteria: category:malware matches BOTH AV and EDR malware events.
	lm := loadTestMap(t)
	categoryConds := lm.Resolve("malware", "", "")

	avMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentinel_av",
		Event: &common.EventFields{
			Category: []string{"malware"},
			Type:     []string{"info"},
		},
	}

	edrMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentineledr",
		Event: &common.EventFields{
			Category: []string{"malware"},
			Type:     []string{"info"},
		},
	}

	nonMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentinel_dlp",
		Event: &common.EventFields{
			Category: []string{"file"},
			Type:     []string{"access"},
		},
	}

	if !MatchesEvent(categoryConds, avMalware) {
		t.Error("AV malware event should match category: malware")
	}
	if !MatchesEvent(categoryConds, edrMalware) {
		t.Error("EDR malware event should match category: malware")
	}
	if MatchesEvent(categoryConds, nonMalware) {
		t.Error("DLP file event should NOT match category: malware")
	}
}

func TestMatchesEventNilEvent(t *testing.T) {
	conditions := map[string]string{"event.category": "malware"}
	event := &common.ECSEvent{
		Timestamp: time.Now().UTC(),
	}
	if MatchesEvent(conditions, event) {
		t.Error("event with nil Event field should not match event.category condition")
	}
}

func TestMatchesEventMultiCategoryEvent(t *testing.T) {
	// An event with multiple categories (e.g., ["process", "malware"]) should
	// match BOTH category:process_creation and category:malware logsources.
	lm := loadTestMap(t)

	multiCatEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentineledr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process", "malware"},
			Type:     []string{"start"},
		},
	}

	// Should match category: process_creation (has "process" in category + "start" in type).
	procConds := lm.Resolve("process_creation", "", "")
	if !MatchesEvent(procConds, multiCatEvent) {
		t.Error("multi-category event with [process, malware] should match process_creation")
	}

	// Should also match category: malware (has "malware" in category).
	malwareConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(malwareConds, multiCatEvent) {
		t.Error("multi-category event with [process, malware] should match malware")
	}
}

func TestResolveCategoryAndProduct(t *testing.T) {
	// A Sigma rule specifying both category AND product should require both to match.
	// Add a mapping that has category+product for this test.
	yaml := `
mappings:
  - logsource:
      product: sentinel_av
    conditions:
      source_type: sentinel_av

  - logsource:
      category: malware
    conditions:
      event.category: malware

  - logsource:
      category: malware
      product: sentinel_av
    conditions:
      source_type: sentinel_av
      event.category: malware
`
	lm, err := ParseLogsourceMap([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseLogsourceMap failed: %v", err)
	}

	// category:malware + product:sentinel_av should pick the most specific (score 2) mapping.
	conds := lm.Resolve("malware", "sentinel_av", "")
	if conds == nil {
		t.Fatal("expected match for category:malware + product:sentinel_av")
	}
	// Should have both conditions from the specific mapping.
	if conds["source_type"] != "sentinel_av" {
		t.Errorf("source_type = %q, want sentinel_av", conds["source_type"])
	}
	if conds["event.category"] != "malware" {
		t.Errorf("event.category = %q, want malware", conds["event.category"])
	}

	// AV malware event should match this combined condition.
	avMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentinel_av",
		Event: &common.EventFields{
			Category: []string{"malware"},
		},
	}
	if !MatchesEvent(conds, avMalware) {
		t.Error("AV malware event should match combined category+product conditions")
	}

	// EDR malware event should NOT match (wrong source_type).
	edrMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "sentineledr",
		Event: &common.EventFields{
			Category: []string{"malware"},
		},
	}
	if MatchesEvent(conds, edrMalware) {
		t.Error("EDR malware event should NOT match sentinel_av+malware conditions")
	}
}

func TestResolveReturnsCopy(t *testing.T) {
	// Mutating the returned map should not affect internal state.
	lm := loadTestMap(t)

	conds1 := lm.Resolve("", "sentinel_av", "")
	if conds1 == nil {
		t.Fatal("expected conditions")
	}

	// Mutate the returned map.
	conds1["source_type"] = "MUTATED"

	// Resolve again — should get the original value.
	conds2 := lm.Resolve("", "sentinel_av", "")
	if conds2["source_type"] != "sentinel_av" {
		t.Errorf("mutation leaked: source_type = %q, want sentinel_av", conds2["source_type"])
	}
}

func TestLoadLogsourceMapFromFile(t *testing.T) {
	// Write a temp file and load it.
	tmpFile := t.TempDir() + "/logsource_map.yaml"
	if err := os.WriteFile(tmpFile, []byte(testLogsourceMap), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	lm, err := LoadLogsourceMap(tmpFile)
	if err != nil {
		t.Fatalf("LoadLogsourceMap failed: %v", err)
	}

	if lm.MappingCount() != 9 {
		t.Errorf("MappingCount() = %d, want 9", lm.MappingCount())
	}
}

func TestLoadLogsourceMapFileNotFound(t *testing.T) {
	_, err := LoadLogsourceMap("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
