package rules

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func listRules(t *testing.T, dir string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	NewHandler(dir, "").HandleList(w, httptest.NewRequest("GET", "/api/v1/rules", nil))
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestListPreservesAllTactics(t *testing.T) {
	dir := t.TempDir()
	data := "title: Multiple tactics\nid: multi\nlevel: high\ntags: [attack.execution, attack.credential_access, attack.execution, attack.t1003]\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n"
	if err := os.WriteFile(filepath.Join(dir, "multi.yml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	response := listRules(t, dir)
	rule := response["rules"].([]any)[0].(map[string]any)
	want := []any{"execution", "credential_access"}
	if !reflect.DeepEqual(rule["tactics"], want) {
		t.Errorf("tactics = %v, want %v", rule["tactics"], want)
	}
	if rule["tactic"] != "execution" || rule["techniqueId"] != "t1003" {
		t.Errorf("legacy fields changed: %v", rule)
	}
}

func TestListProjectRulesMatchesBrowserFixture(t *testing.T) {
	response := listRules(t, filepath.Join("..", "..", "rules"))
	rules := response["rules"].([]any)
	ids := make(map[string]bool)
	for _, value := range rules {
		rule := value.(map[string]any)
		id := rule["id"].(string)
		if id == "" || ids[id] {
			t.Fatalf("empty or duplicate rule ID %q", id)
		}
		ids[id] = true
	}
	if len(ids) != 107 || response["total"] != float64(107) {
		t.Fatalf("got %d IDs, total %v; want 107", len(ids), response["total"])
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "rules-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(response, fixture) {
		t.Fatal("browser fixture differs from the real Rules API; regenerate with go run web/tests/fixtures/generate-rules.go")
	}
}
