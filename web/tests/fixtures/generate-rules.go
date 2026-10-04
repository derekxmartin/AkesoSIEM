//go:build ignore

// Run from the repository root:
// go run web/tests/fixtures/generate-rules.go
// Calls the real read-only handler in memory; never connects to the lab.
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"

	"github.com/derekxmartin/akeso-siem/internal/rules"
)

func main() {
	w := httptest.NewRecorder()
	rules.NewHandler("rules", "").HandleList(w, httptest.NewRequest("GET", "/api/v1/rules", nil))
	var response any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		panic(err)
	}
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("web/tests/fixtures/rules-api.json", append(data, '\n'), 0644); err != nil {
		panic(err)
	}
}
