# Synthetic Hunt exercise — verification

Completed locally on 2026-10-04. No exercise records were ingested into the lab. This report is intentionally spoiler-free; the separate facilitator directory contains conclusions and the solved walkthrough.

## Checkout and preservation

- Repository: AkesoSIEM repository root (all paths below are relative).
- Branch: `main`
- Base/final HEAD: `f3657b2cb92d3f2fc9f24a1ee0d9afd57f6cd94f`
- No `AGENTS.md` was found in the repository or inspected ancestors.
- The existing dirty tree included accepted Hunt, picker, Rules/severity and unrelated work. SHA-256 comparison verified **38/38 pre-existing non-log modified/untracked files unchanged**. Active logs were not edited.
- The old generator, scenarios, entities, profiles, rules, mappings and production Go/UI code were not changed. Only the new `tools/hunt_exercise/` directory was added. Ignored local test logs/baseline snapshots were written under `web/build/exports/`.

## Contract inspection

Inspected the real ingest listener and pipeline; normalization engine, registry and EDR parser; ECS structs and index template; rule YAML, logsource mapping and rule engine; query lexer/parser/translator/API time bounds; Hunt's page-size/projection/aggregation behavior; and the Alerts detail route.

The generator emits the current raw EDR envelope rather than ECS: `source_type=akeso_edr`, `schema=akesoedr/v1`, outer host/agent ID/timestamp and inner event ID/timestamp/source/process/payload. It uses only supported DriverProcess creation payloads. The real normalizer preserves the original raw object, maps full executable paths and parent context, and omits genuinely absent command lines/SIDs. It does not promote raw source IDs or agent IDs into searchable ECS identity fields. `source_type` is excluded from stored JSON, and raw is mapped with `enabled:false`.

The production parser currently falls back to the current time on invalid timestamps. This tool rejects invalid or non-canonical UTC input/envelope timestamps before normalization; production behavior is unchanged.

The candidate rule was loaded from the actual YAML and compiled with the repository logsource map. Local evaluation and the in-process ingest pipeline produced the expected seed alert with the correct source evidence and high severity. This does not prove the running instance has loaded/fired it, nor that other rules cannot match.

## New files

All paths below are relative to `tools/hunt_exercise/` (26 new files):

| Files | Purpose |
| --- | --- |
| `main.go`, `generate.go`, `materials.go` | Local-only generator, validation, deterministic records and per-run material rendering. |
| `exercise_test.go` | Focused isolation, normalization, ingestion, rule and query checks. |
| `README.md`, `VERIFICATION.md` | Entry point, exact commands, scope and results. |
| `templates/ANALYST-BRIEF.md`, `templates/GUIDE.md`, `templates/WORKSHEET.md`, `templates/PREPARE.md` | Analyst workflow and deliberate later preparation instructions. |
| `templates/ANSWER-KEY.md`, `templates/SOLVED-WALKTHROUGH.md` | Separate facilitator material templates. |
| `example/events.ndjson` | One 400-record synthetic raw NDJSON example. |
| `example/run.json`, `example/queries.json` | Inputs, digest, counts, neutral host names, UTC windows and copy-ready query catalog. |
| `example/collision-request.json`, `example/records-request.json`, `example/seed-alert-request.json`, `example/path-request.json` | Serialized JSON request bodies; not Hunt text. |
| `example/ANALYST-BRIEF.md`, `example/GUIDE.md`, `example/WORKSHEET.md`, `example/PREPARE.md` | Generated run-specific analyst/preparation documents. |
| `example/facilitator/manifest.json`, `example/facilitator/ANSWER-KEY.md`, `example/facilitator/SOLVED-WALKTHROUGH.md` | Private normalized expectations, answer key and solved walkthrough; keep closed during the exercise. |

Example inputs: seed `73`, UTC start `2026-10-04T12:00:00Z`, run ID `I2604A`.

NDJSON size: **333,696 bytes**, exactly **400 records**.

SHA-256: `3e8a63d027a24e49988b819139f28aa24183742e0e8fae4c7325ec8dadc2608a`.

## Executed commands and results

All Go commands ran from the repository root with the installed **Go 1.25.5 windows/amd64**, with dependency downloads disabled:

```powershell
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
```

The initial sandbox attempt could not access the installed SDK/build cache. The same local work ran successfully with SDK/cache access through the approval mechanism; no dependency installation or live network operation was introduced.

Generation was executed with:

```powershell
go run ./tools/hunt_exercise --seed 73 --start 2026-10-04T12:00:00Z --run-id I2604A --out tools/hunt_exercise/example
```

After tightening SYSTEM process-context consistency, the final bundle was generated into the new ignored `web/build/exports/hunt-exercise-final-example` directory and copied only over this task's new example files. Final tests verify every one of the 14 example artifacts exactly matches regenerated bytes. The generator itself refuses existing output directories.

To generate an additional local copy without overwriting the example, the exact command is:

```powershell
go run ./tools/hunt_exercise --seed 73 --start 2026-10-04T12:00:00Z --run-id I2604A --out tools/hunt_exercise/run-I2604A
```

Do not ingest both copies; they represent the same run. For another actual ingestion, use a new run ID and perform the collision check first.

| Executed check | Result |
| --- | --- |
| `go test ./tools/hunt_exercise -count=1 -v` | **PASS**, 12 top-level tests, zero failures/skips, final package time 1.250 s. |
| `go vet ./tools/hunt_exercise` | **PASS**, exit 0, no diagnostics. |
| `go test ./internal/normalize/... ./internal/query ./internal/correlate ./internal/ingest -count=1 -json` | **FAIL overall**, 762 top-level tests passed, 2 failed, zero skips. Details below. |
| PowerShell `Language.Parser.ParseInput` over all six generated/README PowerShell blocks | **PASS**; syntax parsed only. No preparation/ingestion commands executed. |
| `gofmt -l` for the four new Go files | **PASS**, no unformatted paths. |
| `git diff --check` | **PASS**, existing LF/CRLF notices only; new Go files also checked with gofmt and generated documents checked for unresolved template markers. |
| Preservation snapshot comparison | **PASS**, 38/38 pre-existing non-log changed/untracked files byte-identical. |

The 12 focused tests verify:

1. Deterministic bytes for all generated artifacts, digest/framing and input-sensitive IDs.
2. Required CLI inputs and invalid/non-UTC timestamp/run-ID/seed rejection.
3. Invalid envelope timestamps and conflicting process/payload fields rejected before normalization.
4. Refusal to overwrite and absence of any ingest option.
5. Host/PID/parent-path/time coherence, consistent SYSTEM context, background name matches and no answer labels in telemetry.
6. Actual EDR normalization for all 400 records; exact raw preservation, host/path/parent/timestamp/SID values and genuine missing fields.
7. Actual HTTP ingest route → normalizer → pipeline → candidate rule, using `httptest.NewRecorder` and an in-memory indexer; stored event/alert objects checked beyond HTTP 202. No live server or Elasticsearch client participates.
8. **18 catalog queries**, all **16 embedded Hunt blocks**, and all four JSON request examples through the actual parser/translator; Windows path value survives both Hunt and JSON layers.
9. Exact fixture pivot counts and boundary event IDs using a deliberately limited test-only AST evaluator. This is not claimed as an Elasticsearch integration test.
10. Real query API handler retains each user filter and applies `gte`/`lt` time bounds with a capture-only searcher.
11. Every documented field exists in the real mapping template; source/raw searchability limits confirmed.
12. Every generated example artifact matches the generator byte for byte.

Broader backend results (top-level tests, subtests not double-counted):

| Package | Passed | Failed | Skipped | Time |
| --- | ---: | ---: | ---: | ---: |
| `internal/normalize` | 7 | 0 | 0 | 0.055 s |
| `internal/normalize/parsers` | 241 | 0 | 0 | 0.226 s |
| `internal/query` (includes existing Hunt checks) | 132 | 0 | 0 | 0.286 s |
| `internal/correlate` | 300 | 1 | 0 | 1.037 s |
| `internal/ingest` | 82 | 1 | 0 | 4.189 s |

The two failures are in unchanged existing tests/code/data; `git diff HEAD -- internal/ingest internal/correlate rules parsers` is empty:

- `TestLoadAllProjectRules`, `internal/correlate/sigma_parser_test.go:1159`: expects 50 curated rules, but the existing directory loads 52.
- `TestDLQDefaultPrefix`, `internal/ingest/dead_letter_test.go:176`: compares an eight-character slice `idx[:8]` with the five-character string `"akeso"`; the test index was correctly `akeso-dlq-2026.10.04`, so that assertion cannot pass. No repair made.

The full backend JSON test log is in the ignored local file `web/build/exports/hunt-exercise-backend-tests.jsonl`.

## Limits and unperformed live checks

- No lab ingestion, collision query, live mapping read, loaded-engine check, indexed-record comparison or running seed-alert check was performed. PREPARE.md provides those later deliberate steps, using existing authentication without embedded secrets. Collision queries intentionally omit time bounds.
- A Rules API listing does not prove a running ingest engine's loaded state. Existing logs can indicate load/skip errors; an indexed seed alert tied to this new run is the firing confirmation. The guide does not assume this is the only matching rule.
- Deterministic raw IDs are **not** ES deduplication keys. Replay can store duplicates; HTTP 202 or alert deduplication does not make replay safe. On an ambiguous ingest response, repeat reads, not ingestion.
- The exercise is a designed 30–45-minute manual workflow, not a measured user study. Preparation time is separate. It contains process-only synthetic observations, not additional forensic sources or proof of causation.
- Runtime mappings, retention, available privileges and UI limits still need the preparation checks. No attempt was made to repair the Alerts list's historical window or any unrelated component.
- Frontend browser/build tests were not rerun: this batch changes no frontend or backend runtime implementation. Existing query/backend tests were run as detailed above. No deployment/binary replacement, live integration suite or whole-repository test run was performed.
- No services restarted, configuration/credentials changed, dependencies installed, data deleted, cases created, commits made or code pushed/deployed.

First preparation step: open `example/PREPARE.md`, confirm the receipt/digest, then run its read-only collision check with existing authentication. Keep the facilitator material closed until your assessment is finished.
