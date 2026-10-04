# One manual Hunt exercise

This is a separate EDR-only, local file generator for a 30–45-minute interview exercise. It demonstrates the manual work between an alert and an evidence-backed endpoint assessment. It does not run the depicted commands, create executable files, connect to the SIEM, ingest data, change rules or create cases. The old `tools/generate_scenarios.py`, entity files and scenarios remain untouched.

Start with [example/PREPARE.md](example/PREPARE.md). Its **first operation is a read-only, all-time collision check** on the exact run hosts, using existing authentication. The 400-record example has not been ingested. HTTP 202 alone will not prove success; preparation includes indexed-record and seed-alert checks after a later deliberate user ingestion step. Replays can duplicate events even though raw IDs are deterministic.

After preparation, open the [spoiler-free analyst brief](example/ANALYST-BRIEF.md), [hands-on guide](example/GUIDE.md) and [worksheet](example/WORKSHEET.md). Keep `example/facilitator/` closed until you have written your assessment; it contains the manifest, answer key and solved walkthrough. Neither answers nor classifications appear in telemetry.

## Generate locally

From the repository root, using the installed Go toolchain and cached module dependencies:

```powershell
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
go run ./tools/hunt_exercise --seed 73 --start 2026-10-04T12:00:00Z --run-id I2604A --out tools/hunt_exercise/run-I2604A
```

The output directory must be new; its parent must already exist. The checked example used the identical inputs with `--out tools/hunt_exercise/example`. Identical inputs produce identical file bytes, including event IDs, irrespective of output directory. Copying a bundle is not permission to ingest the same run again. Choose a fresh run ID before any later replay and check for collisions. For another date, supply an explicit valid UTC start within the lab's existing retention; regenerate the whole bundle, never edit timestamps by hand.

All four flags are required. `--seed` is an unsigned integer (zero is valid); `--start` is second-resolution UTC ending in `Z`; `--run-id` is 1–8 uppercase letters/digits. Names are `SYN-<run ID>-01` through `-04`, at most 15 characters. The generator does not load configuration or credentials. It validates its envelope timestamps before calling the real EDR normalizer; it does not repair that parser's current invalid-timestamp fallback.

## Files and contract

- `main.go`, `generate.go`: explicit CLI, fixed bounded scenario, raw DriverProcess envelopes, deterministic SHA-derived choices/IDs, timestamp/context validation, refuse overwrite.
- `materials.go`, `templates/*.md`: render per-run analyst/facilitator materials and copy-ready queries. All emitted Hunt expressions are parsed and translated by the current backend before any output directory is created.
- `exercise_test.go`: isolated contract and end-to-end in-process tests, including an actual ingest router and pipeline with an in-memory indexer. No test contacts Elasticsearch or a running lab service.
- `example/events.ndjson`: the only generated telemetry file to ingest. `run.json` is a spoiler-free receipt with inputs/digest/counts/hosts/ranges; `queries.json` and four `*-request.json` files distinguish Hunt text from serialized HTTP bodies.
- `example/facilitator/manifest.json`: exact expected normalized values for all records and private labels, alongside the separate answer key and solved walkthrough.

The event envelope has `source_type=akeso_edr`, `schema=akesoedr/v1`, outer `host/agent_id/timestamp` and inner `eventId/timestamp/source/process/payload`. The supported source is `DriverProcess`, with consistent creation payload and process context. All timestamps are explicit; missing command lines are omitted from both context and payload. No ECS documents, detection labels, hashes or network evidence are invented in the raw stream.

Only mapped fields are used for searches: `host.name`, `process.executable`, process/parent names and PIDs, `user.id`, `@timestamp`, and rule/event fields for the separate alert check. Raw and agent IDs remain inspectable in raw; `source_type` is a routing field, not a stored query field. The guide preserves Windows path escaping and does not treat projections/aggregates as full evidence records.

## Local checks

```powershell
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
go test ./tools/hunt_exercise -count=1 -v
go vet ./tools/hunt_exercise
go test ./internal/normalize/... ./internal/query ./internal/correlate ./internal/ingest -count=1
```

See [VERIFICATION.md](VERIFICATION.md) for executed results and unperformed live checks. No dependency upgrades, production changes, services, navigation, agents or additional scenarios belong to this batch.
