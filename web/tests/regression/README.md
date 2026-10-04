# Isolated Hunt and Rules/severity regressions

The current suite contains 44 browser cases: 20 Hunt query/evidence/refresh checks, 4 absolute-picker checks, 16 Rules/severity/escalation checks, and 4 desktop/narrow layout checks. It uses synthetic event fixtures and the in-memory Rules API fixture. All API requests are intercepted; the static server has no connection to the live SIEM.

Run `npm run test:regression` from `web` to build and test. On Windows with installed Edge, set `PLAYWRIGHT_CHANNEL=msedge`; otherwise use the installed Playwright Chromium. Run `node --test web/tests/unit/hunt.test.mjs` from the repository root for the four helper tests. Backend Hunt coverage is in `internal/query` and `cmd/akeso-query`; Rules handler coverage is in `internal/rules`. The exercise generator has its own isolated tests and documentation under `tools/hunt_exercise`.

Artifacts and local verification reports belong under ignored `web/build/`. Do not add screenshots or raw responses from real endpoints to these fixtures. Historical verification notes below document earlier batches; their counts describe those runs, not the current full suite.

## Historical Rules/severity verification

Follow-up verification on 2026-10-03: unsupported case escalation guard.

Informational and Unknown keep their normalized labels. Alert details now show a visible explanation that case escalation does not support that severity yet, and the Escalate to Case button is disabled with an accessible description. The handler normalizes the severity and returns before its first optimistic update or network request for either unsupported value. The case API's accepted severities are unchanged.

Follow-up files changed: `web/src/pages/Alerts.jsx`, `web/src/components/AlertFlyout.jsx`, `web/tests/regression/rules-severity.spec.ts`, and this README. The earlier batch and unrelated working-tree changes were preserved. Historical branch: `main`; HEAD `f3657b2cb92d3f2fc9f24a1ee0d9afd57f6cd94f`.

Commands and results for this follow-up:

- From `web`, `$env:PLAYWRIGHT_CHANNEL = 'msedge'; npm.cmd run test:regression -- --grep 'escalation is blocked|disabled escalation'`: before the guard, all 5 selected assertions failed (enabled action or missing explanation).
- From `web`, `$env:PLAYWRIGHT_CHANNEL = 'msedge'; npm.cmd run test:regression`: after the guard, the production build passed (6.89s) and all 16 browser tests passed (16.1s), with zero skips.
- From the repository root, `go test ./internal/rules -count=1 -v`: both existing handler regressions passed (0.051s), with zero skips.
- `git diff --check`: passed.

The browser suite still checks all 107 rule IDs and all severity normalizations. Four guard cases cover Informational/Unknown opened from the list and via a direct ID absent from the list. They verify a visible explanation, disabled action, accessible description, unchanged New/Acknowledged status, and ZERO alert PATCH and case POST requests after attempted pointer clicks. Both request-level observation and the API interceptor's recorded writes must be empty. Supported levels 2–5 retain enabled escalation, correctly normalized case payloads, and the existing escalated status update. The handler's independent early return was also inspected to confirm it precedes `updateAlertStatus` and `api.post`.

Remaining limitations: this guard does not fix supported-severity transaction ordering. Low/Medium/High/Critical still optimistically mark the alert escalated and send the alert PATCH before case creation; case rejection can still leave an escalated alert without a case. The existing handler also remains a no-op for a directly fetched supported alert absent from the loaded list. No alert rollback, case API, or direct-detail escalation repair was included. Existing bundle-size and auth-store import warnings remain; no frontend lint script/config is configured. Broader Go/lab/integration/replay/load suites were not rerun for this frontend-only follow-up; their earlier results are recorded below.

No live data changes, service restarts, dependency updates, commits, pushes, or deployment were performed. No Hunt work was started. Previously exported report/patch files remain historical snapshots of the initial batch and were not regenerated.

The record below describes the initial Rules/severity batch; the follow-up results above supersede its unsupported-escalation behavior.

These regressions cover only Rules listing and alert severity conversion.

Run from the repository root:

```powershell
go test ./internal/rules -count=1 -v
```

Run the browser suite from `web`:

```powershell
$env:PLAYWRIGHT_CHANNEL = 'msedge' # Installed Edge on Windows; omit for Playwright Chromium.
npm.cmd run test:regression
```

The browser command builds the production UI and starts a temporary static server on `127.0.0.1:4179`. It refuses to reuse an existing server. Every API call is intercepted, unexpected external requests are blocked, and the server has no API proxy. Authentication uses a fake token inside an isolated browser context. Escalation tests inspect intercepted request bodies; they do not create cases or change alerts in the lab. Test output goes under the ignored `web/build` directory.

The Rules fixture is the actual JSON returned by `internal/rules/Handler.HandleList`, invoked in memory over the repository's rules. The Go regression verifies that the fixture still matches the handler and contains exactly 107 unique IDs. To regenerate it intentionally, run `go run web/tests/fixtures/generate-rules.go` from the repository root. No running service is involved.

The browser assertions cover:

- All 107 unique rule IDs rendered with cleared filters and restored after filtering.
- Canonical tactic grouping, per-group counts, multiple memberships, duplicate rule IDs, and unknown/missing/null/empty tactics.
- Disabled rule controls and separate empty, failed, and malformed API response states.
- Numeric severities 1–5 in list, filters, and detail, including High/Critical border styling; supported levels 2–5 in existing escalation request bodies.
- Numeric strings, case-insensitive names, whitespace, rule-field fallback, invalid/missing values, conflicting fields, and detail fetched directly by ID.

Severity policy: valid `event.severity` wins over `rule.severity`. Missing or invalid event severity falls back to a valid rule severity; otherwise the result is `unknown`. The producer scale is 1 informational, 2 low, 3 medium, 4 high, 5 critical. The same normalized value feeds filters, detail, badges, and escalation payloads.

Before the initial fixes, the browser suite had **12 failures and 1 pass**; numeric 4/5 failed their High/Critical assertions. The handler regression failed with `tactics = <nil>, want [execution credential_access]`. After the initial fixes, **13 browser tests and both handler tests passed**.

Initial-batch verification on 2026-10-03 at baseline `f3657b2cb92d3f2fc9f24a1ee0d9afd57f6cd94f`:

- `go test ./internal/rules -count=1 -v`: both tests passed (0.115s).
- In `web`, `$env:PLAYWRIGHT_CHANNEL = 'msedge'; npm.cmd run test:regression`: production build passed (19.71s), then all 13 tests passed (24.0s), zero skips. Build warnings about the large bundle and mixed static/dynamic auth-store imports also occurred before the fixes.
- `go vet ./...`: passed (the Makefile's lint command).
- `go build ./...`: passed.
- `git diff --check`: passed.
- `go test -short ./internal/... ./parsers -count=1`: 14 packages passed, 2 had no tests, and 2 failed due to the existing assertions below. No frontend lint script or ESLint configuration is present, so no frontend lint command was run.
- `go test -short ./internal/correlate ./internal/ingest -run '^(TestLoadAllProjectRules|TestDLQDefaultPrefix)$' -count=1 -v`: reproduced both failures. The affected packages and rule files have no differences from HEAD. `TestLoadAllProjectRules` expects 50 curated rules but finds 52. `TestDLQDefaultPrefix` compares `idx[:8]` with the five-character string `akeso`. Both were left unchanged.
- `go test -short ./internal/store -run '^(TestHealth|TestEnsureTemplate|TestBulkIndexAndSearch|TestUpsertHostScoreIntegration|TestEnsureHostScoreIndexIdempotent)$' -count=1 -v`: all five tests explicitly skipped in short mode, before attempting Elasticsearch access.
- Existing lab-oriented Playwright suites, `tests/integration`, and `tests/benchmark` were not run. No seed, reset, cleanup, or replay scripts were run.

The real fixture has 107 unique IDs and 12 rules with multiple tactics, producing 125 group memberships. Global rule/enabled counts remain 107; per-tactic counts reflect memberships.

Changed files for this work:

- `internal/rules/handler.go`, `internal/rules/handler_test.go`
- `web/src/pages/Rules.jsx`, `web/src/components/RulesList.jsx`, `web/src/lib/rules.js`
- `web/src/pages/Alerts.jsx`, `web/src/components/SeverityBadge.jsx`, `web/src/lib/severity.js`
- `web/package.json`, `web/playwright.regression.config.ts`
- `web/tests/fixtures/generate-rules.go`, `web/tests/fixtures/rules-api.json`
- `web/tests/regression/rules-severity.spec.ts`, `web/tests/regression/serve.mjs`, this README

Existing work in `internal/dashboard/handler.go`, `logs/akeso-ingest.log`, `logs/akeso-query.log`, and the root `package-lock.json` was preserved. Branch and HEAD remain unchanged. No dependencies, detection logic, credentials, schemas, services, or live data were modified. No push, PR, merge, or deployment was performed.

The original batch did not guard case escalation: its backend accepts only low/medium/high/critical and rejects informational/unknown. The follow-up above now blocks these unsupported values before side effects; supported-severity transaction behavior remains unchanged. These isolated tests do not prove successful real case creation. Existing source/coverage/hit-count limitations and detection behavior are unchanged. Full lab-oriented E2E, integration/replay, and load-test suites are not part of these regressions.
