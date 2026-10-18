# Contributing to AkesoSIEM

Start with a focused issue or pull request that explains the observed problem, expected behavior, and a reproducible example. Keep changes small enough to review. Retain upstream attribution and license notices.

## Local checks

Run from the repository root, using a clean dependency installation:

```sh
go build ./...
go vet ./...
go test -race -timeout 5m ./cmd/... ./internal/... ./parsers/... ./tests/integration/...
go test ./tests/benchmark -run TestLoadTest -timeout 2m -loadduration 10s
cd web && npm ci && npm run build
```

See [the CI workflow](.github/workflows/ci.yml) for operating system and runtime versions. Windows projects require Visual Studio 2022 C++ build tools; kernel-driver testing additionally requires a separate authorized Windows lab and the WDK. AkesoNDR requires libpcap development headers. Python checks use Python 3.12; Node checks use Node 24.

## Pull request evidence

CI runs a ten-second ingest load smoke test. The sustained ten-minute benchmark is a separate local check: `go test ./tests/benchmark -run TestLoadTest -timeout 15m`. A smoke test is not a sustained throughput result.

Describe what changed, why, and which commands passed. State skipped checks and environment limitations explicitly. A passing unit test or frontend build does not establish production readiness, live connector behavior, or kernel-driver coverage. Include regression coverage for changed behavior when practical.

Use synthetic fixtures and redact logs. For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of posting exploit details publicly. Attribute AI-assisted work and third-party code accurately; review and validate generated changes before submitting them.
