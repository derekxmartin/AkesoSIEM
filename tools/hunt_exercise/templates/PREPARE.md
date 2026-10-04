# Deliberate preparation — {{.RunID}}

**These instructions have not been executed against the lab.** Generating this directory is local-only. Ingestion below is a separate, deliberate user step. Use existing authentication/permissions, running endpoints and index prefix. Do not change configuration, restart services, seed other scenarios, reload rules, delete data or create cases.

First inspect `run.json` and perform the **read-only collision check** below. Keep the facilitator directory closed if you are the investigator. Use a fresh run ID if any records already exist. **Replay can duplicate stored events:** this checkout's `BulkIndex` does not set a document ID. Deterministic raw event IDs do not guarantee Elasticsearch deduplication. Alert deduplication is separate and can suppress alerts without preventing duplicate events. Do not automatically retry ingestion after a timeout or ambiguous response.

## Local preparation already completed by the generator

- Exactly {{.Count}} DriverProcess creation records; SHA-256 `{{.SHA256}}`.
- `source_type=akeso_edr`, `schema=akesoedr/v1`; outer host/agent/timestamp and inner eventId/timestamp/source/process/payload.
- UTC range: {{(window "all").From}} to {{(window "all").To}}, end exclusive.
- Current parser maps executable to `process.executable`, parent context to `process.parent.*`, SID to `user.id`. Raw IDs/agent IDs remain in raw, not searchable ECS identities. Invalid timestamps are rejected by this generator; the existing production parser's fallback is not repaired here.
- Host/time/PID/path and command-line expectations for every event are in the private manifest. No conclusions or expected dispositions are embedded in telemetry.

## 1. Authenticate normally and check for collisions (read-only)

Run PowerShell from this generated directory. Reuse your existing in-memory `$queryHeaders` and `$ingestHeaders`, without displaying or saving them. Query accepts an existing Bearer token or an authorized `X-API-Key`; ingest requires its existing `X-API-Key`. They may differ. The optional helper below reads existing keys without echo; it does not create credentials. Skip it if authenticated headers are already available. Do not paste literal secrets into scripts/history or include them in screenshots.

```powershell
function Read-ExistingApiHeaders {
    param([string]$Prompt)
    $secret = Read-Host $Prompt -AsSecureString
    try { return @{ 'X-API-Key' = ([System.Net.NetworkCredential]::new('', $secret)).Password } }
    finally { $secret.Dispose() }
}
# Optional, only if you do not already have these authenticated headers:
# $queryHeaders = Read-ExistingApiHeaders 'Existing query API key (hidden)'
# $ingestHeaders = Read-ExistingApiHeaders 'Existing ingest API key (hidden)'

$queryBase = (Read-Host 'Existing query API base URL, no trailing /api/v1').TrimEnd('/')
$labIndexPrefix = Read-Host 'Existing configured index prefix (do not change it)'
if (-not $queryHeaders) { throw 'Authenticate with existing query credentials first.' }
$runInfo = Get-Content -Raw run.json | ConvertFrom-Json
$digest = (Get-FileHash -Algorithm SHA256 events.ndjson).Hash.ToLowerInvariant()
if ($digest -ne $runInfo.ndjson_sha256) { throw 'NDJSON digest mismatch.' }
$collisionBody = Get-Content -Raw collision-request.json
$collision = Invoke-RestMethod -Method Post -Uri "$queryBase/api/v1/query" -Headers $queryHeaders -ContentType 'application/json' -Body $collisionBody
if ($collision.total -ne 0) { throw 'Run hosts already have event records. Do NOT ingest; generate a fresh run ID.' }
$alertCollisionBody = $collisionBody | ConvertFrom-Json
$alertCollisionBody | Add-Member -NotePropertyName index -NotePropertyValue "$labIndexPrefix-alerts-*"
$alertCollision = Invoke-RestMethod -Method Post -Uri "$queryBase/api/v1/query" -Headers $queryHeaders -ContentType 'application/json' -Body ($alertCollisionBody | ConvertTo-Json -Depth 20)
if ($alertCollision.total -ne 0) { throw 'Run hosts already have alerts. Do NOT ingest; use a fresh run ID.' }
```

This query intentionally omits time bounds to find older collisions on the exact four host names. It searches existing event/alert indices with your existing permissions. It neither deletes nor reserves anything; recheck immediately before ingestion if time has passed. Permission/API errors are not a clean collision check.

The underlying query is valid Hunt text, but the collision check needs the API request **without** Hunt's mandatory picker restriction:

```hunt
{{q "collision"}}
```

## 2. Check the candidate rule's availability (read-only)

```powershell
$rules = Invoke-RestMethod -Method Get -Uri "$queryBase/api/v1/rules" -Headers $queryHeaders
$candidate = @($rules.rules | Where-Object id -eq $runInfo.candidate_rule_id)
if ($candidate.Count -ne 1) { throw 'Candidate rule not listed. Stop preparation; do not alter detections.' }
$candidate | Select-Object id, name, severity, enabled
```

The local test loads the actual YAML and `parsers/logsource_map.yaml`, compiles the candidate and proves the normalized seed event matches. In the running instance, the Rules API reads disk and reports `enabled=true`; that is **not proof of the ingest engine's loaded state**. Read existing ingest logs for the load summary and any skip/compile errors mentioning the rule ID/title. There is no relied-upon per-rule loaded-state endpoint in this exercise. The decisive firing check is an indexed alert tied to this new run's seed event after ingestion. Do not call the reload endpoint. Other rules may also match these records.

## 3. Ingest once — deliberate user action, not part of generation

Only proceed after both collision queries succeeded with zero, and after deciding you want these 400 synthetic records stored. Choose a start date compatible with your existing lab retention and demo time; do not change retention. The included example is historical and must be queried with its absolute bounds. For a new run, regenerate all materials together using explicit inputs.

```powershell
if (-not $ingestHeaders) { throw 'Supply the existing ingest API key through a hidden prompt first.' }
$ingestBase = (Read-Host 'Existing ingest API base URL, no trailing /api/v1').TrimEnd('/')
$receipt = Invoke-WebRequest -Method Post -Uri "$ingestBase/api/v1/ingest" -Headers $ingestHeaders -ContentType 'application/x-ndjson' -InFile (Resolve-Path events.ndjson).Path
if ([int]$receipt.StatusCode -ne 202) { throw 'No accepted receipt. Inspect before any replay.' }
$accepted = $receipt.Content | ConvertFrom-Json
if ($accepted.accepted -ne $runInfo.count) { throw 'Unexpected accepted count; verify storage before doing anything else.' }
```

The generator has no ingestion flag. HTTP 202 means accepted by the listener, **not** proof of successful normalization, storage or alert generation. A failed/ambiguous request can already have stored events. Do not replay to “make sure.”

## 4. Verify indexed evidence and the seed alert (read-only)

Allow normal indexing visibility, then make the following reads. If counts are temporarily incomplete, repeat these **reads only** after a short wait. Stop on persistent discrepancies and inspect existing logs; no refresh/index-write endpoint, repair or deletion is part of this exercise.

```powershell
$records = Invoke-RestMethod -Method Post -Uri "$queryBase/api/v1/query" -Headers $queryHeaders -ContentType 'application/json' -Body (Get-Content -Raw records-request.json)
if ($records.result_type -ne 'events' -or $records.total -ne 400 -or @($records.hits).Count -ne 400) { throw 'Expected exactly 400 indexed records; do not replay.' }
$expected = @{}
Get-Content events.ndjson | ForEach-Object { $r = $_ | ConvertFrom-Json; $expected[$r.event.eventId] = $r }
$seen = @{}
$seenEvidence = @{}
foreach ($hit in $records.hits) {
    $s = $hit._source
    $id = $s.raw.event.eventId
    if (-not $hit._index -or -not $hit._id -or -not $expected.ContainsKey($id) -or $seen.ContainsKey($id)) { throw 'Missing identity, unexpected raw ID or duplicate raw ID.' }
    $evidenceKey = $hit._index + '/' + $hit._id
    if ($seenEvidence.ContainsKey($evidenceKey)) { throw 'Duplicate stored evidence identity.' }
    $seen[$id] = $true
    $seenEvidence[$evidenceKey] = $true
    $e = $expected[$id]
    if ($s.host.name -cne $e.host -or ([datetimeoffset]$s.'@timestamp') -ne ([datetimeoffset]$e.timestamp)) { throw 'Host/timestamp mismatch.' }
    if ($s.process.pid -ne $e.event.process.pid -or $s.process.executable -cne $e.event.process.imagePath) { throw 'Process mismatch.' }
    if ($e.event.process.parentPid -gt 0 -and ($s.process.parent.pid -ne $e.event.process.parentPid -or $s.process.parent.executable -cne $e.event.process.parentImagePath)) { throw 'Parent mismatch.' }
    if ($s.process.command_line -cne $e.event.process.commandLine -or $s.user.id -cne $e.event.process.userSid) { throw 'Command line or SID mismatch.' }
    if ($null -eq $e.event.process.commandLine -and ('command_line' -in $s.process.PSObject.Properties.Name -or 'commandLine' -in $s.raw.event.process.PSObject.Properties.Name -or 'commandLine' -in $s.raw.event.payload.PSObject.Properties.Name)) { throw 'Missing command line was filled in.' }
    if (($s.raw | ConvertTo-Json -Depth 30 -Compress) -cne ($e | ConvertTo-Json -Depth 30 -Compress)) { throw 'Raw payload differs; inspect structure and values before proceeding.' }
}
if ($seen.Count -ne 400) { throw 'Missing raw event IDs.' }
$records.hits | Group-Object { $_._source.host.name } | Select-Object Name, Count

$alertBody = Get-Content -Raw seed-alert-request.json | ConvertFrom-Json
$alertBody | Add-Member -NotePropertyName index -NotePropertyValue "$labIndexPrefix-alerts-*"
$seedAlerts = Invoke-RestMethod -Method Post -Uri "$queryBase/api/v1/query" -Headers $queryHeaders -ContentType 'application/json' -Body ($alertBody | ConvertTo-Json -Depth 20)
$verifiedSeed = @($seedAlerts.hits | Where-Object { $_._source.raw.event.eventId -eq $runInfo.starting_raw_event_id -and $_._source.rule.id -eq $runInfo.candidate_rule_id -and $_._source.host.name -eq $runInfo.starting_host })
if ($verifiedSeed.Count -lt 1) { throw 'Seed alert not verified; read existing ingest rule/indexing logs. Do not replay or change rules.' }
$verifiedSeed | Select-Object _index, _id, @{n='OriginalUTC';e={$_._source.'@timestamp'}}, @{n='Rule';e={$_._source.rule.id}}
```

Expected host counts are in `run.json` (total 400). Timestamp comparison is instant-based because serializers can normalize the string form; inspect the original string in raw too. The raw check above is deliberately strict; different property ordering alone can produce a false discrepancy—inspect parsed object equality before concluding values changed. Do not skip a substantive mismatch.

The prepared alert query requires the existing alert index pattern; it is **not** a normal Hunt-default event search:

```hunt
{{q "seed-alert"}}
```

In Hunt, this event query verifies the starting process record:

```hunt
{{q "seed-event"}}
```

If the Alerts list's 1,000 fetched records omit the verified historical alert, use its stored `_id` in the existing `/alerts?id=<URL-encoded ID>` UI route. This checkout reads the `id` parameter and fetches the detail when it is not in the list. Use your existing UI base URL; do not put a raw event ID in that route. If detail loading fails, preserve the read-only API evidence and document the UI limit. Do not change status. Once preparation passes, begin the analyst brief, then the worksheet timer. Keep verification/preparation time separate from the 30–45-minute manual investigation.
