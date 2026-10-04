# Hands-on Hunt guide — I2604A

Budget 30–45 minutes. Keep the facilitator material closed. Stop at an evidence-backed assessment; this exercise does not include containment, case creation or an automated agent.

## 0–5 minutes: confirm the starting evidence

Preparation must already have verified the seed alert; HTTP 202 is insufficient. Open Alerts and locate **Command Prompt Spawned by Office Application**. Inspect its event fields/raw data for `SYN-I2604A-01` and original UTC `2026-10-04T12:30:00Z`. Do not change its status. If the alert is outside the list's fetched window, use the read-only preparation query; the list is not an exhaustive historical search. Hunt's default index covers event records, not alerts.

Record the rule ID, alert's ES index/ID, original UTC time, process executable and parent. A rule match is the starting observation, not an assessment of all endpoints. Open Hunt manually; do not assume a special alert-to-Hunt pivot control.

## 5–12 minutes: narrow a timeline and notice limits

Turn auto-refresh Off. Set an absolute time range. The picker uses browser-local time: convert UTC to your local zone, then verify Hunt's displayed effective UTC bounds. The full range is **2026-10-04T12:00:00Z ≤ time < 2026-10-04T14:00:01Z**. Do not leave “Last 24h” selected for a historical replay. If a minute-only picker cannot enter the final second, choose a containing range ending at the next minute; do not clip the dataset.

Start with this Hunt text:

```hunt
host.name IN ("SYN-I2604A-01") | sort @timestamp asc
```

At the default 100 rows, compare returned records with total matches. Table-header sorting only rearranges returned records; `| sort @timestamp asc` requests backend order. A chart or field sidebar count describes returned records only. Absence from those 100 rows is not absence from the dataset. The existing Rows per page control offers 25/50/100/200; select 200 for this host or narrow time windows. Hunt sends that page size explicitly, overriding a text `limit` pipe, so adding a large text limit is not a workaround. There is no next-page control here.

Narrow the picker to **2026-10-04T12:29:00Z ≤ time < 2026-10-04T12:37:00Z**. Re-run the timeline. Inspect nearby records, including activity before the alert. Write down process PIDs, parent PIDs, full paths and times. PIDs are host-local and can be reused in real telemetry; join them manually only within a defensible host/time context.

<details>
<summary>Hint 1: reconstruct the immediate chain</summary>

Open the alert-triggering process, find its parent, then inspect processes whose parent PID equals a PID you observed. Use the exact host, not a global PID search. This example uses a PID found in this capture:

```hunt
host.name IN ("SYN-I2604A-01") AND (process.pid = 1200 OR process.parent.pid = 1200) | sort @timestamp asc
```

This is an OR filter over events, not a join or recursive process graph. Verify timestamps and executable names on each edge.
</details>

## 12–25 minutes: choose discriminating pivots and compare hosts

Restore the full run range before cross-host searches. Keep the four exact host names in every query to exclude unrelated lab data. First try a broad process-name pivot and record how much context it loses.

<details>
<summary>Hint 2: broad names, then a specific basename</summary>

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.name IN ("cmd.exe", "whoami.exe") | sort @timestamp asc
```

Compare with a basename observed in the initial chain:

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.name IN ("syncsvc.exe") | sort @timestamp asc
```

A basename is not a file hash. Inspect the entire executable path and parent before ranking hosts.
</details>

<details>
<summary>Hint 3: exact executable and parent context</summary>

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.executable IN ("C:\\Users\\lab.user\\AppData\\Local\\Cedar\\syncsvc.exe") | sort @timestamp asc
```

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.parent.executable IN ("C:\\Users\\lab.user\\AppData\\Local\\Cedar\\syncsvc.exe") | sort @timestamp asc
```

Use `process.executable`, not `process.path`. Preserve path case/spelling for exact keyword matches. Compare timing, user information and command lines. Shared paths and nearby times can justify investigation; they do not establish transport, common file contents or lateral movement.

Hunt text above contains **two literal backslashes per path separator**; its lexer decodes each pair to one. A JSON HTTP body needs **four backslashes** for those same two Hunt characters, plus escaped quotes. `path-request.json` is the serialized HTTP example. Paste only the `hunt` code blocks into Hunt, not the JSON body. Let `ConvertTo-Json` serialize request objects; do not manually double-escape them.
</details>

## 25–32 minutes: inspect raw evidence and gaps

Expand several returned records. Compare Table, JSON and Raw. Record the ES index/ID and raw `event.eventId`; the latter is a synthetic source identifier retained inside raw, not an indexed ECS event ID. Preserve original UTC timestamps. The context and payload should agree on process identity and parent PID. User SID maps to `user.id`; it does not supply a username.

<details>
<summary>Hint 4: distinguish absent data from negative evidence</summary>

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND NOT process.command_line exists | sort @timestamp asc
```

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND NOT user.id exists | sort @timestamp asc
```

Verify absence in both `raw.event.process.commandLine` and `raw.event.payload.commandLine`. Missing is not an empty command, an uneventful execution or proof that the collector saw everything. Do not search `raw.*` or `source_type`; this checkout preserves raw for inspection but does not map those fields for these pivots.
</details>

<details>
<summary>Optional coverage check: projection and server aggregation</summary>

```hunt
host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.name IN ("syncsvc.exe") | sort @timestamp asc | fields @timestamp, host.name, process.pid, process.parent, process.executable, process.command_line, user.id
```

This deliberately returns selected fields; fields omitted by projection are not evidence of telemetry loss. Return to the unprojected basename search for raw content.

```hunt
count() by host.name where host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04")
```

```hunt
count() by host.name where host.name IN ("SYN-I2604A-01", "SYN-I2604A-02", "SYN-I2604A-03", "SYN-I2604A-04") AND process.executable IN ("C:\\Users\\lab.user\\AppData\\Local\\Cedar\\syncsvc.exe")
```

These are backend aggregations over the filtered/time-scoped search, distinct from the client histogram and field statistics. Aggregate rows are not individual evidence records and have no event ID or event time. Inspect aggregation output; do not expect a new visualization or pivot control.
</details>

## 32–35 minutes: verify a time boundary

Four notepad records are provided solely as measurement anchors; their PIDs are not investigation labels. Keep the full picker range and run:

```hunt
host.name IN ("SYN-I2604A-01") AND process.pid IN (9000, 9004, 9008, 9012) AND @timestamp >= "2026-10-04T12:30:00Z" AND @timestamp < "2026-10-04T12:35:00Z" | sort @timestamp asc
```

Then set the picker to **2026-10-04T12:30:00Z ≤ time < 2026-10-04T12:35:00Z** and run:

```hunt
host.name IN ("SYN-I2604A-01") AND process.pid IN (9000, 9004, 9008, 9012) | sort @timestamp asc
```

Compare the exact IDs/timestamps. Both approaches should include the start and exclude the end. Query time predicates intersect with the picker; neither replaces it. Restore the full range before final coverage checks.

## 35–45 minutes: write and challenge the assessment

Use the worksheet to write 150–250 words. Rank endpoints for follow-up, cite a few concrete events and contrary observations, identify missing information, and propose next checks. Distinguish observed chain edges from cross-host associations. Consider what hashes/signatures, software inventory, logon or network telemetry would resolve; these are not supplied here.

Finish the timer before opening the separate facilitator directory. Compare your assessment with its answer key and solved walkthrough only after committing your own conclusion. Measure searches, time changes, expanded records, copied evidence and narrative assembly—not just the number of matches.

On an API error or invalid query, record the failure. Stale retained results are not a successful current search. Stop and verify the effective range/query rather than treating an error as “no evidence.”
