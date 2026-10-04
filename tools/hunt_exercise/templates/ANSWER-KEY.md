# Answer key — facilitator only — {{.RunID}}

Do not read until your assessment is written. These are expected interpretations of a bounded synthetic capture, not claims about real endpoints.

| Endpoint | Expected assessment | Basis and counterweight |
| --- | --- | --- |
| {{index .Hosts 0}} | Prioritize investigation | Office → cmd → user-local executable → nearby identity/host/version commands. The seed is a true rule match, not proof of malicious intent; legitimate macros remain a possible explanation. |
| {{index .Hosts 1}} | Follow up with explicit uncertainty | Same exact user-local executable path shortly afterward, with cmd parent and similar child context. Missing command line and user identity constrain attribution. Shared path/timing do not prove the same bytes or lateral movement. |
| {{index .Hosts 2}} | Lower priority for this specific hypothesis, pending deployment checks | Same basename but Program Files path, services.exe parent and SYSTEM SID. Different context defeats a basename-only conclusion; it does not prove safety. |
| {{index .Hosts 3}} | No specific supporting chain in this capture | Ordinary common-name activity supplies comparison noise. Limited process-only coverage cannot exclude other activity. |

Expected total 400; host counts 190 / 90 / 65 / 55 in host-name order. All are DriverProcess starts, including two capture roots per host. Roots have PID 0 as an explicit unknown-ancestor boundary. PIDs are unique per host and never reused; no termination/lifetime inference is available.

Starting alert: {{.RuleTitle}} / {{.RuleID}} at {{.SeedTime}}. Expected candidate match count is one in a candidate-only local engine. Other installed rules may fire; live alert totals are deliberately not promised.

Evidence anchors (raw event IDs; collect corresponding ES index/IDs after ingestion):

| Observation | Raw event ID(s) |
| --- | --- |
| Office parent | {{evidence "office"}} |
| Seed cmd | {{evidence "seed"}} |
| Initial user-local executable | {{evidence "initial-path"}} |
| Its children | {{evidence "initial-child"}} |
| Second host parent, missing context | {{evidence "second-parent-missing"}} |
| Second host path match, missing context | {{evidence "second-path-missing"}} |
| Second host child, missing user | {{evidence "second-child-missing"}} |
| Program Files lookalike and service parent | {{evidence "lookalike-path"}} |
| Lookalike child | {{evidence "lookalike-child"}} |
| One second before boundary start (exclude) | {{evidence "before-start"}} |
| Exactly boundary start (include) | {{evidence "at-start"}} |
| One second before boundary end (include) | {{evidence "before-end"}} |
| Exactly boundary end (exclude) | {{evidence "at-end"}} |

There are two missing command lines and three missing SIDs. Those two command lines are absent in both context and payload, and disappear from normalized JSON rather than becoming empty strings. Normalized user names are absent throughout; supplied SIDs map to `user.id`. EDR Informational severity maps to zero and is omitted from stored event JSON in this parser; the Sigma alert independently has high severity / numeric 4. Neither behavior is changed.

`manifest.json` includes inputs, NDJSON digest, all 400 raw IDs, per-record normalized values and answer-key labels. Labels exist only in this private manifest. Source IDs/agent IDs are kept in raw; no ECS event ID is fabricated. `source_type` is used for routing but excluded from stored JSON. The template uses `dynamic:false`; `raw.*` is not a search pivot. Expected process names preserve executable basename case.

Boundary query/picker expectation: exactly PID 9004 and 9008 on the initial host, at {{(window "boundary").From}} and one second before {{(window "boundary").To}}. PIDs 9000 and 9012 must not be returned by that window.

An adequate assessment cites evidence and competing explanations, prioritizes follow-up without declaring compromise, and requests file hashes/signatures, deployment provenance, user/logon context and network evidence. None of those additional sources is available in this process-only exercise. No evidence proves movement between hosts, identical executable bytes, a malicious document, credential theft or data transfer.
