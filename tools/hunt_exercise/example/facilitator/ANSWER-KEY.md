# Answer key — facilitator only — I2604A

Do not read until your assessment is written. These are expected interpretations of a bounded synthetic capture, not claims about real endpoints.

| Endpoint | Expected assessment | Basis and counterweight |
| --- | --- | --- |
| SYN-I2604A-01 | Prioritize investigation | Office → cmd → user-local executable → nearby identity/host/version commands. The seed is a true rule match, not proof of malicious intent; legitimate macros remain a possible explanation. |
| SYN-I2604A-02 | Follow up with explicit uncertainty | Same exact user-local executable path shortly afterward, with cmd parent and similar child context. Missing command line and user identity constrain attribution. Shared path/timing do not prove the same bytes or lateral movement. |
| SYN-I2604A-03 | Lower priority for this specific hypothesis, pending deployment checks | Same basename but Program Files path, services.exe parent and SYSTEM SID. Different context defeats a basename-only conclusion; it does not prove safety. |
| SYN-I2604A-04 | No specific supporting chain in this capture | Ordinary common-name activity supplies comparison noise. Limited process-only coverage cannot exclude other activity. |

Expected total 400; host counts 190 / 90 / 65 / 55 in host-name order. All are DriverProcess starts, including two capture roots per host. Roots have PID 0 as an explicit unknown-ancestor boundary. PIDs are unique per host and never reused; no termination/lifetime inference is available.

Starting alert: Command Prompt Spawned by Office Application / a1b2c3d4-1012-4a1b-9c12-000000000012 at 2026-10-04T12:30:00Z. Expected candidate match count is one in a candidate-only local engine. Other installed rules may fire; live alert totals are deliberately not promised.

Evidence anchors (raw event IDs; collect corresponding ES index/IDs after ingestion):

| Observation | Raw event ID(s) |
| --- | --- |
| Office parent | `85789c0e-6ac3-88b4-9423-f4900e8560a7` |
| Seed cmd | `29b6e0f9-4a4d-8762-90f3-5be69a24fd60` |
| Initial user-local executable | `4a4ffd85-3074-8334-960f-89f04e60759c` |
| Its children | `3bd1913b-dd41-8af5-8bd7-8c315f848e50`, `04a69b8f-894f-8f91-b25b-5a4182b50163`, `4c313c25-63a6-884b-9e70-a6bb258d4c74` |
| Second host parent, missing context | `00bdaad0-c482-8777-9b04-8baa928c4017` |
| Second host path match, missing context | `45fe6d74-4061-847d-b1fd-e540cc1814b4` |
| Second host child, missing user | `5230a981-18cf-8f2c-a353-2f01620373fd` |
| Program Files lookalike and service parent | `efcd1273-083c-8662-88a6-07c1e89f2c58` |
| Lookalike child | `1ec990b2-8d3d-8b7e-a85f-4cd34d5b88de` |
| One second before boundary start (exclude) | `7a4e1e6c-51be-8064-acd0-c3fcb5131c5e` |
| Exactly boundary start (include) | `53373385-8091-85cf-bf6c-489c2eae2bb9` |
| One second before boundary end (include) | `e6ab990b-167b-84b5-a1df-3dd3a6c49eed` |
| Exactly boundary end (exclude) | `7e8280d4-c581-825a-ab08-abfb63d5e4c5` |

There are two missing command lines and three missing SIDs. Those two command lines are absent in both context and payload, and disappear from normalized JSON rather than becoming empty strings. Normalized user names are absent throughout; supplied SIDs map to `user.id`. EDR Informational severity maps to zero and is omitted from stored event JSON in this parser; the Sigma alert independently has high severity / numeric 4. Neither behavior is changed.

`manifest.json` includes inputs, NDJSON digest, all 400 raw IDs, per-record normalized values and answer-key labels. Labels exist only in this private manifest. Source IDs/agent IDs are kept in raw; no ECS event ID is fabricated. `source_type` is used for routing but excluded from stored JSON. The template uses `dynamic:false`; `raw.*` is not a search pivot. Expected process names preserve executable basename case.

Boundary query/picker expectation: exactly PID 9004 and 9008 on the initial host, at 2026-10-04T12:30:00Z and one second before 2026-10-04T12:35:00Z. PIDs 9000 and 9012 must not be returned by that window.

An adequate assessment cites evidence and competing explanations, prioritizes follow-up without declaring compromise, and requests file hashes/signatures, deployment provenance, user/logon context and network evidence. None of those additional sources is available in this process-only exercise. No evidence proves movement between hosts, identical executable bytes, a malicious document, credential theft or data transfer.
