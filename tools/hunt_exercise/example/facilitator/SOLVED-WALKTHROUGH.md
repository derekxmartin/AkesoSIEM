# Solved walkthrough — open only after your first attempt

This records one reasonable manual path, not a script to automate the investigation.

1. Confirm the rule ID and original timestamp on the seed alert, then match its raw source ID to the initial host's process record. Keep the alert ES identity separate from the event ES identity.
2. The broad initial-host timeline has 190 records, so 100 returned rows are incomplete. Selecting 200 or narrowing around the seed removes that ambiguity. A header sort alone cannot recover excluded rows.
3. In the narrow timeline, inspect WINWORD.EXE (PID 1000), cmd.exe (1100), the user-local syncsvc.exe (1200), and children 1300/1304/1308. Parent PIDs, executable context and ordering support this local chain. They do not establish what the document contained or whether commands succeeded.
4. A global common-name search returns multiple ordinary instances. A syncsvc.exe basename search finds three hosts. Compare full paths before assigning significance. The exact user-local path search narrows to two hosts; this is the first useful cross-host association, not evidence of a transfer mechanism.
5. Inspect the second host's cmd → syncsvc → whoami sequence near the first. Both parent/child command-line gaps are genuine in context and payload. All three user SIDs are absent. Record that these facts increase uncertainty rather than inventing an account or command.
6. Compare the remaining basename match: Program Files path, services.exe parent, SYSTEM SID and a status child. This is materially different context. Request installation/signature evidence before disposition; do not infer “safe” from a directory name.
7. Verify host coverage with the four-host server count and distinguish those 400 records from the currently returned subset. Field projections are convenient summaries but remove unrequested fields, so use full records for evidence. The fourth host has no supporting chain here; do not generalize beyond this small time window and source.
8. Use the four measurement PIDs to verify the time contract: inclusive start, exclusive end. The text-range and picker-range queries should return the same two raw IDs, not simply equal counts.
9. Assemble a brief with a small evidence table, priorities, contrary evidence and next checks. Total the worksheet's queries, range adjustments, opened records, copied identifiers and drafting time. This is the manual before-state the interview should demonstrate.

Example assessment (compare reasoning, not exact wording):

> Prioritize SYN-I2604A-01 for investigation of an Office-launched command shell followed by a user-local executable and nearby process activity. Parent PIDs, original times and full executable paths support the local sequence; cite the seed, executable and child event references in the answer key. This rule match is not by itself proof of compromise.
>
> Follow up on SYN-I2604A-02 because the same full executable path appears shortly afterward with related process context. The absent command lines and user SIDs prevent a stronger comparison or attribution. Path equality does not establish identical contents, and timing does not prove lateral movement.
>
> SYN-I2604A-03 shares the basename but differs in executable path and service parent context; validate software deployment and signing before escalating that association. SYN-I2604A-04 provides no specific supporting chain in this capture, which does not clear the endpoint generally. Request hashes/signatures, software provenance, Office/document context, authentication and network telemetry. Record this assessment as provisional and link each claim to stored event identities rather than aggregate rows.

No case creation, live response or follow-on architecture work is required to complete this exercise.
