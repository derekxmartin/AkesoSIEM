# Manual Hunt exercise — I2604A

**Everything in this run is synthetic.** Allow 30–45 minutes after preparation and indexing verification. Use Hunt, a notes file and the worksheet. Do not open the facilitator directory until you have written your assessment.

Starting alert: **Command Prompt Spawned by Office Application**, rule `a1b2c3d4-1012-4a1b-9c12-000000000012`.

Initial endpoint: **SYN-I2604A-01**. Original event time: **2026-10-04T12:30:00Z** (UTC).

Your question: **Which endpoints deserve further investigation, on what evidence, and with what uncertainty?** Start from the alert, reconstruct relevant activity, choose and test pivots, and compare the four run-scoped endpoints. Do not assume the alert title is a verdict or that a matching name is enough.

Authorized exercise scope: `SYN-I2604A-01`, `SYN-I2604A-02`, `SYN-I2604A-03`, `SYN-I2604A-04`; UTC `2026-10-04T12:00:00Z` through `2026-10-04T14:00:01Z` (end exclusive). These are neutral Windows host names, not real endpoints. No process described in the data has been executed.

Deliver a short assessment with prioritized endpoints, a few supporting event references, contrary evidence, information gaps and next checks. An Elasticsearch index/ID plus original UTC timestamp identifies stored evidence; a raw event ID alone does not establish uniqueness in storage.

Start the timer now. Open GUIDE.md for the workflow and optional progressive hints. Record work in WORKSHEET.md. Do not create cases, change alert status or take response actions.
