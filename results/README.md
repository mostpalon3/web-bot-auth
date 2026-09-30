# Results

Two kinds of file land here, and only one kind is published.

**Published.** The curated result of each experiment, one JSON per run, named
with the UTC timestamp of collection. These are the files every number in the
paper is computed from, and `.gitignore` re-admits them by name. `verify_e1.py`
at the repository root recomputes the headline E1 figures from
`differential/e1_summary.json` so the main claim can be checked without
trusting the write-up.

**Not published.** The raw streams, checkpoints and run logs. They record every
third-party host contacted and every response, which is a large amount of data
about sites that did not ask to be in a public dataset. `scans/` and the
`.jsonl` streams stay local. E1's raw file is 52 MB for that reason, and
`e1_summary.json` is the reduction of it: outcome coding, status, size and
latency, with response bodies and vendor headers dropped.

| file | experiment |
|---|---|
| `census_consolidated.json` | census of 34,900 hosts, deduplicated, with Tranco ranks restored |
| `differential/e1_summary.json` | E1, the matched pair over 10,000 origins |
| `confound/` | E1b, header names with garbage values against decoy headers |
| `deep/` | E2, conformance probing |
| `timeline/` | directory stability over time |
| `keyfetch/` | E4, retrievals of the published public key |
| `tollbooth/` | E5, the HTTP 402 responses |
| `impersonation/` | E3, borrowed key identifiers against owned targets only |
| `admitted/` | E6, the 82 reachable admitted operators |
| `decompose/` | E7, the five arms that isolate the trigger |
| `vantage_edge/` | E8, the same pair from a second network |
| `nearmiss/` | E9, the exact header name against near misses |
| `rfc9421/` | E10, tagged against untagged signatures |
| `pilot/pilot_summary.json` | the pilot that fixed the instrument |
