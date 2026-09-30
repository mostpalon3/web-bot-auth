# The Signed Lane

Measurement of what a Web Bot Auth signature actually buys on the deployed web.

Web Bot Auth (`draft-ietf-webbotauth-httpsig-protocol`, adopted by the IETF on
1 September 2026, layered over RFC 9421) lets an automated client
cryptographically identify itself, and CDNs use it to grant a privileged
"signed lane". This repository measures what that lane grants, to whom, and on
what basis.

**Three findings, in one line each.** A validly signed request is treated
*worse* than an anonymous one. No origin ever retrieves the public key that
verification would require. Not one admitted operator declares any behaviour.

## Reproducing a claim

Each row is a claim in the paper, the script that produces it, and where the
data lands. Every script prints its own reading of its output.

| claim | script | output |
|---|---|---|
| 34,900 hosts, 12 operators, density decays ~2.8x per rank decade | `scan.py` then `census_consolidate.py` | `results/scans/`, `results/census_consolidated.json` |
| **E1** — 298 of 7,267 origins block a signed request they serve unsigned (p < 10^-75) | `differential.py` | `results/differential/` |
| **E1b** — WBA header *names* with garbage values block at 93.6%; decoy headers at 5.3% | `confound.py` | `results/confound/` |
| **E1c** — no size or latency difference among origins serving both arms | `content_diff.py` | reads E1 |
| **E1d** — `cf-mitigated` is always `challenge`; Qrator enforces too; the 402s are one publisher | `mitigation.py` | reads E1 |
| **E4** — 293 of 298 block, and **0 ever fetch the public key** | `keyfetch.py` + `worker/` | `results/keyfetch/` |
| **E5** — the 402 is a `mailto:`, not pay-per-crawl | `tollbooth.py` | `results/tollbooth/` |
| **E6** — admitted population n=82: 95.1% media type, 100% Ed25519, **0% declarations** | `admitted_probe.py` | `results/admitted/` |
| **E7** — any single protocol header reproduces the effect | `decompose.py` | `results/decompose/` |
| **E8** — the pair replicates from a second network, c = 0 in every split | `vantage_edge.py` | `results/vantage_edge/` |
| **E9** — the exact header name blocks at ~93%; near misses do not | `nearmiss.py` | `results/nearmiss/` |
| **E10** — the `tag` parameter is irrelevant, so the collateral is RFC 9421 itself | `rfc9421_scope.py` | `results/rfc9421/` |
| **E1 headline, recomputed from published data** | `verify_e1.py` | reads `results/differential/e1_summary.json` |
| instrument validation — **run first** | `validate.py` | stdout |

```bash
pip install -r requirements.txt
python validate.py          # must pass before anything else
python verify_e1.py         # recomputes 7,267 / 298 : 9 from committed data
```

## Before pointing any of this at the internet

Every collection script requires `--contact` (a monitored address) and
`--info-url` (a public page describing the study), refuses placeholders, and
puts both in the `User-Agent` of every request. `docs/` is the live version of
that page — **keep it accurate**; an earlier version understated how many
requests the study sends, which is an accountability defect, not a cosmetic
one.

Three constraints are enforced in code rather than documented:

- **`impersonate.py` refuses any target not in `owned.txt`.** It sends another
  operator's key identifier, which would attribute your traffic to them in a
  third party's logs — the exact attack the protocol exists to prevent.
- **No script sends a borrowed key, keyid or agent URL to a third party.**
- **Backoff triggers on `429`, or `503` with `Retry-After`** — never a bare
  `503`, which large sites use as a generic block.

Read `DISCLOSURE.md` before publishing anything derived from this. Two findings
sit on a 90-day clock.

## Not in this repository

`keys/` and `*.pem` (generate your own — the directory in `docs/.well-known/`
is ours and will not match), `honeypot/logs/` (third-party IPs),
`worker/.hits_token` (gates a log of third-party addresses), the raw
`results/` streams and `results/scans/` (every third-party host and
response; E1's raw file alone is 52 MB, and `results/differential/e1_summary.json`
is the committed reduction that `verify_e1.py` reproduces the headline from),
`tranco.csv` (regenerate from `tranco.provenance.json`, which records the
SHA-256), and the paper sources, which live outside this repository until
review is over.

## Instrument defects that changed a conclusion

Each was invisible to loopback testing and each would have produced a wrong
published number. `PAPER.md` section 7 has the full list.

1. **A configuration that produced a false null.** 96 workers / 6s timeout gave
   29% clean pairs and b=17, c=17 — an apparent null. 28 workers / 12s gave 73%
   clean and p < 10^-75. Same experiment, opposite conclusion, because timeouts
   generate spurious transitions in both directions that cancel. **Any
   replication that tunes for throughput without reporting its clean-pair rate
   can reach the opposite result from the same design.**
2. **A bare 200 scored as acceptance**, manufacturing ten apparent conformance
   violations against a security vendor out of a public `robots.txt`.
3. **A declaration probe that searched for the wrong field names**, producing a
   published claim of "0 of 9 publish any declaration" when three publish
   `purpose`.
4. **`median()` over two repetitions is their mean**, so one flaky fetch
   manufactured five false "50% smaller" results.
5. **A residual bucket labelled "other" and never read**, hiding a second
   enforcing vendor (Qrator, 13.7%) behind the claim that the effect was
   Cloudflare's alone.

Every one was caught by a control, or by a result being too tidy. That is the
argument for controls, and it is why `validate.py` exists.

---

## Design notes

What follows is the original methodology documentation for the conformance
matrix, the census and the honeypot. It predates the experiments above and is
kept because the reasoning still applies.

---

## E2 — Web Bot Auth signature verification conformance

Does an origin that accepts Web Bot Auth signatures reject the signatures the
specification says it must?

Each case in the matrix isolates exactly one deviation, so an origin's response
attributes to that deviation and nothing else. Cases carry the requirement they
violate, because the paper's claim is per-requirement rather than
per-implementation.

Methodological precedent: *Opossum* (USENIX Security 2026, Distinguished Paper)
applied this design to opportunistic TLS; *QUIC-Attacker* applied it to QUIC
frame handling.

## Run it

```bash
pip install -r requirements.txt
python validate.py                       # always this first
```

Then a measurement round:

```bash
python -m testbed.origin --port 8422     # terminal 1
python run_conformance.py                # terminal 2
python analyze.py                        # aggregate across runs
```

Results land in `results/` as timestamped CSV and JSON.

## Layout

| path | what it is |
|---|---|
| `wba/keys.py` | Ed25519 keys, JWK export, RFC 7638 thumbprints (the `keyid`) |
| `wba/signature.py` | RFC 9421 signature base and header emission |
| `wba/mutations.py` | **the experiment** — the conformance matrix |
| `testbed/origin.py` | strictly conforming reference origin, used as ground truth |
| `run_conformance.py` | sends the matrix, classifies, records |
| `validate.py` | positive and negative controls; run before every round |
| `analyze.py` | per-requirement rates with Wilson intervals, origin profiles |
| `tests/` | RFC 9421 test-vector conformance |
| `PREREGISTRATION.md` | hypotheses and analysis plan, fixed before collection |
| `wba/directory.py` | directory and Signature Agent Card parsing |
| `scan.py` | **T1 census** — concurrent, rate-limited, resumable |
| `harvest.py` | **T1 observatory** — watchlist, snapshot, diff |
| `seeds.txt` | the hypothesis set to probe |
| `honeypot/allocate.py` | **E3** — randomised arm assignment, written once |
| `honeypot/server.py` | the site: serves everything, logs everything |
| `honeypot/simulate.py` | synthetic agents, for validating before real traffic |
| `analyze_e3.py` | declared against observed, per agent |
| `validate_e3.py` | end-to-end check of the E3 chain |

`signature.py` deliberately separates signing from header emission
(`emit_params`, `signature_override`). A correctness-focused library would
refuse to sign over one set of parameters and transmit another; that divergence
is precisely what most cases need.

## The matrix

18 cases: 1 control, 13 the specification requires be rejected, 4 left to
policy and recorded rather than judged.

| group | cases |
|---|---|
| freshness | `expired`, `created_future`, `expires_absent`*, `created_absent`* |
| nonce | `nonce_absent`, `nonce_replayed` |
| integrity | `signature_tampered`, `component_tampered`, `wrong_key`, `keyid_unknown` |
| algorithm | `alg_confusion`, `shared_hmac` |
| coverage | `authority_uncovered`, `tag_absent`*, `tag_wrong`* |
| cross-origin | `cross_origin_replay`, `forwarded_host_confusion` |

\* recorded as policy, not scored.

`nonce_replayed` is stateful: the runner sends the control first and reuses its
nonce, so the replayed signature is valid in every respect except uniqueness.
The draft assigns nonce enforcement to the origin (§5.3), which is exactly why
it is worth measuring whether origins do it.

## Validation

Three independent checks, all automated in `validate.py`:

**RFC 9421 test vectors.** The signature base is pinned to the RFC's published
Ed25519 example (Appendix B.2.6): the RFC's own signature verifies over our
assembled base. Ed25519 verification succeeds only over the exact bytes signed,
so this cannot be faked. A harness that is itself non-conformant would produce
findings that are its own bugs.

**Positive control.** Against a strictly conforming origin: control accepted,
all 13 must-reject cases rejected, zero findings. Catches a harness whose
malformed requests produce rejections that get misread as findings.

**Negative control.** `testbed/origin.py --lax` injects four documented
weaknesses. The suite must find exactly those and nothing else:

| injected weakness | case that catches it |
|---|---|
| trusts `X-Forwarded-Host` for `@authority` | `forwarded_host_confusion` |
| no nonce tracking | `nonce_replayed` |
| ignores `expires` | `expired` |
| no tag requirement | `tag_absent`, `tag_wrong` (policy, recorded) |

Note that `cross_origin_replay` stays *rejected* under lax mode while
`forwarded_host_confusion` fires. The two cases have deliberately different
discriminating power, and the negative control proves it.

A suite that passes only the positive control demonstrates nothing about its
ability to detect a broken verifier. **A green `validate.py` is what licenses
belief in a red row against any other target.** A failed run voids the round.

## Ethics

Development runs against `testbed/origin.py` on loopback. Nothing here requires
touching third-party infrastructure to build or validate.

Before any non-local target:

- institutional sign-off, in writing
- a real contact address in the `--agent` string, and a page at that URL
  explaining the study
- remote runs are forced to ≥2s between requests; raise it further
- honour opt-outs on request, without argument
- 90-day coordinated disclosure for anything found

The suite sends malformed signatures and nothing else. It never attempts to
gain access it would not otherwise have, never exercises any behaviour the
signed-agent policy prohibits, and never touches CAPTCHA or bot-defence bypass.
A rejected signature is the expected and desired outcome of nearly every case.

## Classification

A 200 carrying a bot interstitial is **not** an acceptance. `classify()` scores
those as `challenged`, because counting them as accepted would systematically
overstate how permissive origins are — the direction of error that would
flatter the hypothesis. Anything ambiguous is `inconclusive` and reviewed by
hand; it is never guessed.

## Status


**E2 was subsequently run against external origins and yielded no conformance
data, which is itself the result.** No endpoint exists where signature validity
is load-bearing for an unadmitted party: public paths serve regardless and
gated paths refuse regardless, so the matrix cannot discriminate. The harness
is ready for anyone with allowlist access; see `PAPER.md` section 4.11.

---

## T1 — census

```bash
python scan.py --hosts tranco.csv --limit 1000000 --rate 40 --workers 64
python scan.py --resume
python scan.py --summarise results/scans/scan_<stamp>.jsonl
```

The well-known path is a fixed URL on every host, so the population is a census
to be taken, not a seed list to be guessed at. Precedent for the scale: the ECH
deployment studies scanned 7.5M domains.

One HTTPS GET per host, no retries — retrying multiplies load on the hosts
least able to answer, and a timeout is itself a result. A **global** token
bucket bounds the aggregate rate: per-thread sleeps do not, since 64 workers
each pausing a second still emit 64 requests per second. Checkpointed and
resumable, streaming to JSONL so a million-host run never sits in memory.

**Non-responses are recorded, never dropped.** A census that reports only its
hits cannot tell you how rare the thing is — which is the finding if the
population turns out to be small.

Scanning needs institutional sign-off before it starts. The UA carries a
contact address and an opt-out.

## T1 — observatory

```bash
python harvest.py --seeds seeds.txt     # probe and snapshot
python harvest.py --report              # summarise the latest
python harvest.py --diff                # latest against previous
```

Handles both document shapes in circulation: a plain JWKS, and a Signature
Agent Card (OAuth client metadata plus a `web_bot_auth` object) per
`draft-meunier-webbotauth-registry` (still an individual draft, unadopted).

**`seeds.txt` is a hypothesis set, not a known population.** Which candidates
resolve is the first result. Unreachable seeds are recorded, never dropped — if
the population turns out to be tiny, that is the finding, and it is only
visible if the failures are kept.

The most reliable seed source is passive: run E3's honeypot and read
`Signature-Agent` headers off real traffic. Seeds harvested that way are
observed rather than guessed, and should eventually replace the guessed list.

### What the snapshot measures

Declaration coverage across agent cards — `purpose`, `rate-expectation`,
`rfc9309-compliance`, `expected-user-agent`, `targeted-content` and the rest.
**A declaration that is absent cannot be violated and cannot be checked, so
coverage bounds what E3 is able to measure at all.**

### Why snapshots, not a single scrape

`--diff` reports appeared and vanished operators, key rotations, and — the
reason the observatory exists — **altered declarations**:

```
! declaration  <operator>  purpose
                 was: "search-index"
                 now: "search-index,ai-training"
! declaration  <operator>  rate-expectation
                 was: {"requests-per-minute": 60}
                 now: {"requests-per-minute": 600}
```

An agent that quietly widens its declared purpose or raises its rate
expectation *after* being listed is a finding only a time series can catch.
Keep every snapshot; they are the part of this work that is hard to reproduce
after the fact.

---

## E3 — the honeypot

**No live data was collected with this.** It is validated end to end against
synthetic agents and never received real traffic, because attracting verified
agents requires being discoverable by them, which takes months. The design is
documented because it is the natural continuation, not because it produced a
result in this paper.

```bash
python -m honeypot.allocate --domain example.org --seed 20260910
python -m honeypot.server   --domain example.org --port 8080
python analyze_e3.py        --domain example.org
```

### Two rules that govern the design

**Never block.** A disallowed path is still served. Refusing it would measure
our own enforcement instead of the crawler's compliance, and a violation would
become unobservable.

**Identity is cryptographic.** Agents are attributed by *verified* signature,
not by User-Agent — a User-Agent being exactly what the signed lane exists to
stop trusting. Requests without a valid signature are analysed in a separate,
clearly labelled stratum, because an unverified identity is a claim rather than
a fact.

### Why the allocation is randomised

`allocate.py` assigns paths to `allow_implicit`, `allow_explicit` and
`disallow` arms from a recorded seed. Random assignment is what makes E3 an
experiment rather than a log study: a crawler can have no prior reason to treat
one arm differently except by reading robots.txt.

**The manifest is written before traffic arrives and must not change.** A
robots.txt that shifts under a crawler mid-visit destroys attribution — you
could no longer say whether a fetch was a violation or a stale read. Re-running
allocation refuses unless forced.

Reachability is crossed with the arm, so "did it obey robots.txt" and "how did
it find the page" separate in analysis. The sitemap deliberately lists some
disallowed URLs, because that misconfiguration is common and the precedence
question is worth measuring rather than avoiding.

`/private/deep-canary` is disallowed and linked *only* from another disallowed
page. Fetching it means robots.txt was never consulted before following links —
a stronger violation than fetching a disallowed page linked from the root.

### What the analysis produces

Per agent, joined to its T1 declarations: disallowed-fetch rate with Wilson
intervals, deep-canary hits, whether robots.txt was fetched at all, minimum and
median inter-request gaps against declared `rate-expectation` and site
crawl-delay, and whether the presented User-Agent matches `expected-user-agent`.

The headline is the stratified comparison: **verified agents against
unverified ones.** If verified agents comply no better, verification selects
for paperwork rather than behaviour.

### Validation

`validate_e3.py` drives the whole chain with two synthetic agents whose
behaviour is known in advance — one obedient, one ignoring robots.txt, with
distinct keys and distinct directories — and asserts the analysis recovers the
difference. Unattended collection has no second chance: a mislabelled arm or a
dropped request is only discovered after the months of traffic it was meant to
capture.

A validated run produces exactly the finding shape the paper is looking for: an
agent whose published card declares `rfc9309-compliance: true`, which never
fetches robots.txt, and which fetches disallowed paths at a measurable rate.

## Next

- **A second network vantage.** Two client stacks, one IP, one country. The
  matched-pair design holds the source constant within each comparison, but
  absolute rates belong to this vantage. This is the last structural objection
  a reviewer can raise.
- **Re-probe the declaration layer in a month.** Three operators publish
  `purpose` now; the 10 September probe never looked for that field, so whether
  it is new cannot currently be claimed either way.
- **Second coder and Cohen's kappa** for the 12 census-discovered operators.
  The n=90 taxonomy uses Cloudflare's own labels and needs no inter-rater
  measure.
- **Start the disclosure clock.** `DISCLOSURE.md` is drafted and unsent.
- `challenged` classification is still validated against a marker list rather
  than real interstitials.
