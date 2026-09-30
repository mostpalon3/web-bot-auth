# Pilot census — result

**Collected:** 10 September 2026
**Instrument:** `scan.py`, one HTTPS GET per host to
`/.well-known/http-message-signatures-directory`
**Frame:** Tranco top 5,000 (daily list, SHA-256 recorded in
`tranco.provenance.json`)
**Status:** exploratory. No hypotheses were registered before this run — see
`PREREGISTRATION.md` §0 for why that matters and how it constrains what may be
claimed from it.

---

## Headline

**4,999 hosts scanned. 4,033 resolvable. 5 directories found — 0.124%**
(95% CI, Wilson: 0.053%–0.290%)

## Deployment by rank

| rank range | resolvable | found | density | 95% CI |
|---|---:|---:|---:|---|
| 1–500 | 379 | 3 | 0.79% | 0.27%–2.30% |
| 501–1,000 | 398 | 1 | 0.25% | 0.04%–1.41% |
| 1,001–1,500 | 443 | 0 | 0% | 0–0.86% |
| 1,501–2,000 | 446 | 0 | 0% | 0–0.85% |
| 2,001–2,500 | 398 | 1 | 0.25% | 0.04%–1.41% |
| 2,501–3,000 | 381 | 0 | 0% | 0–1.00% |
| 3,001–3,500 | 403 | 0 | 0% | 0–0.94% |
| 3,501–4,000 | 381 | 0 | 0% | 0–1.00% |
| 4,001–4,500 | 414 | 0 | 0% | 0–0.92% |
| 4,501–5,000 | 390 | 0 | 0% | 0–0.98% |

Five points cannot support a fitted decay curve, and `rank_decay.py` refuses to
fit one. What can be said: four of five sit in the top 1,000, and 1,969
resolvable hosts between ranks 2,501 and 5,000 produced nothing.

## The directories

| rank | host | keys | shape | declarations |
|---:|---|---:|---|---|
| 74 | chatgpt.com | 1 | JWKS | **none** |
| 270 | forter.com | 1 | JWKS | **none** |
| 348 | checkpoint.com | 1 | JWKS | **none** |
| 839 | meta.com | 3 | JWKS | **none** |
| 2,141 | ahrefs.com | 2 | JWKS | **none** |

**Five of five publish a bare JWKS.** Not one publishes a Signature Agent Card.
No `purpose`, no `rate-expectation`, no `rfc9309-compliance`, no
`expected-user-agent`.

## Observations

**The declaration layer appears undeployed while the key layer is not.**
Operators publish the material that earns entry to the signed lane and omit the
metadata that would describe what they intend to do with it. On this evidence
the two halves of the protocol have very different uptake.

*Caveat:* `draft-meunier-webbotauth-registry` is recent (v03, June 2026).
Card adoption may simply lag key publication rather than being declined. A
second census months later would distinguish the two, and that is the strongest
argument for running this as a longitudinal observatory rather than once.

**The standardisation record shows the same split, independently.** Checked
13 September 2026 against the IETF datatracker:

| document | status | date |
|---|---|---|
| `draft-ietf-webbotauth-httpsig-protocol-00` — the identity mechanism | **WG document, Standards Track** | 1 Sept 2026 |
| `draft-meunier-webbotauth-registry-03` — registry and Signature Agent Card | individual, "I-D Exists" | 26 June 2026 |

The signature was adopted onto the Standards Track. The declarations that
would make a signature *mean* something — `purpose`, `rate-expectation`,
`rfc9309-compliance` — were not. This is the deployment finding above,
reached by a completely different route: the standards process and the
operators have independently made the same choice about which half of the
protocol matters.

It also weakens the lag explanation offered in the caveat. The registry draft
is not merely young; it sat unadopted through the very cycle in which the
protocol document was taken up.

**The operator mix does not match the framing.** One of five is an AI agent.
The others are fraud prevention (Forter), security (Check Point), a platform
(Meta) and an SEO crawler (Ahrefs). Public discussion of Web Bot Auth —
including the CDN documentation and the drafts — is framed almost entirely
around AI crawlers. These are businesses that have run automated traffic for a
decade and have long had the same identity problem the protocol addresses.

*Caveat:* five observations. This is a hypothesis about the population, not a
description of it.

## Non-response distribution

Characterising this matters: it is the ambiguity floor for any census of a
well-known path, and it is not reported in the studies this method comes from.

| response | count | share |
|---|---:|---:|
| `404` — correctly absent | 2,276 | 45.5% |
| DNS failure — no apex record | 966 | 19.3% |
| `403` — client blocked | 571 | 11.4% |
| `200`, non-JSON — catch-all page | 481 | 9.6% |
| connect timeout | 184 | 3.7% |
| connection failure | 180 | 3.6% |
| TLS failure | 179 | 3.6% |
| everything else | 162 | 3.2% |

Two entries deserve attention:

**`403` at 11.4%** — hosts that block an unfamiliar client outright. A directory
could exist behind that block and this method would never see it, so **0.124%
is a lower bound**, not a point estimate.

**`200` with non-JSON at 9.6%** — hosts returning a catch-all page for a path
they have never heard of. Any census that treats HTTP 200 as presence would
overcount by roughly two orders of magnitude relative to the true rate.

**DNS failure at 19.3%** — Tranco ranks by DNS query volume, so CDN and DNS
infrastructure (`akamaiedge.net`, `cloudfront.net`, `root-servers.net`,
`gvt1.com`) rank highly while serving nothing at the apex. They cannot host a
directory. All densities above use the resolvable denominator; using the raw
count would understate deployment by about a fifth.

## Instrument corrections made during this run

Both were found because the pilot met the real internet, and neither was
visible from loopback testing.

**503 no longer triggers global backoff.** Large sites routinely return `503`
as a generic block with no rate-limit meaning. One such response paused all
workers for 30 seconds; throughput fell from 10/s to 3.2/s. Now only `429`, or
`503` carrying `Retry-After`, is treated as an instruction to slow down.

**Worker starvation.** Sixteen workers against an 8-second timeout caps
throughput at 2/s regardless of the configured rate. Raised so the rate limiter
binds instead of worker availability.

## Throughput, for planning

Observed 0.6–4.1 requests per second, degrading with rank as timeouts become
more common in the tail. The earlier estimate of "1M hosts in 7 hours at 40/s"
assumed a rate that this connection does not sustain; a full census would run
for days.

## What this implies for the study

**A 1M census is poor value.** Zero hits across 1,969 resolvable hosts in ranks
2,501–5,000, against multi-day runtime.

**Scan the top 50,000 instead.** It covers where the population appears to be,
completes in hours, and makes the rank-decay curve a result rather than a
footnote. It should also yield enough hits to fit the curve that five cannot.

**The research question moves.** It was: *do agents honour the declarations
that earn them privileged access?* On this evidence the prior question is
sharper and answerable without waiting for honeypot traffic: **what is the
signed lane actually granting access on, if the declarations meant to justify
it are absent in deployment?**

See `PREREGISTRATION.md` for how that revision is handled without dressing a
post-hoc hypothesis as a prior one.

---

# E1 — differential access

**Collected:** 10 September 2026. **Instrument:** `differential.py`.
**Design:** matched pairs, same origin, same URL, same User-Agent, same
session, randomised arm order, two repetitions.

  Arm A  unsigned
  Arm B  valid Web Bot Auth signature, key published at the study site and
         listed in no CDN directory
  Arm C  listed key — not obtainable; no claim about listed keys is made

## Broad sample: 200 top-ranked origins

| outcome | A unsigned | B signed | delta |
|---|---:|---:|---:|
| served | 100 | 96 | −4 |
| blocked | 7 | 12 | **+5** |
| challenged | 13 | 12 | −1 |

7/200 origins treated the arms differently. McNemar exact on served vs
not-served: b=5, c=1, **p=0.219 — not significant**. With 193 concordant pairs
there is no power, and the aggregate claim is therefore: *no significant effect
on access, with a directional imbalance toward blocking.*

**The signature is inert at 193 of 200 origins.** Where it is not inert, it
counts against the sender.

## Purposive sample: the 10 known implementers

3/10 reacted — chatgpt.com, openai.com, cloudflare.net — all blocking the
signed arm. b=3, c=0, p=0.250.

The other seven directory publishers (Forter, Check Point, Meta, Ahrefs,
FingerprintJS, Pocket Casts, BuiltWith) served both arms identically.

**Publishing a directory does not imply verifying signatures.** Those operators
sign outgoing requests; nothing at their edge inspects incoming ones. The
publisher and verifier populations are close to disjoint.

## Verification is a CDN edge behaviour

Attributing each reacting origin by response headers:

| origin | transition | fronted by |
|---|---|---|
| cloudflare.net | served → blocked | Cloudflare |
| chatgpt.com | served → blocked | Cloudflare |
| openai.com | served → blocked | Cloudflare |
| medium.com | challenged → blocked | Cloudflare |
| mts.ru | served → blocked | Qrator |

Two further differing origins (unity3d.com `served→error`,
triplinkintl.com `error→served`) are transient failures, not reactions, and are
excluded.

**Four of five reactions are Cloudflare; the fifth is Qrator.** No origin
reacted without a bot-management CDN in front of it.

It is not simply "all Cloudflare sites": **18 Cloudflare-fronted origins did not
react**, so verification depends on a customer-enabled configuration rather than
being a platform default.

## The claim this supports

> Among 200 top-ranked origins, a valid Web Bot Auth signature from a key absent
> from CDN allowlists produced no access benefit at any origin, and blocking at
> five — including the protocol's originating CDN and a major agent operator.
> Every reaction occurred behind a bot-management CDN. Correct but unadmitted
> implementation of the specification is weakly disfavoured relative to no
> implementation at all.

Defensible on this data without resting on significance: it is a claim about
composition and direction, not about a population rate.

## Limitation requiring work before this is load-bearing

The `challenged` classification has never been validated against real
interstitials. `medium.com` is recorded as `challenged → blocked`, which depends
on that classifier. The stored response bodies must be inspected by hand before
any claim distinguishing *challenged* from *served* is made.

---

# E2 — verification conformance: cannot be conducted from outside

**Attempted:** 10 September 2026 against `cloudflare.net`, an origin E1
identified as reacting to signatures.
**Result: inconclusive, and structurally so.**

## What happened

All 18 cases returned HTTP 200. An earlier version of the classifier scored a
200 as "signature accepted" and reported **ten conformance violations** —
expired signatures, replayed components, tampered signatures, HMAC in place of
Ed25519, all apparently accepted.

**Those were not findings.** `cloudflare.net/robots.txt` is a public file served
to every requester. The 200s meant the file was public, not that any signature
was verified. Publishing them would have been a false and damaging claim about
a security vendor's implementation.

The classifier now scores a bare 200 as `served_unconditionally` and refuses to
treat it as acceptance. The corrected run reports 0 checkable cases.

## Why no endpoint works

A conformance test requires an endpoint where **signature validity is
load-bearing**: one that refuses without a valid signature and serves with one.
Only then does varying a requirement reveal anything.

No such endpoint is reachable:

- **Public paths** serve everyone regardless. Signature never consulted.
- **Gated paths** refuse us regardless — E1 established that a valid signature
  from an unlisted key produces a *block* at these origins.

Signature validity is never the deciding variable for an unadmitted party. The
endpoint that would make it decisive exists only for keys on the allowlist.

## The finding

> The verification behaviour of deployed Web Bot Auth verifiers is unauditable
> by any party the gatekeeper has not admitted. Whether a deployed edge
> correctly rejects expired signatures, replayed nonces, uncovered authorities
> or algorithm confusion is not externally checkable — and the party deciding
> who may check is the same party whose implementation would be checked.

This completes the argument the other measurements build toward:

| measurement | door |
|---|---|
| Census | the accountability layer (declarations) is unpublished — 8/8 |
| E1 | access is decided by allowlist, not by cryptography |
| E2 | the allowlist-holder's implementation cannot be independently verified |

## The artifact still stands

The harness is RFC 9421 vector-validated, passes positive and negative controls,
and detects injected weaknesses exactly. It works against a conforming origin
and is ready for anyone with allowlist access — a CDN auditing itself, a
customer with a verifying configuration, or the working group.

**"We built the conformance test and it cannot be run from outside" is the
result**, not a failure to produce one.

## Instrument corrections from this attempt

**Git Bash path conversion.** MSYS rewrote `--path /robots.txt` into
`C:/Program Files/Git/robots.txt`, producing an unreachable host. Every case
errored, which looked exactly like an origin refusing all traffic. Run with
`MSYS_NO_PATHCONV=1`.

**A bare 200 is not acceptance.** The single most dangerous classifier defect in
this codebase, since it manufactures findings against origins that never
verified anything. It surfaced because *every* case passed while the control
also passed — a pattern that should always be treated as suspect rather than
as a result.

---

# E1 at scale — the effect is real

**Interim, 1,943 of 10,000 origins.** Reported here because the result reversed
a previous conclusion and the reason matters.

## Result

Among **1,414 origins where both arms produced a definite outcome**:

| transition | n |
|---|---:|
| served → blocked | 51 |
| challenged → blocked | 10 |
| blocked → served | 2 |

**McNemar exact, blocked vs not-blocked: b=62, c=2, p ≈ 9×10⁻¹³.**

A valid Web Bot Auth signature from a key absent from CDN allowlists is
**strongly and significantly associated with being blocked** — 31 origins
penalised it for every 1 that rewarded it. Roughly 4.4% of origins actively
disadvantage correct protocol implementation.

## Why an earlier run said the opposite

A configuration at 96 workers with a 6-second timeout produced **b=17, c=17** —
an apparently clean null.

That was not the truth. It was error noise cancelling itself. Timeouts
generated spurious `error → served` and `served → error` transitions at roughly
equal rates, and those swamped the real signal. Only 29% of origins yielded a
definite outcome in both arms.

Reducing concurrency to 28 workers and raising the timeout to 12 seconds lifted
the clean rate to ~71% **at the same throughput** — the aggressive
configuration was not faster in any useful sense, it was spending requests on
timeouts and recording them as observations.

**The same experiment produced a false null at 29% data quality and
p < 10⁻¹² at 71%.** More requests yielded a worse answer.

## Consequences for the analysis

**An errored arm is missing data, not an outcome.** A timeout says nothing
about how an origin treats a signature. Pairs with an error in either arm are
excluded from every paired test, and the exclusion count is reported alongside
the result.

**The earlier compositional claim is superseded.** The 200-origin run supported
only "five origins reacted, and they were the implementers." This supports a
population-level claim with a significance test behind it.

**Data quality is a load-bearing parameter, not an implementation detail.** Any
replication that tunes for throughput without reporting its clean-pair rate can
reach the opposite conclusion from the same design.

---

# E1 final — 10,000 origins

**Collected 10 September 2026.** Matched pairs, randomised arm order, two
repetitions, identical User-Agent and session; the arms differ only in whether
a valid Web Bot Auth signature is present.

## Sample

| | |
|---|---:|
| origins probed | 10,000 |
| clean pairs (definite outcome in both arms) | **7,267** (73%) |
| excluded — at least one arm errored | 2,733 |
| differing | 345 (4.75% of clean) |

Errored arms are missing data, not outcomes, and are excluded from every paired
test. The exclusion count is reported rather than absorbed.

## Result

| transition | n |
|---|---:|
| served → blocked | 270 |
| challenged → blocked | 23 |
| served → **HTTP 402 Payment Required** | 20 |
| blocked → served | 7 |
| challenged → served | 4 |

**McNemar exact, blocked vs not-blocked: b=298, c=9, p ≈ 4.7 × 10⁻⁷⁶**
**McNemar exact, served vs not-served: b=301, c=13, p ≈ 2.3 × 10⁻⁷²**

298 origins blocked the signed request while serving the byte-identical
unsigned one. Nine showed the reverse. **4.1% of origins actively penalise
correct implementation of the specification.**

## The effect is one vendor

| CDN | blocking / clean origins | rate |
|---|---:|---:|
| **Cloudflare** | 268 / 2,612 | **10.3%** |
| Akamai | 0 / 155 | 0% |
| Imperva | 0 / 55 | 0% |
| DataDome | 0 / 57 | 0% |
| no CDN detected | 2 / 1,128 | 0.2% |

**268 of 298 blocking origins are Cloudflare — 90% of the effect.** Every other
bot-management vendor in the sample reacts to a valid Web Bot Auth signature
exactly as it reacts to no signature: not at all.

Web Bot Auth is not a web-wide trust layer being adopted unevenly. It is one
vendor's product feature, enabled by roughly a tenth of that vendor's
customers, and invisible everywhere else.

## The tollbooth

Twenty origins returned **HTTP 402 Payment Required** to the signed arm while
serving the unsigned one. Identifying yourself as an agent does not only risk
refusal: at some origins it triggers a demand for payment that anonymous
traffic never encounters.

The signed lane is not only a gate. It is also a till.

## What this establishes

The protocol exists so automated clients can prove their identity and be
treated accordingly. Measured across ten thousand origins, doing exactly that —
reading the draft, generating a keypair, publishing a conformant directory,
signing correctly — leaves a client **worse off than doing nothing**, unless a
gatekeeper has added it to a list.

The incentive the protocol was designed to create is inverted in deployment,
and the inversion is attributable to a single vendor's configuration.

---

# E1b — ruling out the confound, and what it revealed

E1 compared an unsigned request against one carrying three extra headers and
attributed the blocking to the signature. That attribution had an obvious
alternative explanation: **a bot-management edge might penalise any request
with unfamiliar headers**, in which case the finding is about header novelty
and not about this protocol at all.

Four arms, run against the 298 origins E1 observed blocking. Readings were
fixed in code before collection.

## Result

94 origins yielded a definite outcome in all four arms.

| arm | blocked | rate |
|---|---:|---:|
| A — unsigned (control) | 0 | 0.0% |
| B — valid Web Bot Auth signature | 91 | **96.8%** |
| C — decoy headers, same shape, unrelated names | 5 | 5.3% |
| D — Web Bot Auth header names, **invalid** values | 88 | **93.6%** |

| comparison | b | c | p | reading |
|---|---:|---:|---|---|
| A vs B | 0 | 91 | 8.1×10⁻²⁸ | signatures block |
| A vs C | 0 | 5 | 0.063 | unfamiliar headers alone barely block |
| **C vs B** | 1 | 87 | **5.8×10⁻²⁵** | **the effect is specific to Web Bot Auth** |
| **D vs B** | 0 | 3 | **0.25** | **validity makes no difference** |

## The confound is ruled out

Decoy headers of the same shape and size, carrying unrelated names, block at
5.3% where real signatures block at 96.8% (p ≈ 6×10⁻²⁵). The E1 finding is not
an artefact of sending unusual headers. It is specific to this protocol.

## The enforcement path does not verify

Arm D carries the real header names with syntactically invalid contents — a
malformed nonce and random bytes where the signature belongs. Anything actually
parsing and evaluating the signature rejects it for a different reason than it
rejects an unlisted key, and would not necessarily block.

**It blocks at 93.6%, statistically indistinguishable from a valid signature.**

The origins doing the blocking are matching on header names, not evaluating
cryptography. The observable behaviour is consistent with: *does this request
carry Web Bot Auth headers → is the keyid on our allowlist → no → block.* That
path never verifies anything. The signature could be random noise.

**At the enforcement point, the cryptographic apparatus does no work.**
Admission decides.

## Scope of the claim

This establishes that the *blocking* path ignores signature validity for keys
absent from the allowlist. It does **not** establish whether verification
occurs for admitted keys — that question is E2's, and E2 established it cannot
be answered from outside the allowlist.

The two findings interlock: the enforcement we can observe does not verify, and
the enforcement we cannot observe is the one we are asked to trust.

## Limitation

Only 94 of 298 origins produced a definite outcome in all four arms (32%). Four
arms multiply the chance that any one errors. The effect sizes are large enough
that this does not threaten the conclusions, but the exclusion rate is reported
rather than absorbed.

---

# E1 replication — a second client stack

**Collected 13 September 2026** from the same network as the original run
(`202.59.209.34`), inside a Kali VM: a different Python build, a different
OpenSSL, a different TLS fingerprint, different HTTP client behaviour.

## Result

| | laptop, Windows | Kali, Linux |
|---|---:|---:|
| origins | 10,000 | 1,500 |
| clean pairs | 7,267 (72.7%) | 1,068 (71.2%) |
| arm A blocked | 15.91% | 12.55% |
| arm B blocked | 19.88% | 16.29% |
| **paired difference** | **+3.98 pp** | **+3.74 pp** |
| McNemar b : c | 298 : 9 | 43 : 3 |
| p | 4.7 × 10⁻⁷⁶ | 4.6 × 10⁻¹⁰ |

## Client fingerprint is ruled out

The paired effect is +3.97pp on Windows and +3.74pp on Linux —
indistinguishable across two client stacks presenting different TLS
fingerprints to the same origins. The blocking is not a reaction to how our
client negotiates TLS. It is a reaction to the signature.

This closes an objection the first run could not answer, and it closes it with
an independently significant result rather than a consistency argument.

## Reputation recovery, and a second demonstration

The unsigned baseline fell from 15.91% to 12.55% between the two runs, two days
apart, with no measurement traffic in between. Source reputation recovered.

**The paired difference did not move** (+3.97 → +3.74).

This is the same methodological point the within-run drift analysis made,
arriving by the opposite mechanism: once as reputation *degraded* during a run,
once as it *recovered* between runs. Absolute block rates are a property of the
vantage. The paired difference is a property of the signature.

Two independent demonstrations, by opposite mechanisms, that the paired design
is robust to the confound most likely to be raised against it.

## What remains untested

`same_network: true`. Both runs used one IP in one country. **Network
reputation and geography are still untested**, and testing them requires a
genuinely different network — a machine elsewhere, or a cloud instance.

The limitation has narrowed rather than closed: from *"single vantage, single
stack, neither ruled out"* to *"stack ruled out, network untested."*

---

# E1c — response content and latency, re-analysed from E1

No new traffic. Every E1 observation already carried `bytes` and
`latency_ms`; neither had been analysed. The outcome codes answer *whether* an
origin served the request, not *what* it served.

## Result: a load-bearing null

Among **5,020** origins that served *both* arms (2xx carrying an actual body):

| | unsigned | signed |
|---|---|---|
| median body | 169,479 B | 168,719 B |
| smaller by >2% | — | 39 (0.8%) |
| larger by >2% | — | 35 (0.7%) |
| within ±2% | — | 4,946 (98.5%) |

Sign test p = 0.898. Wilcoxon z = +0.53, p = 0.599.

Latency, 5,162 pairs: signed slower 2,580, faster 2,582, sign test p = 0.989.
Median paired delta **−4 ms**.

**Why this matters more than it looks.** It rules out silent degradation as a
hidden middle ground, so the binary outcome coding behind the headline result
is not concealing a gradient — admitted or refused, with nothing in between.
It also rules out a *synchronous directory fetch on the request path*: an
origin retrieving our JWKS to verify would add a full network round trip, and
none did.

**What it does not show.** It is not evidence that verification is skipped.
Ed25519 verification costs tens of microseconds against a 1,200 ms median
latency and could not be detected here on any sample size. Anyone reading the
latency null as proof that the crypto is ignored is overreading it. That
question is what E4 exists to answer.

## Two origins refuse with a 200

| origin | unsigned (2 reps) | signed (2 reps) |
|---|---|---|
| `temu.com` | 318,826 / 318,797 | **2,889 / 2,889** |
| `skyscanner.it` | 185,927 / 159,925 | **708 / 708** |

Both return HTTP 200. Both, consistently across repetitions, hand the signed
request a near-empty body while serving the full page unsigned.

This is a refusal that no status code records, and it is invisible to every
outcome-based measurement of this protocol including our own. **4.1% is a
floor, not an estimate.**

## An artifact caught, and what it cost

The first pass reported **twelve** such origins. Five were manufactured by my
own analysis: `statistics.median` over two repetitions returns their *mean*,
so a single flaky fetch halved an origin's recorded size. `mail.ru`
(194,793 and 936), `kinopoisk.ru` (249,931 and 2,836) and `thalesgroup.com`
(146,165 and 212) each had one normal and one anomalous repetition.

It was caught because the shrinkage clustered at almost exactly 50% across
unrelated origins — `dome9.com` 126,703 → 63,351, `thalesgroup.com`
146,165 → 73,188 — which is not how content degradation behaves and is
precisely how averaging behaves.

Two further origins (`dome9.com`, `c-span.org`) entered the analysis because
a **`202 Accepted` with a zero-byte body** scores as `served`. Right for
counting outcome transitions, wrong for comparing content.

Four more (`runescape.com`, `comdirect.de`, `singular.net`, and `skyscanner`'s
own unsigned arm) vary between their own repetitions by up to an order of
magnitude — `comdirect.de` returned 1,273,409 B and then 106,347 B to the
*identical unsigned request*. Nine origins are now excluded on that ground.

The rule that replaced the average: **every signed repetition must fall below
every unsigned one**, and every observation must be a 2xx that carried bytes.
Two origins survive it.

*Both defects are recorded in PAPER.md §7 alongside the four found during
collection. A measurement paper that reports only the instrument defects it
found before publication is not describing how instruments actually behave.*

---

# The edge delivers the signature intact

Against an origin we control behind the same CDN (`/echo` on the instrumented
Worker), all three protocol headers arrive byte-identical:

```
signature survived edge  : True
signature-input survived : True
signature-agent survived : True
cf.botManagement         : null        (free tier — no verdict exposed)
tls / protocol           : TLSv1.3 / HTTP/1.1
```

Cloudflare neither strips nor rewrites them. **This closes an alternative
explanation for the headline result:** the blocking is a decision taken on the
headers as sent, not a side effect of the edge mangling them into something
malformed that then fails a parser.

## The impersonation experiment did not run here

Five arms against the Worker, 5 repetitions each: **all served**. Arm B (our
valid signature) was not blocked, so this origin does not reproduce the
enforcement seen in E1 and the impersonation comparison is undefined against
it — `cf.botManagement` is null on the free tier, so there is no verdict to
differentiate on.

Recorded as inconclusive rather than negative. The question — whether
admission is keyid matching rather than signature verification — needs an
origin with bot management enabled. E4 answers a neighbouring and arguably
more fundamental question without needing one.

---

# E4 — was verification ever possible? (design)

Everything above argues *from rates* that the enforcement path does not
evaluate the cryptography: E1b found invalid header values blocked at 93.6%
against 96.8% for a valid signature. A reviewer can propose alternatives —
fail-closed verification, caching, a different rule being tripped.

There is a way to remove the inference entirely.

Verifying an RFC 9421 signature requires the signer's public key. The only
route to ours is the directory named in `Signature-Agent`. Serve that
directory from an origin we control, log every retrieval with requester
address, ASN and User-Agent, then send one signed request to each of the
**298 origins that demonstrably react to signing** — the strongest available
target set, since a null across origins that ignore signatures would prove
nothing.

- **any fetch** → that origin obtained key material; verification was
  possible. Record who, and when relative to the request.
- **zero fetches** → no origin held the key at any point. Verification was not
  skipped but *impossible*, and admission is keyed on the presence of the
  headers rather than the cryptography they carry.

The second outcome converts the central claim from statistical to deductive,
for the cost of 298 requests.

**Anticipated objection, answered by design:** a verifier could have fetched
and cached the directory earlier. The key is published at this origin for the
first time for this experiment, so any prior fetch appears in the same log;
the counter is read before the run and reported.

**Side effect worth noting.** GitHub Pages serves our directory as
`application/octet-stream` — the one conformance dimension where all nine
measured operators conform and we did not. The Worker serves
`application/http-message-signatures-directory+json`, closing that gap.

---

# E4 — RESULT: verification was impossible, not merely absent

Collected 13 September 2026. Reading fixed in PREREGISTRATION.md *while the
run was in flight*, before any third-party fetch had appeared.

## The pairing that is the finding

| | |
|---|---|
| origins sent one validly signed GET | **298** (every origin that blocked the signed arm in E1) |
| **blocked** the signed request | **293 (98.3%)** |
| served | 4 (`adroll.com`, `thekitchn.com`, `wpzoom.com`, `24-hdx.com`) |
| `503` | 1 (`tele2.ru`) |
| **directory fetches by any third party** | **0** |

Send window 15:13:10Z – 15:23:39Z, plus a 150 s settle to 15:26:13Z.

**293 origins actively refused a signed request. Not one of them retrieved
the public key that would have told them whether the signature was valid.**

Verifying an RFC 9421 signature is not possible without the signer's key, and
the only route to ours is the directory named in `Signature-Agent`. No origin
took it. The refusal therefore cannot be a verification failure — there was
nothing to verify with. **Admission is keyed on the presence of the headers,
not on the cryptography they carry.**

E1b established this statistically (invalid values blocked at 93.6%, valid
signatures at 96.8%). E4 establishes it deductively. That is the difference
between "the rates are indistinguishable, so probably nothing is checked" and
"the key was never obtained, so nothing *could* be checked."

## Both records, independently

Two logs, because Workers KV `list`/`get` are eventually consistent and the
counter's read-modify-write is racy — an inconsistency observed directly
during setup (`total_fetches: 2` with one entry visible).

| record | coverage | events | third-party |
|---|---|---|---|
| Workers KV | whole run | 4 | **0** |
| `wrangler tail` | 15:11:59Z – 15:26:42Z | 2 | **0** |

The tail stream's final write at 15:26:42Z is *after* the settle window
closed, so its coverage spans the entire experiment. All four KV events are
ours: `curl/8.18.0` ×3 (setup verification) and `python-requests/2.33.1` ×1
(E4's own preflight), every one from `202.59.209.43`, ASN 9825. The counter
read 4 before the run and 4 after: **delta zero**.

## Threats, and what actually happened to each

1. **Cached from an earlier fetch.** The key was first published at this origin
   for this experiment, so any prior retrieval appears in the same log. The
   counter stood at 4 — all ours — before the first request was sent.
2. **Asynchronous verification after the response.** The log was read 150 s
   after the last request and the tail ran 3 minutes past that. Nothing.
3. **Key resolution by a path we do not serve.** Possible in principle, and the
   claim is scoped accordingly: no origin retrieved the key **from the location
   the protocol specifies**, which is the only location a conforming verifier
   is defined to use.
4. **Free-tier bot management.** Irrelevant here. The 298 requests went to
   third-party origins; our Worker only served the directory. This is exactly
   the question the impersonation experiment could not reach.

## A defect in my own filter, reported because it cuts the right way

The exclusion of our own fetches was meant to work on source address. It did
not: `api64.ipify.org` reported our egress as `202.59.209.34` while Cloudflare
recorded `202.59.209.43` — the machine leaves by different paths depending on
destination. Every logged entry therefore *passed* the address test as
"not ours" and was excluded on User-Agent alone.

This biases toward **over**-reporting third parties, not under-reporting them.
A filter tilted toward finding fetches found none. The null is robust to its
own bug, which is the only reason it is reportable as it stands; the address
comparison should be fixed against the Cloudflare-observed address before any
replication.

## Scope

This concerns **unlisted signers**. It does not show that Web Bot Auth cannot
be verified, that these origins verify nothing at all, or that operators on a
CDN allowlist are treated this way. For a signer outside the allowlist, the
signature is not evaluated, because it cannot be — and the request is refused
at 98.3% regardless.

---

# E1d — mechanism, tollbooth ownership, and determinism

Re-analysis of E1. No new traffic. Three dimensions that were recorded and
never read.

## 1. The mechanism is a challenge, not a block

Cloudflare names its action in `cf-mitigated`. Across 10,000 origins there is
exactly one value in the entire dataset:

| `cf-mitigated` | unsigned | signed |
|---|---:|---:|
| `challenge` | 941 | 1,252 |
| any other value | 0 | 0 |

**Signing draws 1.33× as many mitigations.** Origins mitigated *only* when
signed: **216**. Only when unsigned: **61**. A 3.5:1 asymmetry.

Cloudflare never issued a hard block to either arm. It issued a *challenge* —
an interactive proof a non-browser client cannot complete — which then
presents to the client as `403`. This is a sharper claim than "signed requests
are blocked": the signed lane routes a declared, correctly-implemented agent
into a challenge designed to exclude automation.

The irony is worth stating plainly in the paper. An agent that declares itself
honestly, in the manner the protocol prescribes, is 33% more likely to be
asked to prove it is a human.

## 2. The tollbooth is one publisher

Twenty Cloudflare origins answered the signed arm with `402` while serving the
unsigned one. They are not twenty independent adopters:

`allrecipes.com`, `bhg.com`, `eatingwell.com`, `ew.com`, `foodandwine.com`,
`health.com`, `investopedia.com`, `lifewire.com`, `marthastewart.com`,
`people.com`, `realsimple.com`, `seriouseats.com`, `southernliving.com`,
`thebalancemoney.com`, `thespruce.com`, `thoughtco.com`,
`travelandleisure.com`, `treehugger.com`, `verywellhealth.com`,
`verywellmind.com`

**All twenty are People Inc. brands** (formerly Dotdash Meredith, an IAC
operating business, renamed 31 July 2025) — Allrecipes, Better Homes &
Gardens, EatingWell, Entertainment Weekly, Food & Wine, Health, Investopedia,
Lifewire, Martha Stewart, People, Real Simple, Serious Eats, Southern Living,
The Balance, The Spruce, ThoughtCo, Travel + Leisure, TreeHugger, and two
Verywell properties.

**This is n = 1, not n = 20.** The correct statement is not "20 origins
operate a tollbooth" but "the largest digital publisher in the United States
has enabled pay-per-crawl across its portfolio, and it charges the signed
arm while serving the anonymous one." That is a more interesting finding and a
much smaller sample, and the paper must say both.

Three further origins returned `402` to *both* arms — `telegraph.co.uk`,
`allhen.online`, `mintmanga.one` — so their paywall is not signature-triggered
and they are excluded from the count.

**Not recoverable from this run:** `crawler-price` was not in the captured
header set, so the price distribution is unknown. Twenty targeted requests
would recover it.

## 3. The effect is policy, not sampling

Each arm ran twice. Of origins whose signed arm was ever blocked:

| | count |
|---|---:|
| blocked in **every** repetition | 1,439 |
| blocked in some but not all | 32 |
| never blocked | 8,529 |

**97.8% of blocking origins blocked consistently.** A reviewer proposing that
the effect is noise has to explain a 45:1 consistency ratio.

## 4. The vendor claim, hardened

The published table reported Akamai, Imperva and DataDome at 0% against
denominators of 155, 55 and 57. Under a deliberately *broader* Akamai
attribution — one that also counts `x-cdn: Akamai`, raising the denominator
from 155 to 294 — three Akamai origins block the signed arm. All three are
eBay properties (`ebay.co.uk`, `ebay.com.au`, `ebay.it`), and every one is a
single repetition out of two, with the other serving normally.

Requiring the effect to reproduce in both repetitions resolves it:

| CDN | clean pairs | blocked ≥1 rep | rate | blocked **both** reps | rate |
|---|---:|---:|---:|---:|---:|
| Cloudflare | 2,616 | 272 | 10.40% | **271** | **10.36%** |
| Akamai (broad) | 294 | 3 | 1.02% | **0** | **0.00%** |
| DataDome | 58 | 0 | 0% | 0 | 0% |
| Imperva | 55 | 0 | 0% | 0 | 0% |
| Sucuri | 6 | 0 | 0% | 0 | 0% |
| other | 4,238 | 24 | 0.57% | 16 | 0.38% |

Cloudflare loses one origin when consistency is required. Akamai loses all
three. **The vendor claim is stronger under the stricter criterion and under
the broader attribution**, which is the combination a hostile reviewer would
choose.

*The paper's current wording — "every other CDN in the sample blocks at 0%" —
is too strong as stated, because it depends on how Akamai is attributed. The
defensible claim is the consistency-stratified table above. Corrected.*

---

# E5 — the tollbooth, probed directly. It is not pay-per-crawl.

Collected 13 September 2026. 23 origins, unsigned then signed, every response
header captured rather than a whitelist.

**Correction to the E1d write-up above and to PAPER.md §4.7.** I described this
as pay-per-crawl. It is not. Probing the origins directly shows no Cloudflare
pay-per-crawl mechanism is involved: there is no `crawler-price` header, no
payment header of any kind, and no price anywhere in the response.

## The effect replicates independently

| | |
|---|---|
| People Inc. origins returning 402 to the signed arm only | **20 / 20** |
| unsigned arm at those origins | 200, all 20 |
| interval since E1 | 3 days |
| `Signature-Agent` used | the Worker, **not** the URL used in E1 |

Same result from a different agent URL three days later. This is a clean
independent replication of the strongest per-origin effect in the study.

## What the 402 actually contains

All 20 bodies are **byte-identical** (one SHA-256 prefix across all twenty),
served by Cloudflare. One configuration applied across the portfolio, which
independently confirms single-operator control.

The body is a human-readable page. Trimmed to the operative sentences:

> If you are a reader experiencing an access issue, please contact
> `support@people.inc` … If you would like to access our content for
> licensing, please contact `contentlicensing@people.inc`

**There is no machine-readable price, and no way for an agent to transact.**
The response tells a declared, correctly-signed agent that access requires
payment, and then supplies an email address for a human to write to.

This is the sharper finding, and it belongs with §4.2 rather than standing
alone. The protocol's *accountability* layer is unpublished; its *economic*
layer, at the one place in 10,000 origins where a payment status appears in
response to agent identity, is a mailto: link. An autonomous agent cannot pay,
cannot discover a price, and cannot proceed.

## HTTP 402 is used incoherently across the web

The three origins that answer *both* arms with 402 are not paywalls at all.
Three distinct meanings for one status code, in a sample of 23:

| origins | body | actual meaning |
|---|---|---|
| 20 People Inc. | licensing referral | pay — via email, to a human |
| `telegraph.co.uk` | "our security systems have detected some unusual activity… disable your VPN" | **a bot block** |
| `allhen.online`, `mintmanga.one` | `NOT FOUND IN THE ADDRESS` | **a routing error** |

Any measurement treating 402 as evidence of pay-per-crawl adoption would be
wrong on 3 of 23 origins, and wrong about the mechanism on all 23. We were,
until we read the bodies.

## Method note

The first run of this probe reported 2/20 rather than 20/20. `allow_redirects`
was set to `False` while E1 followed redirects, so 18 origins stopped at a 301
to `www` and never reached the origin that issues the 402. Caught because an
18-origin non-replication with two exact survivors is not what configuration
drift looks like. Recorded here because the corrected run is the one reported,
and because it is the third averaging-or-defaults defect this study has found
in its own instruments.

---

# Census consolidated — 12 operators, and a correction to §4.2

Collected 14 September 2026 by consolidating every scan run and re-probing
every operator found. **This corrects two claims in PAPER.md.**

## The population is larger than reported

The scan files overlap: three runs, 55,547 rows, **20,647 duplicate host
rows** (one file is a byte-copy of another, and `builtwith.com` appears three
times). Counting rows rather than distinct hosts inflates numerator and
denominator unequally.

| | reported | consolidated |
|---|---:|---:|
| distinct hosts | 30,600 | **34,900** |
| resolvable | — | 24,069 |
| operators found | 9 | **12** |
| density | 0.124% (top-5k pilot) | **0.0499%** (95% CI 0.0285–0.0871%) |

Seven operators the paper does not list: `fpjs.io` (5,805), `pocketcasts.com`
(11,819), `builtwith.com` (15,771), `cybershoke.net` (17,949), `you.com`
(20,949), `ptengine.jp` (21,622), `visually.io` (29,467).

## §4.1 is now answerable: the decay curve fits

| rank range | resolvable | found | density | 95% CI |
|---|---:|---:|---:|---|
| 1–1,000 | 777 | 4 | 0.515% | 0.200–1.316% |
| 1,001–5,000 | 3,257 | 1 | 0.031% | 0.005–0.174% |
| 5,001–10,000 | 4,308 | 1 | 0.023% | 0.004–0.131% |
| 10,001–25,000 | 10,440 | 5 | 0.048% | 0.020–0.112% |
| 25,001–50,000 | 5,287 | 1 | 0.019% | 0.003–0.107% |

`log10(density) = −1.734 − 0.448 · log10(rank)`, R² = 0.844 on 5 buckets:
**density falls ~2.8× per decade of rank.**

*Honest caveat:* the decay is not monotonic — the 10,001–25,000 bucket sits
above the two above it, and its confidence interval overlaps all of them. With
12 hits total, the slope is indicative. Report the table as the result and the
slope as a summary of it.

## THE CORRECTION: "0 of 9 publish any declaration field" is wrong

**Three of eleven reachable operators publish `purpose`:**

| operator | `signature_agent` | `purpose` |
|---|---|---|
| `chatgpt.com` | `https://chatgpt.com` | `"ai"` |
| `checkpoint.com` | `https://www.checkpoint.com` | `"security"` |
| `visually.io` | — | `"signed-agent"` |

The remaining eight serve a bare `{"keys": [...]}`. (`ptengine.jp` timed out.)

**Why the original claim was wrong, and it is not longitudinal drift.** The
10 September deep probe recorded `declared: {}` and `card_fields: []` for
`chatgpt.com` and `checkpoint.com` — but it was looking for a `web_bot_auth`
sub-object and a field list of `client_id`, `client_name`, `client_uri`. It
**never checked for `purpose`**, which is the registry draft's own field name.
The word does not appear anywhere in the stored probe output. So the data to
distinguish "newly added" from "always there and never inspected" does not
exist, and no four-day-change claim can be made. A re-probe in a month would
establish the longitudinal claim honestly; asserting it now would be inventing
a result out of an instrument defect.

**Fourth instrument defect, and the most consequential.** The other three
produced wrong numbers that were caught. This one produced a headline claim in
the paper that was wrong at the time of writing.

## What survives, and it is still the paper's thesis

The corrected claim is narrower and defensible:

> **No operator publishes a single behavioural declaration.** 0 of 11 publish
> `rate-expectation`, `rate-control`, `rfc9309-compliance`,
> `expected-user-agent`, `targeted-content` or `trigger`.

Three publish a one-word `purpose` — and one of those three, `visually.io`,
answers `"signed-agent"`, which restates the mechanism rather than declaring
anything about intent. So even the field that *is* published carries close to
no information in a third of its instances.

Nobody states a crawl rate. Nobody claims robots.txt compliance. Nobody names
the user agent they will present. The declarations that would *justify*
admission remain entirely unpublished — which is the claim the paper actually
needs, and it is now true as stated.

## New dimension: key validity windows

Two operators bound their keys in time; the other nine do not:

| operator | not-before | expires | window | status on 14 Sep 2026 |
|---|---|---|---|---|
| `chatgpt.com` | 2025-01-01 | 2026-09-20 | 627 d | **expires in 6 days** |
| `forter.com` | 2026-05-14 | 2028-12-31 | 962 d | expires in 840 days |

Nine of eleven publish keys with no expiry at all. Of the two that do, one
rotates on a horizon of days and the other on a horizon of years. There is no
shared practice here, and the specification mandates none — a key with no
`exp` is valid until the operator removes it, and nothing in the protocol tells
a verifier how long to cache it.

---

# CORRECTION: the effect is not one vendor. It is two.

The published claim — "Cloudflare-fronted origins block at 10.3%; Akamai,
Imperva and DataDome block at 0%; 90% of all blocking is Cloudflare" — treated
every non-Cloudflare blocker as noise in an "other" bucket. Reading that bucket
shows it is not noise.

Seventeen non-Cloudflare origins block the signed arm in **both** repetitions.
Seven of them return `Server: QRATOR` — Qrator Labs, an independent
DDoS-mitigation and WAF vendor with no relationship to Cloudflare.

Rates recomputed by vendor, requiring the block in every repetition:

| vendor | clean pairs | blocked both reps | rate | 95% CI (Wilson) |
|---|---:|---:|---:|---|
| Qrator | 51 | 7 | **13.73%** | 6.81–25.72% |
| Cloudflare | 2,616 | 271 | **10.36%** | 9.25–11.59% |
| other | 4,186 | 9 | 0.22% | 0.11–0.41% |
| Akamai | 294 | 0 | 0% | 0–1.29% |
| DataDome | 58 | 0 | 0% | 0–6.21% |
| Imperva | 55 | 0 | 0% | 0–6.53% |
| Sucuri | 6 | 0 | 0% | 0–39.03% |

**Qrator's point estimate is higher than Cloudflare's**, and the intervals
overlap: on this evidence the two are indistinguishable in behaviour, differing
only in how many origins each fronts. `uuWAF` blocks 1 of 1 and is reported
for completeness only; n=1 licenses nothing.

## Why this matters more than the original claim

"One vendor's feature" invites the reading that this is a Cloudflare
configuration quirk. Two unrelated vendors independently arriving at the same
treatment is a different and stronger claim: **presenting Web Bot Auth headers
is read as a bot signal by anti-bot infrastructure generally**, and two of the
seven vendors observed have implemented that reading while three have not.

It also removes a weakness. A reviewer could dismiss a single-vendor finding as
a bug report. A finding replicated across two independent commercial
implementations is a property of how the protocol meets deployed anti-bot
systems.

## What remains true about Cloudflare

Cloudflare still accounts for the overwhelming majority of *absolute* blocking
(271 of 287 consistent blocks) because it fronts 36% of the clean-pair sample
against Qrator's 0.7%. The concentration is real; the exclusivity was not.

Cloudflare also remains distinctive for reasons unrelated to rate: it authors
the registry draft, operates the verified-bot directory that decides admission,
and is the largest single operator inside that directory (below). Those are
governance facts, not rate facts, and the paper should keep them separate from
the enforcement measurement.

*Method note: the original 0% figures for Akamai, Imperva and DataDome survive
the recount. The error was in the residual bucket, not the named vendors — and
it came from labelling a bucket "other" and never reading it.*

---

# The admitted population, from Cloudflare's own directory

Source: Cloudflare Radar's verified-bot directory, via the community mirror
`microlinkhq/cloudflare-bot-directory` (698 entries, CC BY-NC 4.0, **not
affiliated with Cloudflare**). Provenance matters here: this is a scrape, and
every claim below is about what the published directory *records*.

This population is the one our census cannot see — operators already admitted
to the allowlist.

## Web Bot Auth adoption among admitted bots

**90 of 698 verified bots (12.9%) publish a `signatureAgentUrl`.** Across 69
distinct registrable domains.

## Our census sees a seventh of it, and mostly different operators

| | count |
|---|---:|
| Cloudflare-listed WBA domains | 69 |
| our census found | 12 |
| **in both** | **5** — `builtwith.com`, `chatgpt.com`, `meta.com`, `visually.io`, `you.com` |
| publish a directory, **not** on Cloudflare's list | 7 — `ahrefs.com`, `checkpoint.com`, `cybershoke.net`, `forter.com`, `fpjs.io`, `pocketcasts.com`, `ptengine.jp` |
| on Cloudflare's list, invisible to our census | 64 |

**Two findings, one methodological and one substantive.**

*Methodological.* An apex-domain census undercounts Web Bot Auth by roughly
5×, because signature agents are deployed on service subdomains and API
endpoints — `api.manus.im`, `bot.trychannel3.com`, `search.ai.cloudflare.com`,
opaque `keydirectory` hostnames — not at the registrable apex a Tranco-driven
scan visits. Any replication using our method inherits this floor, and it
should be stated as a limitation of the technique rather than a property of
deployment.

*Substantive.* **Publishing a key and being admitted are nearly disjoint.**
Seven of twelve operators that publish a conformant directory do not appear on
the list that grants access. Implementing the protocol correctly is neither
necessary nor sufficient for admission — which is the same claim §4.5 makes
from the access side, arrived at from the registry side.

## The gatekeeper is the largest tenant

| operator | WBA entries |
|---|---:|
| **Cloudflare** | **12** |
| Amazon | 9 |
| (unattributed) | 4 |
| everyone else | 1 each |

Cloudflare operates 12 of the 90 Web Bot Auth entries in the directory it
maintains — more than any other party, and 13.3% of the admitted cohort:
AI Search, AI Search External, Browser Run, Crawler, Radar URL Scanner,
Robots API, Web Scanner, two CustomerSLO Probers, and Daric2/3/4.

The company that authors the registry draft, operates the directory deciding
admission, and enforces at the edge is also the single largest occupant of the
lane it controls. This is a governance observation, not an accusation of bad
faith; it is reportable because no other party occupies all four roles.

## The behavioural declaration is recorded for almost nobody

Cloudflare's verification policy states the requirement plainly: a verified bot
must be one that *"obeys `robots.txt` and crawl directives, maintains
reasonable request rates, and has not been observed evading website owner
preferences or attacking sites."*

The directory records `followsRobotsTxt: true` for:

| population | with commitment recorded |
|---|---|
| all verified bots | 68 / 698 (**9.7%**) |
| the Web Bot Auth cohort | 5 / 90 (**5.6%**) |

And **three of those five are Cloudflare's own bots** (AI Search, Robots API,
Web Scanner). The non-Cloudflare remainder is two: Artsdata Crawler and
sourcedash.

**Read this carefully — `false` does not mean "violates robots.txt."** The
field is a boolean on every entry, never null, and it discriminates: GPTBot,
Applebot, Amazonbot, BingBot and Internet Archive are `true`. But DuckDuckBot
is `false` and is well documented as respecting robots.txt. So `false` records
*no asserted commitment*, not observed violation. Any stronger reading is
unsupported and would be defamatory.

The defensible claim is about the record, and it is enough: **the accountability
metadata that the registry draft defines, that Cloudflare's own policy makes a
condition of admission, is recorded for 5.6% of the Web Bot Auth operators
Cloudflare has admitted.** The declarations are absent from the operators'
directories (§4.2, 0 of 11) *and* absent from the gatekeeper's own register.
Neither side holds the accountability the protocol is premised on.

## One more irony, measured

`chatgpt.com` is simultaneously a Web Bot Auth operator in Cloudflare's
directory and an origin that blocked our validly signed request in both
repetitions of E1. An admitted participant in the signed lane refuses
signed traffic at its own edge.

---

# E6 — the admitted population, probed directly (n=82)

Collected 13 September 2026. Every `signatureAgentUrl` in Cloudflare's
verified-bot directory, fetched once. This is the population the paper
previously could not examine: operators already granted access.

**90 URLs probed. 82 served a parseable directory.**

## The paper's sharpest contrast, now at n=82 instead of n=12

| dimension | result |
|---|---|
| defined media type | **78 / 82 (95.1%)** |
| key algorithm OKP/Ed25519 | **82 / 82 (100%)** |
| distinct keys | 95 |
| keys reused across operators | **0** |
| **any behavioural declaration** | **0 / 82 (0%)** |

**Not one admitted operator declares a single behaviour.** Zero publish
`rate-expectation`, `rate-control`, `rfc9309-compliance`,
`expected-user-agent`, `targeted-content` or `trigger`. The only top-level
fields that appear anywhere in 82 directories are `purpose` (10) and
`signature_agent` (6).

Where the specification is machine-checkable, compliance is near-total.
Where it asks an operator to state what it intends to do, compliance is
exactly zero. That contrast held at n=12 from the undiscovered side; it holds
at n=82 from the admitted side, which is the sample that matters, because
these are the operators the gatekeeper has already vouched for.

## `purpose` is published by 12%, in an uncontrolled vocabulary

Ten of 82 publish it, in **eight distinct spellings for ten publishers**:

`rag` (2), `ai` (2), `agentic_commerce`, `Agentic Commerce Order P...`,
`Agentic Checkout`, `multi-service`, `monitoring`, `signed-agent`

Two operators writing `agentic_commerce` and `Agentic Checkout` mean roughly
the same thing and share no token. `signed-agent` and `multi-service` restate
the mechanism rather than the intent. There is no registry, no enumeration and
no validation, so the one declarative field that is published cannot be
aggregated, compared or enforced against.

## Key validity is the exception, not the rule

| | count |
|---|---:|
| keys carrying `exp` | 18 / 82 (22%) |
| keys carrying `nbf` | 19 / 82 (23%) |

Roughly three quarters of the admitted population publishes keys that never
expire. Nothing in the protocol requires an expiry or tells a verifier how long
to cache a directory, so those keys are valid until their operator removes
them.

## Key hygiene is genuinely good on the one dimension the draft mandates

95 distinct thumbprints across 82 operators and **zero reuse across hosts**.
The draft forbids sharing a signing key across purposes and nobody violates it.
Worth stating plainly: this population is not careless. It is careful about
everything a machine can check.

## 8 of 90 admitted operators cannot be verified at all

| host | what it serves |
|---|---|
| `web-bot-auth-directory.radar-cfdata-org...` | **404** — *Cloudflare Radar URL Scanner* |
| `crawl.corp.novellum.ai` | 404, "Cannot GET /.well-known/..." |
| `app.hark.com` | 403 |
| `windowsforum.com` | 403 Access Denied |
| `pureconsent.com` | 302 to HTML |
| `crawler.prod.quartr.cloud` | connect timeout |
| `www.sourcedashboard.co.uk` | connection refused |
| `signature-agents.twin.so` | connection refused |

**8.9% of the admitted population publishes a directory from which no verifier
could ever retrieve a key.** Admission does not appear to be conditioned on the
directory resolving — these operators are on the list that grants access while
serving a 404 at the only location the protocol defines for obtaining their
key.

Two details sharpen it. One of the eight is **Cloudflare's own** Radar URL
Scanner, so the party that maintains the directory has a broken entry in it.
And `www.sourcedashboard.co.uk` is one of only five entries in the entire Web
Bot Auth cohort with a recorded robots.txt commitment — one of the five most
accountable-looking entries is unreachable.

This complements E4 exactly. E4 showed that no origin *fetches* the key. E6
shows that for nearly one in ten admitted operators, fetching it would fail
regardless. Verification is neither performed nor, in these cases, possible.

## Recorded robots.txt commitment vs published declaration

Four of the 82 are recorded in the directory as `followsRobotsTxt: true`.
**None of the four publishes `rfc9309-compliance`** — or any other behavioural
field — in its own directory. The commitment exists only as a row in the
gatekeeper's private register, never as a statement the operator makes in the
place the protocol defines for making it.

---

# Blocking does not vary with site popularity

Consistent signed-only blocking, by Tranco rank band, over the 7,267 clean
pairs:

| rank band | origins | blocked | rate | 95% CI | Cloudflare penetration | rate among Cloudflare origins |
|---|---:|---:|---:|---|---:|---:|
| 1–1,000 | 675 | 17 | 2.52% | 1.58–4.00% | 24% | **9.3%** (15/162) |
| 1,001–2,500 | 1,121 | 53 | 4.73% | 3.63–6.13% | 42% | **10.7%** (50/469) |
| 2,501–5,000 | 1,680 | 43 | 2.56% | 1.91–3.43% | 27% | **9.2%** (42/457) |
| 5,001–10,000 | 3,791 | 175 | 4.62% | 3.99–5.33% | 40% | **10.7%** (164/1,528) |

The overall rate appears to alternate. It does not: **the rate among
Cloudflare-fronted origins is flat at 9.2–10.7% across the entire range**, and
the apparent variation in the left column tracks Cloudflare's share of each
band (24%, 42%, 27%, 40%) rather than any change in behaviour.

**What this rules out.** The natural alternative explanation for a 10% figure
is selection: that larger, better-resourced, more attacked sites tune their
defences harder and therefore block declared agents more. They do not. A site
at rank 500 behaves like a site at rank 9,000.

**What it implies.** Uniformity across three orders of magnitude of popularity
is the signature of a *setting* rather than a per-site judgement. Roughly one
in ten Cloudflare customers has a configuration enabled that penalises a
correctly signed agent, and that proportion is the same wherever you look. No
site in the sample appears to have decided this about Web Bot Auth
specifically; they enabled a bot-defence setting and this is what it does to
the protocol their CDN is standardising.

This also means the headline 4.1% is best read as a composition of two
quantities that should be reported separately: **Cloudflare's penetration of
the sample (36%) and the constant ~10% enforcement rate within it.** A
replication over a population with different CDN composition will get a
different headline rate from identical behaviour, and should report both.

---

# Validating the outcome classifier against what origins actually returned

The `challenged` classification was flagged as resting on a marker list never
checked against real interstitials. E1 retained response titles, so it can be
checked now.

## `blocked` is sound

Titles on the 5,237 observations classified `blocked` (401/403):

| title | n |
|---|---:|
| `Just a moment...` | 1,936 |
| `Access Denied` | 753 |
| `Attention Required! \| Cloudflare` | 574 |
| *(no title)* | 542 |
| `403 Forbidden` | 259 |
| `ERROR: The request could not be satisfied` | 152 |
| `Access Blocked`, `DDoS-Guard`, `Bloomberg - Are you a robot?`, … | rest |

Unambiguous. Note that the largest single category, `Just a moment...`, is
Cloudflare's **interactive challenge** delivered with a 403 status — which
independently corroborates E1d's finding that `cf-mitigated` is always
`challenge` and never `block`.

## `challenged` is badly contaminated

Of 1,493 observations classified `challenged` (200 + a marker string), only
**38** carry a title that plainly indicates one (`Bot Verification`). 417 have
no title. The remainder are ordinary pages:

`Likee - Short Video Community`, `WhatsApp | Secure and Reliable…`,
`Stream and listen to music online for free with SoundCloud`,
`Latest news, sport and opinion from the Guardian`, `The Movie Database (TMDB)`,
`ImageShack…`

These are not interstitials. They are pages that happened to contain a marker
string somewhere in the first 8 KB — in body text, or in JavaScript. **The
false-positive rate of the `challenged` class is high**, and the earlier
suspicion about `medium.com` was not an isolated case but an instance of a
systematic problem.

## Why the headline result is unaffected, provably

The McNemar predicate is binary on `blocked`. Decomposing both counts:

| | total | composition |
|---|---:|---|
| **b** (A not blocked → B blocked) | **298** | 270 from `served`, 23 from `challenged`, 5 from transient errors |
| **c** (A blocked → B not blocked) | **9** | 7 to `served`, 1 to `http_503`, 1 to `challenged` |

These are exactly the published figures. A page wrongly labelled `challenged`
when it was really `served` moves **within** the not-blocked category, so it
cannot change either count. The headline is therefore robust to the classifier
defect by construction, not by luck.

**What the defect does invalidate:** any analysis that treats `challenged` as
an outcome in its own right. None is reported. The 23 `challenged → blocked`
transitions inside b are correctly counted whatever arm A really was, because
all that is asserted of arm A there is that it was *not* blocked.

**For replication.** A classifier that keys on body markers to distinguish an
interstitial from a served page should not be trusted without validating
against captured interstitials. Ours would have produced a materially wrong
number for any claim built on `challenged`, and the only reason it did not is
that the design never needed that class. Prefer status code plus a mitigation
header where one exists; `cf-mitigated` turned out to be a far cleaner signal
than any body heuristic.

---

# CORRECTION: the signed lane does work. At three origins out of 7,267.

PAPER.md §4.5 asserted: *"No origin, anywhere in the sample, granted better
access for presenting a valid signature."* That is false, and it is falsifiable
by inspection of data already collected, which makes it exactly the kind of
absolute claim a reviewer finds first.

Applying the same consistency rule used everywhere else — the outcome must
reproduce in **both** repetitions of **both** arms:

| direction | origins |
|---|---:|
| unsigned blocked twice → **signed served twice** | **3** |
| unsigned served twice → signed blocked twice | 259 |

**86 : 1 against the signer.**

## The three that worked

| origin | unsigned (2 reps) | signed (2 reps) | CDN |
|---|---|---|---|
| `letelegramme.fr` | 403 `Just a moment...` ×2 | 200, 332,943 B ×2 | Cloudflare |
| `nettiauto.com` | 403 `Just a moment...` ×2 | 200, 542,436 B ×2 | Cloudflare |
| `manomano.fr` | 403 `Just a moment...` ×2 | 200, 524,295 B ×2 | Cloudflare |

All three are Cloudflare. All three showed the anonymous client an interactive
challenge, twice, and served the signed client the full page, twice. **This is
the signed lane doing precisely what it is advertised to do**, and it is the
only place in 7,267 origins where that happens.

That it is Cloudflare in both directions matters: the same vendor whose default
configuration penalises signed requests at ~10% also hosts the only origins
where signing helps. The difference is configuration, not capability. Roughly
one Cloudflare customer in a thousand appears to have configured the lane the
way the protocol intends; about one in ten has configured it to do the
opposite.

## Why the four eBay origins are excluded

`ebay.com`, `ebay.de`, `ebay.ca`, `ebay.fr` also show `blocked → served` in the
aggregate, but their unsigned arm blocked **once of two** and served the other
time — the same Akamai flakiness that produced three spurious Akamai "blocks"
in the vendor table. Their signed arm served both times. There is no evidence
signing changed anything; the unsigned arm is simply unstable. Excluded, and
`kariyer.net` and `carview.co.jp` likewise for mixed outcomes.

## The claim that replaces it

> Three origins of 7,267 (0.04%) consistently admitted a signed request they
> refused unsigned. 259 did the reverse. Presenting a valid Web Bot Auth
> signature is **86 times more likely to lose access than to gain it.**

This is stronger than the absolute version, not weaker. It is exact, it
survives inspection, it quantifies the asymmetry rather than asserting a
universal, and it concedes the mechanism works — which makes the finding about
*deployment* rather than about the protocol being broken. An absolute claim
that a reviewer can falsify with one counterexample costs more credibility
than the counterexample costs the argument.

---

# E7 — which header is the bot signal? It is `Signature-Input`.

Collected 13–14 September 2026. 298 origins that block a signed request, five
arms each, arm order randomised per origin, 1,490 requests. 296 origins clean
on all five arms. Every arm carries only our own key and our own identity.

| arm | what it sends | blocked | rate | 95% CI |
|---|---|---:|---:|---|
| A | no protocol headers | 8 | **2.70%** | 1.38–5.24% |
| B | `Signature-Agent` only | 270 | **91.22%** | 87.44–93.94% |
| C | `Signature-Input` only | 287 | **96.96%** | 94.32–98.39% |
| D | `Signature` + `Signature-Input`, no identity | 287 | **96.96%** | 94.32–98.39% |
| E | all three, valid | 288 | **97.30%** | 94.76–98.62% |

Paired McNemar, same origins:

| comparison | b | c | p |
|---|---:|---:|---|
| A → E — does the protocol block at all? | 280 | 0 | 1.0×10⁻⁸⁴ |
| A → B — identity alone vs nothing | 262 | 0 | 2.7×10⁻⁷⁹ |
| A → C — metadata alone vs nothing | 279 | 0 | 2.1×10⁻⁸⁴ |
| **C → E — is metadata alone weaker than the full protocol?** | 3 | 2 | **1.0** |
| **D → E — does removing identity matter?** | 2 | 1 | **1.0** |
| B → E — is identity alone weaker? | 18 | 0 | 7.6×10⁻⁶ |
| **B → C — identity vs metadata** | 17 | 0 | **1.5×10⁻⁵** |

Note `c = 0` almost everywhere: the arms are near-perfectly nested. Every
origin blocked by a weaker arm is blocked by a stronger one.

## The result

**`Signature-Input` alone is statistically indistinguishable from a complete,
valid Web Bot Auth signature** (96.96% vs 97.30%, p = 1.0). It reproduces
99.7% of the effect.

`Signature-Input` contains no identity, no operator URL and no cryptographic
proof. It is a list of which message components are covered, a creation
timestamp, an expiry and a key identifier. It is the *metadata about* a
signature, not a signature.

**Removing the identity header entirely changes nothing** (arm D vs E,
p = 1.0). **The identity header alone is significantly weaker** than the
metadata header (91.22% vs 96.96%, p = 1.5×10⁻⁵) — 17 origins block on
`Signature-Input` that do not block on `Signature-Agent`, and none the reverse.

So the thing being matched is not the operator's identity, not the
cryptographic proof, and not the combination. It is the literal presence of the
header name `Signature-Input`.

## The complete chain, four experiments

Each rules out one candidate explanation, and together they leave exactly one:

| ruled out | evidence |
|---|---|
| the signature is invalid | arm E is valid and blocked at 97.30% |
| the cryptography is being checked | E1b: WBA names with **garbage values** block at 93.6% vs 96.8% valid |
| verification is even possible | E4: **0 of 298** origins ever fetched the public key |
| origins dislike unfamiliar headers | E1b decoy arm: same shape, same size, unrelated names — **5.3%** |
| the operator's identity is being read | E7: dropping `Signature-Agent` entirely changes nothing (p = 1.0) |

**What remains:** a string match on a header name. The protocol's own metadata
header is being used as a bot fingerprint.

## What this means

Web Bot Auth exists to replace user-agent trust — a system where an
unauthenticated string in a header determines how a client is treated. In
deployment, for an unlisted signer, it has reproduced that system exactly. The
string is `Signature-Input` instead of `User-Agent`, and the consequence is
inverted (declaring gets you refused rather than admitted), but the mechanism
is identical: **an unauthenticated header name, matched literally, decides
access.** The Ed25519 machinery beneath it is inert.

For an implementer the practical statement is blunt: sending
`Signature-Input` — with or without a valid signature, with or without an
identity — carries a ~97% probability of refusal at origins that react to Web
Bot Auth at all, against a 2.70% baseline.

## Caveats

Arm C sends `Signature-Input` without `Signature`, which is malformed under RFC
9421, so "origins reject malformed signature metadata" is a competing reading.
E1b disposes of it: **decoy headers of the same shape and size with unrelated
names blocked at 5.3%**, and WBA header names carrying syntactically invalid
values blocked at 93.6%. Malformedness is not what is matched; the name is.

The population is 298 origins already known to react to signing, chosen so a
null would be meaningful. These rates do not generalise to the web — 4.1% of
all origins react at all. What generalises is the *decomposition*: among
origins that do react, it is the header name that triggers them.

---

# E8 — a second network vantage. The effect replicates.

Collected 13–14 September 2026. The last structural limitation of the study
was that every measurement left one residential IP in one country.

**Method.** The matched pair is executed from a Cloudflare Worker instead of
the laptop: different ASN, different address, no shared request history with
these origins, and none of the reputation damage the laptop accumulated during
earlier collection. The private key never leaves the laptop — each request is
signed locally and only the finished headers are posted to the Worker, which
replays them. A leaked Worker secret would expose a public key and nothing
else.

Target population: the 298 origins that consistently blocked a signed request
from the laptop. Chosen for power. A random Tranco sample is useless here —
only ~4% of origins react at all, and a 50-origin pilot returned **b=0, c=0**,
which is an empty sample rather than a null.

## Result

198 clean pairs of 298 (66.4%), from colo DAC.

| population | arm A unsigned | arm B signed | paired diff | McNemar |
|---|---:|---:|---:|---|
| all clean pairs (198) | 20.71% | **94.44%** | **+73.74 pp** | b=146, c=0, p = 2.2×10⁻⁴⁴ |
| Cloudflare-fronted (183) | 21.31% | 95.63% | +74.32 pp | b=136, c=0, p = 2.3×10⁻⁴¹ |
| **not Cloudflare (15)** | 13.33% | 80.00% | **+66.67 pp** | b=10, c=0, p = 0.0020 |

**`c = 0` in every split.** Not one origin blocked the unsigned arm while
serving the signed one. The effect is entirely one-directional from this
vantage, as it was from the laptop.

## What this licenses, and what it does not

**Licensed:** the paired effect is not a property of the laptop's address, its
country, its ISP, or its accumulated reputation. It reproduces from a network
with no history at these origins, at p = 2.2×10⁻⁴⁴. Combined with the earlier
Linux/OpenSSL replication that ruled out client fingerprint, and the two
demonstrations that the paired difference is invariant to baseline drift, the
single-vantage limitation is closed.

**Not licensed — the magnitude is not comparable to the headline.** The
+73.74 pp here is measured on a population *selected for blocking*, where arm B
is near ceiling by construction. The laptop's +3.97 pp was across 10,000
unselected origins, of which only ~4% react at all. **These two numbers must
never be placed side by side as though they measured the same quantity.** What
replicates is the direction, the one-sidedness (c=0) and the significance, on
the same origins from a different network.

**The confound, addressed rather than assumed away.** This traffic originates
inside Cloudflare's network, and Cloudflare-to-Cloudflare routing could differ
from the public internet. The non-Cloudflare subset is the clean test, and it
holds: +66.67 pp, p = 0.0020, c=0. It is only 15 origins, so it is the weakest
row in the table and is reported as such — but its direction and one-sidedness
match the other 183 exactly.

**Arm A is higher here than on the laptop** (20.71% vs 12.55–15.91%), which is
expected: this population was selected for being defensive, so its unsigned
baseline is elevated relative to a random sample. It is not evidence that the
edge has worse reputation than the laptop.

## Two defects found and fixed in this instrument

1. **`cf-ray` is meaningless as CDN attribution from inside Cloudflare.** The
   edge adds it to responses it proxies on the Worker's behalf, so the first
   run reported **28 of 28** origins as Cloudflare-fronted. Attribution now
   comes from the laptop run, where the header means what it says. Caught
   because 100% Cloudflare is implausible against a known ~36% share.
2. **Zero discordant pairs was being read as a null.** McNemar uses only b and
   c, so b=c=0 gives p=1 by construction — no information. The 50-origin pilot
   printed "the effect DOES NOT replicate" on exactly that basis, which would
   have been a fabricated negative result. The reading now requires at least 10
   discordant pairs before claiming anything in either direction.

The second is the more dangerous of the two: it would have produced a confident
false negative on the study's most contested claim, and it was wrong in the
direction that looks like scientific caution.

---

# Persistence, and the instrument's test–retest reliability

Both figures come from data already collected; no new traffic.

## The effect persists

The 298 origins were identified as consistent blockers on **10 September**.
E7's arm E sent each of them a full valid signature on **13–14 September**:

| | |
|---|---:|
| re-probed | 297 |
| **still blocking** | **289 (97.3%)** |
| no longer blocking | 8 |

The eight: `rutube.ru`, `adroll.com`, `ebay.com.au`, `trulia.com`,
`wpzoom.com`, `scirp.org`, `24-hdx.com` (all now `served`) and `tele2.ru`
(`503`).

The effect is not a transient configuration state, a momentary reputation
score, or an artifact of one afternoon's collection. It is stable over days.

## Two independent probes agree

E4 and E7 measured the same 298 origins independently on 13 September, with
different tooling, different user-agents and different request counts:

| | |
|---|---:|
| both recorded `blocked` | 288 |
| disagreed | 5 |
| **agreement** | **98.3%** |

The five disagreements: `rutube.ru`, `ebay.com.au`, `trulia.com`, `scirp.org`
(E4 blocked, E7 served) and `thekitchn.com` (E4 served, E7 blocked).

**This is a test–retest reliability figure for the whole measurement chain**,
and it is worth reporting for its own sake: measurement papers in this area
rarely provide one. 98.3% agreement between independent probes bounds how much
of the observed variation is instrument noise rather than origin behaviour.

Note that three of the five disagreeing origins — `ebay.com.au`, `rutube.ru`,
`trulia.com` — were already flagged as inconsistent in the E1 repetition
analysis. **The instability is a property of those origins, not of the
instrument**, which is exactly what a reliability check should be able to
distinguish and what the consistency rule used throughout was designed to
handle.

---

# E9 — the match is on the exact registered name

150 origins, four arms, order randomised, 148 clean on all arms. The three
header arms carry an **identical value**; only the spelling of the name varies.

| arm | header name | blocked | rate |
|---|---|---:|---:|
| A | *(none)* | 5 | 3.38% |
| B | `Signature-Input` | 143 | **96.62%** |
| C | `X-Signature-Input` | 15 | 10.14% |
| D | `Signature-Inputs` | 16 | 10.81% |

Paired, same origins:

| comparison | b | c | p |
|---|---:|---:|---|
| A → B | 139 | 1 | 2.0×10⁻⁴⁰ |
| C → B | 128 | 0 | 5.9×10⁻³⁹ |
| D → B | 128 | 1 | 3.8×10⁻³⁷ |
| A → C | 11 | 1 | 0.0063 |
| A → D | 12 | 1 | 0.0034 |

## Reading, which is not the clean binary the script expected

**The dominant mechanism is an exact string match.** Adding a one-character
suffix (`Signature-Inputs`) or an `X-` prefix collapses the effect from 96.62%
to ~10%, with 128 origins reversing and 0–1 going the other way. Of the
93.24 pp the registered name produces over baseline, the variants reproduce
**6.76 pp — about 7%**. Roughly 93% of the effect is specific to the exact
registered spelling.

**But the variants are not at baseline.** 10.14% and 10.81% against 3.38%,
both significant (p = 0.0063, p = 0.0034). A minority of origins — on the order
of one in ten — react to something broader than the exact name, presumably a
heuristic over signature-shaped or unfamiliar headers. That is consistent with
E1b's decoy arm at 5.3% and slightly above it, which makes sense: these headers
are more signature-like than the decoys were.

So the honest statement is two-part, and the script's automatic reading of
"Mixed" was right to refuse the clean answer:

> Roughly 93% of the effect is a literal deny-list entry keyed on the
> protocol's own registered header name. A residual ~7 pp above baseline
> indicates a minority of deployments using a broader heuristic.

## Why this matters for the paper's closing argument

E7 showed the trigger is a header name rather than identity or cryptography.
E9 shows *which* string, and how literally. **The header the specification
defines has been added to a bot signature list**, matched close to exactly.

That is a stronger and more actionable finding than "signed requests get
blocked". It means the mechanism is not an emergent property of anti-bot
heuristics meeting unusual traffic — it is a specific entry, naming a specific
protocol, that somebody wrote down.

It also means the finding is trivially falsifiable by the vendors, which is a
virtue: if Cloudflare or Qrator state that no such rule exists, that claim is
checkable against this table, and the disclosure asks them directly.

---

# E10 — the deny-list catches RFC 9421, not Web Bot Auth

Collected 14 September 2026. 150 origins, four arms, order randomised.
**This is the widest finding in the study and it changes what the paper is
about.**

## The defect that prompted it

Web Bot Auth is RFC 9421 plus two things: a `Signature-Agent` header, and a
`;tag="web-bot-auth"` parameter inside `Signature-Input`.

Our signer emits that tag by default (`wba/signature.py`:
`tag: Optional[str] = WEB_BOT_AUTH_TAG`). **E7 and E9 both sent it without it
being noticed.** E7's arm D was described at the time as "a proof with no
identity" and treated as generic RFC 9421. It was not: it carried an explicit
Web Bot Auth marker in the signature parameters. Caught while attempting to
write up a claim that rested on it.

## Result

| arm | what it sends | blocked | rate |
|---|---|---:|---:|
| A | nothing | 4 | 2.67% |
| B | `Signature-Input` **with** `tag="web-bot-auth"` | 143 | 95.33% |
| C | `Signature-Input`, **no tag, no agent** | 142 | **94.67%** |
| D | `Signature` + `Signature-Input` (no tag) + `Content-Digest` | 144 | **96.00%** |

| comparison | b | c | p |
|---|---:|---:|---|
| A → B | 140 | 1 | 1.0×10⁻⁴⁰ |
| A → C | 139 | 1 | 2.0×10⁻⁴⁰ |
| A → D | 141 | 1 | 5.1×10⁻⁴¹ |
| **C → B — does the tag matter?** | **1** | **0** | **1.0** |

**The Web Bot Auth tag makes no difference.** Tagged and untagged are
statistically identical.

## What this means

Arm C carries no Web Bot Auth marker of any kind — no `Signature-Agent`, no
tag. It is a bare RFC 9421 signed request. Arm D is the shape a real
integration sends: a digest of the body plus a signature over it, which is how
webhook verification and signed API calls are built.

**Both are blocked at ~95% against a 2.67% baseline.**

RFC 9421 is not a bot protocol. It is a general-purpose IETF standard for
signing HTTP messages, used for API authentication, webhook verification,
payment callbacks and inter-service authorisation. At these origins it cannot
be used at all.

**The finding is therefore not "Web Bot Auth adopters are penalised."** It is:

> An IETF Standards Track mechanism for authenticating HTTP messages is
> treated as a bot signature by anti-bot infrastructure. Any client presenting
> `Signature-Input` — for any purpose, bot or not — is refused at ~95% of the
> origins that react at all.

Web Bot Auth is caught because it is built on RFC 9421, not because it is Web
Bot Auth.

## Consequences for the earlier sections

**E7 and E9 stand, and their readings are unchanged**, because E10 shows the
tag they inadvertently carried is irrelevant (p = 1.0). Had the tag mattered,
both would have needed retraction. Their *descriptions* are corrected: they
tested `Signature-Input` carrying a Web Bot Auth tag, and E10 establishes that
this is equivalent to testing `Signature-Input` alone.

**E9's conclusion is strengthened.** It found the trigger is the exact header
name rather than a heuristic. E10 confirms it from the other direction:
changing the *value* of the header — removing the protocol marker entirely —
changes nothing, while changing the *name* by one character collapsed the
effect to 10%. The match is on the name and nothing else.

## Consequence for disclosure

This raises the stakes of the notification to Cloudflare considerably, and the
disclosure has been updated. The earlier items concerned how declared agents
are treated — a policy question. This is an operational one: **customers who
enable the setting are also blocking signed API traffic, webhook callbacks and
any other RFC 9421 integration**, and there is no reason to think they know
that. It is the item in the disclosure most likely to be acted on, because it
affects paying customers' own integrations rather than third-party crawlers.
