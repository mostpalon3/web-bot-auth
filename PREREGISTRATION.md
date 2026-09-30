# Pre-registration — Web Bot Auth deployment study

**Authors:** Sumit Sagar, Tanishka Sharma, Gautam Bajaj — Netaji Subhas University of Technology, New Delhi, India

This document is written in phases. Each phase is registered before its own
data collection, and each states plainly what was already known when it was
written. Phases are appended, never rewritten.

---

## §0 — Provenance, stated first because it constrains everything below

**The pilot census (10 September 2026) was exploratory. No hypotheses were
registered before it ran.**

That is a limitation, and it is recorded here rather than obscured. Nothing
from that census may be reported as a confirmed hypothesis test. Its results —
in `FINDINGS.md` — are descriptive: a first look at a population nobody had
measured, with confidence intervals and stated caveats, and no claim to have
tested anything.

**The hypotheses in §2 were formed after seeing that census.** Presenting them
as though they had preceded it would be HARKing — hypothesising after results
are known — and it is the specific failure this document exists to prevent. So:
they are declared post-hoc, dated after the census, and they will be tested on
**data not yet collected** (the top-50,000 census, E2, E3). That is a legitimate
and ordinary sequence: exploratory work generates hypotheses, confirmatory work
tests them on fresh data. It is only illegitimate when the two are blurred.

In the paper, the pilot appears as exploratory motivation. The confirmatory
claims rest on the later collections.

---

## §1 — Phase 1: pilot census

**Registered:** not registered in advance. Exploratory.
**Collected:** 10 September 2026.
**Question asked:** how many hosts publish a Web Bot Auth key directory, and
what do they publish?
**Result:** `FINDINGS.md`.
**Status:** complete. Reportable as description only.

---

## §2 — Phase 2: extended census

**Registered:** 10 September 2026, after Phase 1 and informed by it.
**Data:** not yet collected.

### Hypotheses

**H1 — deployment concentrates in the head of the ranking.**
Directory density declines monotonically with Tranco rank across the top
50,000, tested over the resolvable denominator.

*Origin: suggested by Phase 1, where four of five hits fell in the top 1,000
and 1,969 resolvable hosts in ranks 2,501–5,000 produced none. Five points
cannot establish this; 50,000 hosts can.*

**H2 — the declaration layer is deployed at a materially lower rate than the
key layer.**
Among hosts publishing a directory, the proportion publishing a Signature Agent
Card with at least one `web_bot_auth` field is below 50%.

*Origin: Phase 1 found 0 of 5. The 50% threshold is set now, before collection,
so the test cannot be tuned to the result.*

**H3 — operators are not predominantly AI agents.**
Among directory publishers classifiable by primary business, AI agent operators
are fewer than half.

*Classification is a judgement, so it is fixed in advance: categories are
{AI agent, search/SEO, security/fraud, platform/social, infrastructure/CDN,
other}, assigned from the operator's own public description of its primary
product, by two coders independently, with disagreements recorded and
Cohen's κ reported. Coding happens before density analysis so it cannot be
influenced by it.*

### Analysis

Wilson score intervals throughout — n per bucket is small and proportions are
extreme, where the normal approximation misleads. H1 by Cochran–Armitage trend
test across rank buckets. H2 and H3 as one-sided binomial tests against 0.5.

### Denominator

All rates over **resolvable** hosts. Hosts with no A record at the apex cannot
serve a directory; Phase 1 found these to be 19.3% of the frame, concentrated
in CDN and DNS infrastructure that ranks highly in Tranco because it is ranked
by query volume.

### Declared in advance

**0.124% is a lower bound, not a point estimate.** 11.4% of Phase 1 hosts
returned `403` to an unfamiliar client; a directory behind such a block is
invisible to this method. The paper says "lower bound" wherever it says a rate.

**HTTP 200 is not presence.** 9.6% of Phase 1 hosts returned 200 with non-JSON
for a path they had never heard of. Presence requires a parseable JSON document
containing keys or a card. Treating 200 as presence would overcount by roughly
two orders of magnitude.

### Stopping rule

Collection stops when the frame is exhausted or on a stated calendar date —
never when a result reaches significance.

### Exclusions

Hosts on `blocklist.txt`. Runs where the study page was unreachable during
collection, since the User-Agent would have pointed at nothing.

---

## §3 — Phase 3: verification conformance (E2)

**Registered:** 10 September 2026. **Data:** not yet collected.

Unchanged from the original registration except for the sampling frame, which
Phase 1 now supplies.

**H4 — origins accepting Web Bot Auth accept signatures the specification
requires them to reject.**

**H5 — acceptance is not uniform across requirements.** Requirements the
specification delegates to the origin — nonce uniqueness (§5.3), authority
binding (§5.7) — are accepted at higher rates than those enforced by the
cryptographic operation itself (§3.2, §2.5).

H5 is the substantive prediction: cryptographic checks are enforced by the
library, policy checks require the deployer to have acted. **A null result on
H5 is publishable and will be reported as such.**

**Frame:** origins identified as verifying Web Bot Auth, from the Phase 2
census. Not randomly sampled — results describe the enumerated population and
are not projected to the web. Stated in the abstract, not buried.

**Instrument validity:** `validate.py` must pass immediately before each
collection round — positive control (strict origin, zero findings), negative
control (four injected weaknesses, found exactly and only those), and the RFC
9421 test vector. A failed validation voids the round.

---

## §4 — Phase 4: declared against observed (E3)

**Registered:** 10 September 2026. **Data:** not yet collected.

**Contingent on Phase 2.** Phase 1 found no declarations at all. If Phase 2
confirms H2 strongly — say, under 10% of publishers issuing cards — then E3 has
almost nothing to check declared behaviour against, and running a honeypot for
months to measure compliance with declarations that do not exist would be a
waste of the collection window.

**Decision rule, fixed now:** if Phase 2 finds fewer than 20 directory
publishers with a parseable `rate-expectation` or `rfc9309-compliance` field,
E3 is descaled to a single-domain observational deployment reported as
supporting material, and the paper rests on Phases 2 and 3.

**H6 — directory-publishing agents violate their own declarations**, measured
against randomised robots.txt arms. Only tested if the decision rule permits.

Allocation seeds are recorded in `honeypot/manifests/`, committed to git before
any traffic, so the arms are demonstrably fixed in advance.

---

## §5 — Ethics

Unchanged across phases.

- Institutional sign-off in writing before external collection.
- User-Agent carries a monitored address and a live study page; `scan.py`
  refuses to run externally against placeholders or an unreachable page.
- One request per host, no retries. Only `429`, or `503` with `Retry-After`, is
  treated as an instruction to slow down; the whole scan pauses when it is.
- Opt-outs honoured permanently, without argument, recorded in `blocklist.txt`.
- 90-day coordinated disclosure; operators notified before publication.
- Raw honeypot logs contain visitor IP addresses and are never published.
  Aggregates only.

---

## §6 — What would falsify the interesting claims

If Phase 2 finds cards widely deployed, H2 fails and the study becomes a
straightforward compliance measurement — E3 as originally designed.

If Phase 3 finds every origin rejecting every malformed signature, H4 fails and
the finding is that verification is sound in deployment. That is a useful,
publishable answer to a question nobody has asked, and the design does not
depend on finding failures.

Both are reported with the same prominence as the alternative.

---

## Amendments

Dated entries only. Nothing above is edited after its phase collects data.

| date | change | reason |
|---|---|---|
| 2026-09-10 | Restructured into phases; §0 added | Pilot ran before any registration. Recording that plainly, and separating exploratory from confirmatory, rather than presenting post-hoc hypotheses as prior ones. |
| 2026-09-10 | Frame reduced from 1M to top 50,000 | Phase 1: zero hits across 1,969 resolvable hosts in ranks 2,501–5,000, and observed throughput of 0.6–4.1/s makes 1M a multi-day run for little expected yield. |
| 2026-09-10 | E3 made contingent, with a numeric decision rule | Phase 1 found no declarations. Committing months of honeypot collection to checking declarations that may not exist would be poor use of the window. Threshold fixed now so it cannot be adjusted later. |

---

## E4 — directory retrieval. Reading fixed before the data.

Recorded 13 September 2026, while the run was in flight and before any
third-party fetch had appeared in the log. This section exists so that the
interpretation cannot be adjusted to whatever arrives.

**Question.** Did any origin retrieve the public key it would need in order to
verify a signature we sent?

**Design.** Our JWKS is served from an origin we control, at the media type the
specification defines, with every retrieval logged (address, ASN, User-Agent,
timestamp). One validly signed GET is sent to each of the 298 origins that
blocked the signed arm in E1 — the origins that provably react to signing.
Two independent records: Workers KV, and a `wrangler tail` stream, because KV
list/get are eventually consistent and the counter's read-modify-write is racy.

**Committed readings.**

*Zero third-party fetches.* No origin held the key material at any point
during the window, so verification of our signature was impossible rather than
merely absent. Admission is keyed on something other than the cryptography.
This is deductive, and is the reading we expect.

*One or more third-party fetches.* At least one origin obtained the key.
Report which ASN, with what User-Agent, and how the fetch timestamp relates to
the request that plausibly triggered it. This would weaken the E1b inference
and must be reported prominently rather than as an aside.

**Threats to the null, and how each is handled.**

1. *A verifier fetched the directory before this run and cached it.* The key
   was first published at this origin for this experiment, so any earlier
   fetch appears in the same log. The counter is read before the run and both
   values are reported. Our own preflight and verification fetches are
   excluded by source address, not by User-Agent alone.

2. *Verification happens asynchronously, after the response.* The log is read
   150 s after the final request, and the tail stream continues past that.

3. *A verifier resolves keys through some path we do not serve.* Possible in
   principle. The claim is therefore scoped to: no origin retrieved the key
   **from the location the protocol specifies**, which is the only location a
   conforming verifier is defined to use.

4. *Free-tier absence of bot management.* Irrelevant here. The requests go to
   298 third-party origins, not to our Worker; our Worker only serves the
   directory. This is why E4 answers a question the impersonation experiment
   could not.

**What a null does not license.** It does not show that Web Bot Auth cannot be
verified, that these origins verify nothing at all, or that listed operators
are treated this way. It is a statement about unlisted signers: for them the
signature is not evaluated, because it cannot be.
