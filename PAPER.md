# Paper outline — working draft

**Working title:** *Signed and Refused: What the Web's New Bot Identity Layer
Actually Grants*

**Target:** PETS (rolling quarterly deadlines) or ACM IMC. PETS Issue 4 closes
28 February 2027; the measurement is complete well before that.

**Status:** every claim below is mapped to evidence already collected, or
marked as still needed. Nothing here is written ahead of its data.

---

## The argument in one paragraph

Major CDNs now grant automated traffic a privileged "signed lane" on the
strength of Web Bot Auth, which layers agent identity over RFC 9421 and was
adopted onto the IETF Standards Track on 1 September 2026. The protocol is
presented as a cryptographic replacement for user-agent trust. We census
34,900 hosts for published key directories and run a matched-pair access
experiment against 10,000 origins. We find that the
accountability metadata the protocol defines is published by nobody; that a
valid signature grants better access at no origin in the sample and provokes
blocking at 298 of 7,267 (p < 10⁻⁷⁵), concentrated in two independent anti-bot vendors and
delivered as a challenge rather than a refusal; that one publisher's entire
portfolio answers a signed request with a demand for payment that no agent can
machine-read or satisfy; and that the
conformance of the checking origins cannot be audited by anyone the gatekeeper
has not admitted. We then show the refusal is not a verification failure: of
298 origins that block a signed request, **none ever retrieved the public key
that verification requires**, so the signature could not have been checked.
Finally we show the effect is not specific to Web Bot Auth at all: a bare
RFC 9421 signed request, carrying no agent identity and no protocol tag, is
refused at 94.67% against a 2.67% baseline, and so is the digest-plus-signature
shape a webhook or signed API call takes (96.00%). **An IETF Standards Track
mechanism for authenticating HTTP messages is being treated as a bot
signature.** Cryptography authenticates, but admission decides — and admission
is keyed on the presence of a header name, justified by declarations nobody
publishes, and open to inspection by nobody.

---

## 1. Introduction

**Claim:** the public framing of Web Bot Auth as a web-wide trust layer is not
what is deployed.

Motivating facts, all measured:
- **0 of 82 admitted operators declare any behaviour** - no rate, no robots.txt
  commitment, no user agent - while 95.1% serve the defined media type and 100%
  use the mandated key algorithm
- 8 of 90 admitted operators serve a directory no verifier could read
- across 7,267 matched pairs, 298 origins **blocked** a validly signed request
  while serving the identical unsigned one; 9 did the reverse (p < 10⁻⁷⁵)
- requiring the block to reproduce in both repetitions: **Qrator 7/51 (13.7%)
  and Cloudflare 271/2,616 (10.4%)** - two unrelated vendors, indistinguishable
  rates - against Akamai 0/294, DataDome 0/58, Imperva 0/55
- the only mitigation Cloudflare ever applies is `challenge` — a declared
  agent is asked to prove it is human, 1.33× as often as an anonymous one
- **`Signature-Input` alone reproduces the full effect** (96.96% vs 97.30%,
  p = 1.0): the trigger is a header name, not identity and not cryptography
- **a bare RFC 9421 request with no Web Bot Auth marker at all is blocked at
  94.67%** — the collateral is every non-bot use of HTTP Message Signatures
- one publisher's 20 brands answer the signed arm with **HTTP 402** and a
  `mailto:` - no price, no way for an agent to pay
- of 298 origins that block a signed request, **0 ever fetched the public key**
  that verification requires

## 2. Background

Web Bot Auth over RFC 9421. The registry draft and the Signature Agent Card.
Cloudflare's signed-agent policy, which conditions admission on behavioural
claims — obeying robots.txt, reasonable rates, honest self-identification.

**The standardisation record makes the same split the measurement finds.**
The identity mechanism was adopted as a working-group document on
1 September 2026 (`draft-ietf-webbotauth-httpsig-protocol-00`, Standards
Track). The accountability layer — the registry and the Signature Agent Card,
which define `purpose`, `rate-expectation`, `rfc9309-compliance` and the rest
— remains an individual submission (`draft-meunier-webbotauth-registry-03`,
26 June 2026, "I-D Exists"), unadopted. The signature is being standardised;
the declarations that would make the signature *mean* something are not.
§4.2 finds the identical split in deployment, arrived at independently: 9/9
operators implement the crypto, 0/9 publish a declaration.

**The gap this paper addresses:** the policy governs behaviour, the signature
attests identity, and nothing connects them.

### 2.1 Related work

Four adjacent literatures exist. None measures what a signature buys.

**Do bots obey the rules they are admitted under?** Liu et al., *Scrapers
Selectively Respect robots.txt Directives* (IMC 2025, arXiv:2505.21733),
instrument 130 self-declared bots over 40 days with controlled `robots.txt`
files: 60.9% honour crawl-delay but only 30.7% honour `Disallow`, and AI search
crawlers frequently never fetch `robots.txt` at all. *The Odyssey of robots.txt
Governance* (CCS 2025) reaches compatible conclusions for LLM bots. Both
measure **compliance given identity**. We measure the step before: what
identity is worth at the door, and whether the declarations that would make
compliance checkable are published at all. Their result is the reason ours
matters — admission conditioned on `robots.txt` compliance is admission
conditioned on something 69% of bots do not do.

**How much blocking is there, and who does it?** *Detecting Bot Detection*
(2026, arXiv:2606.14525) visits 10,000 sites in four browser configurations
(40K visits), finding 82% of blocks attributable to bot detection, Cloudflare
blocking 37% and Akamai 26% of headless Chromium, and — closest to our E7 —
that 75% of headless-only blocks come from header-level signals alone.

That paper is the sharpest available control for our vendor result. **Akamai
blocks headless browsers at 26% and signed requests at 0% (0/294).** Akamai is
therefore not passive about automation; it simply does not act on Web Bot Auth
headers. This disposes of the natural objection that our zero rates reflect
vendors without bot management rather than vendors that have declined to
enforce on this signal. Their header-level finding and our E7 also converge
from different directions: theirs that header signals dominate browser
fingerprint, ours that a single protocol header name reproduces the full
effect.

**Who is the agent?** *FP-Agent: Fingerprinting AI Browsing Agents*
(arXiv:2605.01247) and related work identify agents from observable behaviour
and browser surface. That line asks how to recognise an agent that does not
declare itself. We ask what happens to one that does, correctly and
cryptographically.

**Can publishers control crawling at all?** *Somesite I Used To Crawl*
(arXiv:2411.15091) surveys creator awareness and efficacy of `robots.txt`,
`noai` tags and reverse-proxy blocking; *ai.txt* (arXiv:2505.07834) proposes a
richer language; *Is Misinformation More Open?* (arXiv:2510.10315) measures
network-level and User-Agent-based blocking. These study the publisher's
instruments. Web Bot Auth is the first mechanism that moves the decision from
the publisher to a CDN allowlist, and that shift is what we measure.

**The gap, stated precisely.** No prior work runs a matched-pair signed-versus-
unsigned access experiment, measures whether verifiers retrieve the key
material verification requires, or audits the declaration layer of the admitted
population. Those are §4.5, §4.10 and §4.3 respectively.

## 3. Method

Three instruments, each validated before use.

**Census** — one HTTPS GET per host to the well-known path, 50,000 hosts from a
provenance-recorded Tranco list. Global rate limit, no retries, resumable.

**Differential access (E1)** — matched pairs at 10,000 origins, randomised arm
order, two repetitions, identical User-Agent and session. Arm A unsigned, Arm B
validly signed with a key published at our study site and listed in no CDN
directory. Arm C (a listed key) requires gatekeeper admission and is not
obtainable; no claim about listed keys is made. Pairs where either arm errored
are excluded as missing data and the exclusion count reported.

**Conformance (E2)** — 18 cases, each isolating one deviation from a cited
requirement. RFC 9421 test-vector validated; positive and negative controls.

**Validity.** The conformance harness reproduces RFC 9421's published Ed25519
test vector, accepts nothing against a strict origin, and detects exactly the
four weaknesses injected into a deliberately lax one. Instrument defects found
and corrected during collection are reported in §7.

## 4. Results

### 4.1 Deployment is concentrated and small
34,900 distinct hosts, 24,069 resolvable, **12 operators**. Density
**0.0499%** (95% CI 0.0285-0.0871%).

| rank range | resolvable | found | density | 95% CI |
|---|---:|---:|---:|---|
| 1-1,000 | 777 | 4 | 0.515% | 0.200-1.316% |
| 1,001-5,000 | 3,257 | 1 | 0.031% | 0.005-0.174% |
| 5,001-10,000 | 4,308 | 1 | 0.023% | 0.004-0.131% |
| 10,001-25,000 | 10,440 | 5 | 0.048% | 0.020-0.112% |
| 25,001-50,000 | 5,287 | 1 | 0.019% | 0.003-0.107% |

`log10(density) = -1.734 - 0.448*log10(rank)`, R^2 = 0.844: density falls
~2.8x per decade of rank.
**Evidence:** consolidated census. **Collected.**
*The decay is not monotonic - the 10,001-25,000 bucket sits above the two
above it and its interval overlaps all of them. With 12 hits the table is the
result and the slope is a summary of it, not a law.*

### 4.2 No operator declares any behaviour
**0 of 11 reachable operators publish a single behavioural declaration** - no
`rate-expectation`, no `rate-control`, no `rfc9309-compliance`, no
`expected-user-agent`, no `targeted-content`, no `trigger`. Nobody states a
crawl rate, claims robots.txt compliance, or names the user agent they will
present.

Three publish a one-word `purpose`: `chatgpt.com` (`"ai"`), `checkpoint.com`
(`"security"`), `visually.io` (`"signed-agent"`). The third restates the
mechanism rather than declaring an intent, so even the published field carries
almost no information in a third of its instances. Eight serve a bare
`{"keys": [...]}`.
**Evidence:** consolidated census + re-probe, 14 Sept 2026. **Collected.**

*This supersedes an earlier claim of "0 of 9 publish any declaration field",
which was wrong. The 10 September probe searched for a `web_bot_auth`
sub-object and a `client_*` field list, and never checked `purpose` - the
registry draft's own field name. Because the field was never inspected, the
data cannot distinguish recent adoption from four days of oversight, and no
longitudinal claim is made. Recorded in section 7 as the fourth instrument
defect and the only one that reached a headline claim.*

### 4.3 Conformance is high where machine-checkable, zero where declarative
Probing every `signatureAgentUrl` in Cloudflare's verified-bot directory gives
the **admitted** population, n=82 of 90 reachable:

| dimension | admitted population |
|---|---|
| defined media type | 78 / 82 (95.1%) |
| key algorithm OKP/Ed25519 | 82 / 82 (100%) |
| keys reused across operators | 0 of 95 distinct keys |
| **any behavioural declaration** | **0 / 82 (0%)** |

**Evidence:** E6. **Collected.**
*The paper's sharpest single table, and it now rests on the population the
gatekeeper has already vouched for rather than on 12 operators discovered by
apex scan. Where the specification is machine-checkable, compliance is
near-total; where it asks an operator to state its intent, it is exactly zero.
This population is not careless - it is careful about everything a machine can
check.*

`purpose` is published by 10 of 82, in **eight distinct spellings for ten
publishers** (`rag`, `ai`, `agentic_commerce`, `Agentic Checkout`,
`multi-service`, `monitoring`, `signed-agent`). No registry, no enumeration and
no validation: the one declarative field in use cannot be aggregated or
enforced against. Only 18 of 82 publish keys that ever expire.

### 4.3b One in eleven admitted operators cannot be verified at all
8 of 90 serve a directory no verifier could retrieve a key from: four 404/403,
one 302 to HTML, three unreachable. **Admission is not conditioned on the
directory resolving.** One of the eight is Cloudflare's own Radar URL Scanner;
another, `sourcedashboard.co.uk`, is one of only five entries in the cohort
with a recorded robots.txt commitment.
**Evidence:** E6. **Collected.**
*This complements section 4.10 exactly: no origin fetches the key, and for
nearly one in ten operators fetching it would fail regardless. Verification is
neither performed nor, in these cases, possible.*

### 4.4 Half the adopters are not AI, and Web Bot Auth defines "agent"
Classified by **Cloudflare's own category labels**, not ours, across the 90
Web Bot Auth entries in its verified-bot directory:

| category | n | share |
|---|---:|---:|
| AI_ASSISTANT | 32 | 35.6% |
| MONITORING_AND_ANALYTICS | 13 | 14.4% |
| AI_CRAWLER | 8 | 8.9% |
| SECURITY | 8 | 8.9% |
| SEARCH_ENGINE_CRAWLER | 7 | 7.8% |
| AGGREGATOR | 6 | 6.7% |
| OTHER | 5 | 5.6% |
| AI_SEARCH | 4 | 4.4% |
| SEO / ACADEMIC / SOCIAL / PAGE_PREVIEW | 7 | 7.8% |

**AI-related: 44 of 90 (48.9%). Not AI-related: 46 (51.1%).**

Public discussion of Web Bot Auth — the CDN documentation, the drafts, the
press — is framed almost entirely around AI crawlers. Half its adopters are
monitoring vendors, security scanners, SEO tools, aggregators and page-preview
fetchers: businesses that have run automated traffic for a decade and have
always had the identity problem this protocol addresses.

**But the adoption is genuinely AI-skewed relative to the baseline.** Across
all 698 verified bots only 12.9% are AI-related, against 48.9% of the Web Bot
Auth cohort — a 3.8x enrichment. Both statements are true and the paper should
make both: AI operators adopt this disproportionately, *and* half of who uses
it is not AI.

**Web Bot Auth has become the operational definition of "agent."** Cloudflare
splits its directory into `BOT` and `AGENT`:

| kind | uses Web Bot Auth | total | rate |
|---|---:|---:|---:|
| `AGENT` | **36** | 37 | **97.3%** |
| `BOT` | 54 | 661 | 8.2% |

Every entry Cloudflare classifies as an agent but one publishes a signature
agent URL. Whatever the protocol is nominally for, in this deployment it is
the thing that makes something an agent rather than a bot.
**Evidence:** Cloudflare verified-bot directory, 13 Sept 2026. **Collected.**

*No inter-rater reliability is reported for this table and none is needed:
the labels are the gatekeeper's, not ours, so there is no coding judgement to
be reliable about. Our own taxonomy is applied only to the 12 census-discovered
operators, where a second coder and κ remain outstanding. Using the
gatekeeper's categories has its own limitation — they are unaudited, assigned
by the party whose admission decisions we are studying, and we take them as
given rather than as ground truth.*

### 4.5 A valid signature grants nothing and costs a great deal
7,267 matched pairs. 298 origins blocked the signed request while serving the
identical unsigned one; 9 the reverse. **McNemar exact p ≈ 4.7 × 10⁻⁷⁶.**
4.1% of origins actively penalise correct implementation.
**Evidence:** E1 at 10,000 origins. **Collected.**
*The headline result.*

**The signed lane does work — at three origins.** Applying the consistency rule
used elsewhere (the outcome must reproduce in both repetitions of both arms),
3 origins of 7,267 admitted a signed request they refused unsigned, against 259
that did the reverse: **86:1 against the signer**. The three are
`letelegramme.fr`, `nettiauto.com` and `manomano.fr`, all Cloudflare, each
showing the anonymous client `Just a moment...` twice and serving the signed
client the full page twice.

*This supersedes an earlier claim that no origin anywhere granted better
access, which was false and falsifiable from data already collected. The exact
version is stronger: it concedes the mechanism works, which locates the finding
in deployment rather than in the protocol, and the same vendor appears on both
sides — about one Cloudflare customer in a thousand has configured the lane as
intended, about one in ten has configured it to do the opposite. The difference
is configuration, not capability.*

### 4.6 Two vendors enforce; three do not
Requiring the effect to reproduce in **both** repetitions:

| vendor | clean pairs | blocked both reps | rate | 95% CI |
|---|---:|---:|---:|---|
| **Qrator** | 51 | 7 | **13.73%** | 6.81-25.72% |
| **Cloudflare** | 2,616 | 271 | **10.36%** | 9.25-11.59% |
| other | 4,186 | 9 | 0.22% | 0.11-0.41% |
| Akamai (broad attribution) | 294 | 0 | 0% | 0-1.29% |
| DataDome | 58 | 0 | 0% | 0-6.21% |
| Imperva | 55 | 0 | 0% | 0-6.53% |

Qrator Labs is an independent DDoS-mitigation vendor unrelated to Cloudflare.
Its point estimate is **higher** than Cloudflare's and the intervals overlap:
the two are indistinguishable in behaviour, differing in how many origins each
fronts. Three Akamai origins block on one repetition of two, all eBay, and
none survives the consistency requirement.

*This supersedes an earlier claim that the effect was one vendor, which came
from bucketing every non-Cloudflare blocker as "other" and never reading the
bucket. Two unrelated commercial implementations arriving at the same
treatment is the stronger finding: presenting Web Bot Auth headers is read as
a bot signal by anti-bot infrastructure generally, and two of seven observed
vendors have implemented that reading. A single-vendor result could be
dismissed as a bug report; this cannot.*

Cloudflare still accounts for 271 of 287 consistent blocks in absolute terms,
because it fronts 36% of the sample against Qrator's 0.7%. The concentration
is real; the exclusivity was not.

**The mechanism is named in the data.** `cf-mitigated` carries exactly one
value across all 10,000 origins: `challenge`. Never `block`. Signed requests
draw 1.33× as many (1,252 vs 941); 216 origins are mitigated only when signed
against 61 only when unsigned, a 3.5:1 asymmetry. Cloudflare does not refuse
the signed request — it demands an interactive proof of humanity that a
declared agent cannot complete.
**Evidence:** E1 + E1d. **Collected.**
*Web Bot Auth is not a web-wide trust layer adopted unevenly. It is a bot
signal that two of seven anti-bot vendors have chosen to act on, enabled by
about a tenth of their customers, inert everywhere else — and the penalty it
imposes on honest self-identification is a CAPTCHA.*

### 4.7 The signed lane is also a tollbooth — operated by one publisher
20 origins returned **HTTP 402 Payment Required** to the signed arm while
serving the unsigned one. **All 20 are People Inc. brands** (formerly Dotdash
Meredith, an IAC business): Allrecipes, Investopedia, People, Serious Eats,
The Spruce, ThoughtCo, Lifewire, Better Homes & Gardens, Entertainment Weekly,
Food & Wine, Travel + Leisure, Southern Living, Real Simple, Martha Stewart,
EatingWell, Health, TreeHugger, The Balance and two Verywell properties.

**This is n = 1 publisher, not n = 20 adopters,** and the paper must lead with
that.

**And it is not pay-per-crawl.** Probing all 20 directly (E5) found no
`crawler-price` header, no payment header of any kind, and no price in the
body. All 20 responses are byte-identical - one configuration across the
portfolio - and the body is a human-readable page giving an email address:
*"If you would like to access our content for licensing, please contact
`contentlicensing@people.inc`."*

A declared, correctly-signed agent is told that access requires payment and
handed a `mailto:` for a human to write to. It cannot discover a price, cannot
transact, and cannot proceed. **The economic layer is as absent as the
accountability layer in section 4.2** - that is where this finding belongs.

**402 is used incoherently.** Of 23 origins returning it: 20 mean "email our
licensing team", `telegraph.co.uk` means "your connection looks suspicious,
disable your VPN" (a bot block), and `allhen.online` / `mintmanga.one` return
`NOT FOUND IN THE ADDRESS` (a routing error). Any study treating 402 as
evidence of pay-per-crawl adoption is wrong about the mechanism at all 23.

**Evidence:** E1 + E1d + E5. **Collected; replicated 13 Sept from a different
`Signature-Agent` URL, 20/20.**

### 4.8 Admission is binary, and the refusal is honest
Among 5,020 origins that served *both* arms, the signed response is neither
smaller nor larger than the unsigned one (sign test p = 0.90; Wilcoxon
p = 0.60; median 169,479 vs 168,719 bytes) and no slower (5,162 pairs, median
paired delta −4 ms, p = 0.99). An origin that admits a signed request serves
it the same page, at the same speed.
**Evidence:** E1c, re-analysis of E1. **Collected.**
*This is a load-bearing null. It rules out silent degradation as a hidden
middle ground, which means the binary outcome coding in §4.5 is not
concealing a gradient. It also rules out a synchronous directory fetch on the
request path: an origin retrieving our JWKS to verify would add a network
round trip, and none did. It does **not** show that verification is skipped —
Ed25519 verification costs tens of microseconds against a 1,200 ms median and
is undetectable here. That question is settled by §4.10, not by this.*

**Two exceptions, and they matter.** `temu.com` (318,826 / 318,797 bytes
unsigned → 2,889 / 2,889 signed) and `skyscanner.it` (185,927 / 159,925 →
708 / 708) return **HTTP 200 with a near-empty body** to the signed request,
in both repetitions, while serving the full page to both unsigned ones. A
refusal that no status code records. Every outcome-based measurement of this
protocol — including our own headline result — is blind to it, so 4.1% is a
floor rather than an estimate.
*Nine further origins were excluded because their own unsigned arm varied by
more than 3×; an averaging artifact in the first pass of this analysis
manufactured five false positives from single flaky fetches, and is reported
in §7.*

### 4.9 The edge delivers the signature intact
Against an origin we control behind the same CDN, all three protocol headers
(`Signature`, `Signature-Input`, `Signature-Agent`) arrive byte-identical.
Cloudflare neither strips nor rewrites them.
**Evidence:** instrumented Worker, `/echo`. **Collected.**
*This closes an alternative explanation for §4.5: the blocking is a decision
taken on the headers, not a side effect of the edge mangling them into
something malformed.*

### 4.10 No origin ever retrieves the key it would need
Verifying an RFC 9421 signature requires the signer's public key, obtainable
only from the directory named in `Signature-Agent`. We served that directory
from an instrumented origin, logged every retrieval, and sent one validly
signed request to each of the 298 origins that blocked the signed arm in E1.

**293 of 298 (98.3%) blocked the signed request. Zero retrieved the key.**

Two independent records — Workers KV and a `wrangler tail` stream, the latter
covering 15:11:59Z–15:26:42Z, past the end of the 150 s settle window. Four
directory fetches were logged in total, all ours (`curl` ×3 during setup,
`python-requests` ×1 preflight), all from one address. Counter delta over the
run: **zero**.
**Evidence:** E4. **Collected 13 September 2026.**

*This is the paper's strongest claim and the only deductive one. The refusal
cannot be a verification failure, because no origin obtained the material
required to verify. §4.5 and E1b establish statistically that the enforcement
path does not evaluate the cryptography; this establishes that it could not
have. Admission is keyed on the presence of the headers.*

*Scope: unlisted signers. It does not show Web Bot Auth cannot be verified,
nor that allowlisted operators are treated this way. Threats — prior cached
fetch, asynchronous verification, key resolution by an unserved path — are
enumerated with their disposition in FINDINGS.md and were registered in
PREREGISTRATION.md while the run was still in flight.*

### 4.12 The signal is a header name, and it is `Signature-Input`
298 origins that react to signing, five arms each, arm order randomised,
296 clean on all arms:

| arm | sends | blocked | rate |
|---|---|---:|---:|
| A | nothing | 8 | 2.70% |
| B | `Signature-Agent` only | 270 | 91.22% |
| C | `Signature-Input` only | 287 | **96.96%** |
| D | `Signature` + `Signature-Input`, no identity | 287 | 96.96% |
| E | all three, valid | 288 | 97.30% |

**`Signature-Input` alone is statistically indistinguishable from a complete
valid signature** (McNemar b=3, c=2, p = 1.0). Removing the identity header
entirely changes nothing (D vs E, p = 1.0). The identity header alone is
significantly *weaker* (B vs C: b=17, c=0, p = 1.5x10^-5).

`Signature-Input` carries no identity, no operator URL and no proof - only a
covered-components list, timestamps and a key identifier. It is metadata about
a signature, not a signature.
**Evidence:** E7. **Collected.**

*The arms are near-perfectly nested (c=0 almost everywhere): every origin
blocked by a weaker arm is blocked by a stronger one.*

**The chain closes.** Four experiments each eliminate one explanation:

| ruled out | evidence |
|---|---|
| the signature is invalid | arm E is valid, blocked at 97.30% |
| the cryptography is checked | E1b: garbage values block at 93.6% vs 96.8% valid |
| verification is possible at all | E4: 0 of 298 ever fetched the key |
| origins dislike unfamiliar headers | E1b decoys: same shape and size, 5.3% |
| the identity is read | E7: dropping `Signature-Agent` changes nothing |

What remains is a literal string match on a header name.

**This is the paper's closing argument.** Web Bot Auth exists to replace
user-agent trust - a system in which an unauthenticated header string decides
how a client is treated. For an unlisted signer it has reproduced that system
exactly. The string is `Signature-Input` rather than `User-Agent` and the
consequence is inverted, but the mechanism is identical: an unauthenticated
header name, matched literally, decides access. The Ed25519 machinery beneath
it is inert.

*Caveat: arm C is malformed under RFC 9421 (metadata without a signature), so
"origins reject malformed signature metadata" competes as a reading. E1b
disposes of it - decoy headers of identical shape and size blocked at 5.3%
while WBA names carrying invalid values blocked at 93.6%. The name is what is
matched, not the malformedness. The 298-origin population was chosen because it
already reacts to signing, so these rates do not generalise to the web; the
decomposition does.*

### 4.11 Verifier conformance is unauditable from outside
No endpoint exists where signature validity is load-bearing for an unadmitted
party: public paths serve regardless, gated paths refuse regardless.
**Evidence:** E2 attempt. **Collected.**

### 4.13 The effect is not a property of our network
The matched pair re-run from a Cloudflare Worker - different ASN, different
address, no history with these origins:

| population | arm A | arm B | paired | McNemar |
|---|---:|---:|---:|---|
| 198 clean pairs | 20.71% | 94.44% | +73.74 pp | b=146, c=0, p = 2.2x10^-44 |
| Cloudflare-fronted (183) | 21.31% | 95.63% | +74.32 pp | b=136, c=0, p = 2.3x10^-41 |
| not Cloudflare (15) | 13.33% | 80.00% | +66.67 pp | b=10, c=0, p = 0.0020 |

`c = 0` in every split: no origin anywhere reversed.
**Evidence:** E8. **Collected.**

*Population is the 298 known blockers, chosen for power - a random sample
returns almost no discordant pairs. **The magnitude is therefore not comparable
to section 4.5's +3.97 pp**, which was measured across 10,000 unselected
origins. Direction, one-sidedness and significance are what replicate. The
non-Cloudflare row addresses the confound that this traffic originates inside
Cloudflare's network; it is 15 origins and is the weakest row in the table.*

### 4.14 The deny-list catches RFC 9421, not Web Bot Auth
Web Bot Auth is RFC 9421 plus a `Signature-Agent` header and a
`;tag="web-bot-auth"` parameter. Removing both leaves a bare signed request
with nothing agentic about it:

| arm | sends | blocked | rate |
|---|---|---:|---:|
| A | nothing | 4 | 2.67% |
| B | `Signature-Input` with `tag="web-bot-auth"` | 143 | 95.33% |
| C | `Signature-Input`, **no tag, no agent** | 142 | **94.67%** |
| D | `Signature` + `Signature-Input` + `Content-Digest` | 144 | **96.00%** |

**The tag makes no difference** (C vs B: b=1, c=0, p = 1.0). Arm D is the shape
a webhook or signed API call actually takes.
**Evidence:** E10. **Collected.**

*RFC 9421 is a general-purpose IETF standard for signing HTTP messages - API
authentication, webhook verification, payment callbacks, inter-service
authorisation. It is not a bot protocol. At these origins it cannot be used.*

**This changes what the paper is about.** The finding is not that Web Bot Auth
adopters are penalised. It is that **an IETF Standards Track mechanism for
authenticating HTTP messages is treated as a bot signature**, and any client
presenting `Signature-Input` for any purpose is refused at ~95% of origins that
react at all. Web Bot Auth is caught because it is built on RFC 9421, not
because it is Web Bot Auth.

*Method note: our signer emits the Web Bot Auth tag by default, so sections
4.12 and 4.13 sent it without it being noticed. Their conclusions stand
unchanged because E10 shows the tag is irrelevant (p = 1.0); had it mattered,
both would have required retraction. Recorded in section 7.*

## 5. Discussion

**The incentive inversion.** An operator implementing the specification
correctly but not admitted to an allowlist is treated *worse* than one who
ignores it. The protocol as deployed disincentivises the behaviour it exists to
encourage.

**The cryptography is not load-bearing, and we can say exactly what is.**
§4.10 shows the key is never fetched, so verification was impossible. §4.12
shows which header carries the effect: `Signature-Input` alone is
indistinguishable from a full valid signature, and dropping the identity
header changes nothing. What the deployment matches is a header *name*.

The mechanism marketed as replacing user-agent trust has, for everyone outside
the allowlist, reproduced user-agent trust exactly — an unauthenticated string
in a header deciding access, with the sign of the consequence flipped.

**And the blast radius is wider than the protocol.** §4.14 shows the match is
on `Signature-Input` regardless of whether any Web Bot Auth marker is present.
RFC 9421 is a general-purpose standard: webhook verification, signed API calls,
payment callbacks. Those uses have nothing to do with automation policy and are
refused anyway. A standards body has produced a mechanism for authenticating
HTTP messages, and deployed anti-bot infrastructure has classified the
mechanism itself as evidence of misbehaviour. That, rather than anything about
crawlers, is the governance failure worth naming.

**Who governs the agentic web.** Enforcement is a choice two anti-bot vendors
have made independently, but *admission* is decided by a single private list:
Cloudflare authors the registry draft, operates the verified-bot directory
that decides who is admitted, and is the largest single operator inside it.
The list is justified by declarations that are not published and enforced by
an implementation that cannot be inspected.

**For the working group.** The registry draft defines declaration fields nobody
publishes. Either admission should require them, or the draft should
acknowledge that admission rests on out-of-band agreement.

## 6. Limitations

Stated plainly and early, not buried.

- **Sample sizes, by population.** Conformance and declaration claims now rest
  on n=82, the admitted population probed directly (E6). The census population
  is n=12. These are different samples answering different questions and the
  paper should never pool them.
- **The census undercounts Web Bot Auth by roughly 5x, and this is a property
  of the method, not of deployment.** An apex-domain scan found 12 operators;
  Cloudflare's directory lists 69 distinct domains, of which only 5 overlap.
  Signature agents live on service subdomains and API endpoints
  (`api.manus.im`, `bot.trychannel3.com`, opaque `keydirectory` hosts) that a
  Tranco-driven apex scan cannot reach. Any replication using this technique
  inherits the same floor.
- **0.0499% is a lower bound for a second reason.** 7.3% of hosts return `403`
  to an unfamiliar client and 17.5% fail TLS; a directory behind either is
  invisible.
- **The Cloudflare directory is a third-party scrape.** The admitted-population
  work uses `microlinkhq/cloudflare-bot-directory`, a community mirror of
  Cloudflare Radar, explicitly not affiliated with Cloudflare. Every directory
  it lists was re-fetched directly by us, so the conformance numbers are our
  own measurements; only the membership list and the `followsRobotsTxt` column
  are inherited.
- **`followsRobotsTxt: false` records no asserted commitment, not observed
  violation.** DuckDuckBot is marked `false` and demonstrably respects
  robots.txt. Any reading of that column as evidence of misbehaviour would be
  both unsupported and defamatory, and the paper must say so where it uses it.
- **Data quality is load-bearing and must be reported.** A configuration at 96
  workers / 6s timeout yielded 29% clean pairs and an apparent null (b=17,
  c=17). At 28 workers / 12s the same experiment gave 73% clean pairs and
  p < 10⁻⁷⁵. **The aggressive run produced a false null**, because timeouts
  generate spurious transitions in both directions that cancel. Any replication
  that tunes for throughput without reporting its clean-pair rate can reach the
  opposite conclusion from the same design.
- **~~Single network vantage~~ — CLOSED.** The matched pair was re-run from a
  Cloudflare Worker (E8): different ASN, different address, no request history
  with these origins, none of the laptop's accumulated reputation damage.
  Against the 298 known blockers, 198 clean pairs: arm A 20.71%, arm B 94.44%,
  **b=146, c=0, p = 2.2x10^-44**. It holds on the non-Cloudflare subset too
  (15 origins, +66.67 pp, p = 0.0020, c=0), which addresses the confound that
  this traffic originates inside Cloudflare's network.
  *The magnitude is NOT comparable to the +3.97 pp headline: E8's population
  was selected for blocking, so arm B is near ceiling by construction. What
  replicates is direction, one-sidedness and significance on the same origins
  from a different network. The two figures must never be presented side by
  side as the same quantity.*
- **Two client stacks, one network.** The paired effect replicates across
  Windows/Schannel (+3.97pp, p < 10⁻⁷⁵, 7,267 pairs) and Linux/OpenSSL
  (+3.74pp, p = 4.6×10⁻¹⁰, 1,068 pairs) against the same origins. **Client
  fingerprint is ruled out.** Between the two runs, taken two days apart, the
  unsigned baseline fell 15.91% → 12.55% as source reputation recovered, while
  the paired difference did not move — a second demonstration, by the opposite
  mechanism to the within-run drift analysis, that absolute rates belong to the
  vantage and the paired difference belongs to the signature. **Network
  reputation and geography remain untested**; both runs used one IP in one
  country.
  *The matched-pair design holds the source address constant within each
  comparison, which is what licenses the causal reading regardless; a second
  network would establish that the rate itself generalises.*
- **E2 yields no conformance data.** The impossibility is the result; some
  readers will find that unsatisfying.
- **The `challenged` classifier has a high false-positive rate, now quantified.**
  Of 1,493 observations so labelled, only 38 carry a title indicating a real
  interstitial; most are ordinary pages (SoundCloud, the Guardian, TMDB) that
  contained a marker string in the first 8 KB. **The headline is provably
  unaffected:** the McNemar predicate is binary on `blocked`, and a page
  mislabelled `challenged` when it was `served` moves within the not-blocked
  category, so neither b (298 = 270 served + 23 challenged + 5 transient) nor
  c (9) can change. No claim in the paper treats `challenged` as an outcome.
  Reported because a replication that does build on that class would be wrong,
  and because `cf-mitigated` proved a far cleaner signal than any body
  heuristic.
- **Our own directory** is served by GitHub Pages as `application/octet-stream`,
  not the defined media type — we are non-conformant on a dimension where all
  nine operators conform.

## 7. Instrument defects found during collection

Reported because each was invisible to loopback testing and each would have
produced a wrong result.

1. **`503` treated as rate limiting.** A generic block from one large host
   paused all workers; throughput fell 10/s → 3.2/s.
2. **Worker starvation.** 16 workers against an 8s timeout caps throughput at
   2/s regardless of configured rate — a 5× underestimate of feasible speed.
3. **Shell path conversion.** MSYS rewrote a URL path into a Windows file path;
   every case errored, resembling an origin refusing all traffic.
0. **The declaration probe searched for the wrong field names.** The most
   consequential: it looked for a `web_bot_auth` sub-object and a `client_*`
   field list, never for `purpose`, which is the registry draft's own field.
   This produced the claim "0 of 9 publish any declaration field", which was
   wrong at the time of writing - three operators publish `purpose`. Because
   the field was never inspected, the stored data cannot support a
   longitudinal claim either way. The corrected claim (section 4.2) is about
   *behavioural* declarations, which remain at 0 of 11.
4. **A bare 200 scored as acceptance.** The most dangerous: it manufactured ten
   apparent conformance violations against a security vendor from a public
   `robots.txt`. Caught because every case passed while the control also passed.
5. **Median-of-two is a mean.** The first pass of the §4.8 analysis collapsed
   each arm's two repetitions with a median, which for n=2 averages them. One
   flaky fetch therefore halved an origin's recorded size and produced five
   spurious "50% smaller" results — `mail.ru`, `kinopoisk.ru`,
   `thalesgroup.com` and two others, all with one normal repetition and one
   anomalous. Caught because the shrinkage clustered implausibly tightly at
   exactly 50% across unrelated origins. Replaced by a rule requiring every
   signed repetition to fall below every unsigned one, which leaves two.
6. **The signer emitted a Web Bot Auth tag that went unnoticed for two
   experiments.** `wba/signature.py` defaults `tag` to `WEB_BOT_AUTH_TAG`, so
   sections 4.12 and 4.13 sent `;tag="web-bot-auth"` inside `Signature-Input`
   while one arm was described as generic RFC 9421. Caught while drafting a
   claim that depended on it being absent. E10 then established the tag is
   irrelevant (p = 1.0), so both conclusions stand — but they stood by luck,
   and had the tag mattered both would have required retraction. The lesson is
   to assert what an instrument *emits*, not what it was intended to emit.
7. **Zero discordant pairs read as a null result.** McNemar uses only the
   discordant counts, so b=c=0 yields p=1 by construction and carries no
   information. A 50-origin pilot of E8 printed "the effect DOES NOT
   replicate" on exactly that basis. Had it been believed it would have been a
   fabricated negative on the study's most contested claim, and it was wrong in
   the direction that resembles scientific caution. The reading now requires at
   least 10 discordant pairs before concluding in either direction.
8. **`cf-ray` is meaningless as CDN attribution from inside Cloudflare's
   network.** The edge adds it to responses proxied on a Worker's behalf, so
   E8's first run labelled 28 of 28 origins Cloudflare-fronted. Attribution now
   comes from the laptop run. Caught because 100% is implausible against a
   known ~36% share.
9. **`202 Accepted` with a zero-byte body scored as `served`.** Correct for
   counting outcome transitions, wrong for comparing content; two origins
   entered the size analysis with an empty acknowledgement standing in for a
   page. Content comparison now requires a 2xx that actually carried bytes.

## 8. Artifacts

Census, differential and conformance tooling; the RFC-vector tests; the lax
negative-control origin; pre-registration; codebook; curated datasets. The
conformance harness is ready for anyone with allowlist access.

---

## What is still needed

| item | status |
|---|---|
| ~~E4 directory-fetch log~~ | **done, 13 Sept 2026 — 293/298 blocked, 0 key fetches** |
| ~~50k census completion~~ | **done - 34,900 distinct hosts, 12 operators** |
| ~~Rank-decay curve fit~~ | **done - slope -0.448, R^2 0.844** |
| Re-probe declarations in a month | would make the `purpose` question longitudinal |
| Operator coding, two coders, κ | needed only for the 12 census operators; the n=90 table uses Cloudflare's own labels |
| Disclosure to Cloudflare, the IETF WG and People Inc. | **drafted (DISCLOSURE.md); not sent — clock not started** |
| Second network vantage | the last structural objection; costs a free-tier VM |
| ~~Related-work section~~ | **drafted (section 2.1) — 7 works positioned** |
| Re-census for longitudinal comparison | months away; strengthens §4.2 |
| ~~Serve our own directory at the defined media type~~ | **done — Worker serves `application/http-message-signatures-directory+json`** |
| Fix the source-address filter in `keyfetch.py` | ipify and Cloudflare disagree on our egress; exclusion fell back to User-Agent |

## Honest assessment

The paper has a headline result at p < 10⁻⁷⁵ on 7,267 matched pairs, a
deductive result (E4) showing the key is never fetched so verification was
never possible, and a conformance contrast at n=82 that is the sharpest single
table in the work: **95.1% on the defined media type, 100% on the mandated key
algorithm, 0% on any behavioural declaration.**

Three claims were wrong and were corrected during this analysis rather than
after review. The effect is two vendors, not one (Qrator at 13.7% alongside
Cloudflare at 10.4%). The declaration claim was "0 of 9" from a probe that
never looked for `purpose`. The tollbooth is not pay-per-crawl but a `mailto:`.
Section 7 records all of them. A measurement paper that reports only the
defects it found before collection is not describing how instruments behave.

**What remains genuinely thin:**

- ~~A single network vantage.~~ **Closed by E8**: the effect replicates from
  Cloudflare's edge at p = 2.2x10^-44 with c=0, including on the
  non-Cloudflare subset.
- **No second coder** for the operator taxonomy, so no κ.
- **No longitudinal arm.** Everything is a single cross-section except the
  20/20 tollbooth replication three days later. A re-census in a month would
  settle whether `purpose` adoption is moving, which currently cannot be
  claimed either way.
- **Disclosure is drafted but unsent.** The 90-day clock has not started.

**What is no longer thin:** operator count, declaration evidence, the
conformance contrast, mechanism identification, vendor attribution, and the
central causal claim.

This is a strong PETS or IMC submission now. Every structural objection we
identified has been answered with data: client fingerprint (Linux/OpenSSL
replication), baseline drift (invariant paired difference, demonstrated twice
by opposite mechanisms), network and reputation (E8), sample size for the
declaration claim (n=82 admitted population), single-vendor attribution
(Qrator), and mechanism (E7).

What is left is not structural. A second coder for the 12 census-discovered
operators, a re-probe in a month to make the `purpose` question longitudinal,
and sending the disclosure.