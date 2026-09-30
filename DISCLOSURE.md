# Coordinated disclosure

**Status:** drafted 14 September 2026. Not yet sent.
**Clock:** 90 days from first contact, then publication proceeds regardless.

---

## What this is, and what it is not

Most of what this study found is **not a vulnerability**. It is measurement of
how a pre-standard protocol behaves in deployment, and the findings are about
governance and incentives rather than exploitable defects. Framing them as a
security disclosure would overstate them and waste the recipients' time.

Three findings are different. They are operational defects that the affected
parties would want to know about before they read them in a paper, and one of
them concerns a third party who cannot fix it without being told.

Everything else in the paper is published on the normal academic timetable
with no embargo, because there is nothing to fix and no one at risk.

---

## Recipient 1 — Cloudflare

**Route:** the security disclosure address, cc the Web Bot Auth product
contact named in the registry draft. Not a bug bounty submission; this is a
courtesy notification of measurement results, and it should say so in the
first line so it is not triaged as a vulnerability report.

### 1.1 Eight verified-bot entries publish an unusable key directory

8 of the 90 Web Bot Auth entries in the public verified-bot directory serve a
`signatureAgentUrl` from which no verifier can retrieve a key:

| host | response |
|---|---|
| `web-bot-auth-directory.radar-cfdata-org…` | 404 — **Cloudflare Radar URL Scanner** |
| `crawl.corp.novellum.ai` | 404 |
| `app.hark.com` | 403 |
| `windowsforum.com` | 403 |
| `pureconsent.com` | 302 to HTML |
| `crawler.prod.quartr.cloud` | connect timeout |
| `www.sourcedashboard.co.uk` | connection refused |
| `signature-agents.twin.so` | connection refused |

Observed 13 September 2026, one request each.

**Why it matters to them specifically:** one of the eight is Cloudflare's own
Radar URL Scanner, and `sourcedashboard.co.uk` is one of only five entries in
the cohort recorded as following `robots.txt`. If admission is meant to imply
a working directory, the register and the reality have diverged. If admission
is not conditioned on the directory resolving, that is worth stating publicly,
because implementers currently assume otherwise.

**Asked of them:** confirm whether a resolving directory is a condition of
listing. That answer changes a sentence in the paper either way, and we would
rather print theirs than infer one.

### 1.2 Signed requests are challenged more often than anonymous ones

Across 7,267 matched pairs, origins behind Cloudflare returned a mitigation to
a validly signed request 1.33× as often as to the identical unsigned request
(1,252 vs 941). 271 origins blocked the signed arm in both repetitions while
serving the unsigned one in both. `cf-mitigated` carried the value `challenge`
in every instance and no other value anywhere in the dataset.

**Why it matters to them specifically:** this is the opposite of the stated
intent of the signed-agent programme. An operator implementing the
specification correctly, but not on the allowlist, is treated worse than one
that sends nothing. We do not claim this is a bug — it may be exactly the
configured behaviour of Bot Fight Mode meeting an unrecognised header — but
customers enabling that setting are likely unaware that it penalises the
protocol Cloudflare is standardising.

**Asked of them:** whether this is intended, and whether the interaction
between Bot Fight Mode and unlisted Web Bot Auth signers is documented
anywhere a customer would find it.

### 1.3 The setting also blocks customers' own signed API traffic

**This is the item most likely to warrant action, and it is not about bots.**

Web Bot Auth is RFC 9421 plus a `Signature-Agent` header and a
`;tag="web-bot-auth"` parameter. Removing both — leaving a bare RFC 9421 signed
request with nothing agentic about it — does not change the outcome:

| request | blocked |
|---|---|
| nothing | 2.67% |
| `Signature-Input` with the Web Bot Auth tag | 95.33% |
| `Signature-Input`, no tag, no agent header | **94.67%** |
| `Signature` + `Signature-Input` + `Content-Digest` | **96.00%** |

150 origins, 14 September 2026. Tagged versus untagged: b=1, c=0, p = 1.0.

The last row is the shape a webhook callback or a signed API request actually
takes. RFC 9421 is a general-purpose IETF standard used for API
authentication, webhook verification and payment callbacks — not a bot
protocol.

**Customers who enable this setting appear also to be blocking their own
inbound signed API traffic**, and we see no reason to think they know it. We
are raising it because it affects paying customers' integrations rather than
third-party crawlers, and because it is cheaply checkable on their side.

**Asked of them:** whether blocking on the presence of `Signature-Input` is
intended, and whether the effect on non-bot RFC 9421 traffic was considered.

### 1.4 Nothing here is an exploit

We are not reporting a bypass, a forgery, or a way to obtain access. The
impersonation experiment that would have tested whether admission is keyid
matching was **run only against an origin we control** and is reported as
inconclusive, because the free tier exposes no bot-management verdict. We did
not send another operator's key material to any third party, and the tooling
refuses to.

---

## Recipient 2 — the IETF `webbotauth` working group

**Route:** the working group mailing list, publicly and on the record. This is
input to a Standards Track document, not a private security matter, and it
should be visible to everyone implementing against the draft.

### 2.1 The declaration fields are published by nobody

Of 82 reachable operators in the admitted population, **0 publish any
behavioural declaration**: no `rate-expectation`, `rate-control`,
`rfc9309-compliance`, `expected-user-agent`, `targeted-content` or `trigger`.
The same 82 achieve 100% on the mandated key algorithm and 95.1% on the
defined media type.

The contrast is the point. This population complies with everything a machine
checks and declares nothing. That is an incentive result, not a competence
one, and the working group is the body that can change the incentive.

### 2.2 `purpose` has no controlled vocabulary

10 of 82 publish `purpose`, in eight distinct spellings: `rag`, `ai`,
`agentic_commerce`, `Agentic Commerce Order P…`, `Agentic Checkout`,
`multi-service`, `monitoring`, `signed-agent`. Two operators meaning
substantially the same thing share no token, and two others restate the
mechanism rather than an intent.

**Suggestion, offered as a data point rather than a proposal:** either
enumerate the permitted values or drop the field. As deployed it cannot be
aggregated, compared, or enforced against.

### 2.3 The registry draft is unadopted while the protocol is Standards Track

`draft-ietf-webbotauth-httpsig-protocol-00` was adopted 1 September 2026.
`draft-meunier-webbotauth-registry-03` remains an individual submission. The
identity mechanism is being standardised and the accountability layer is not,
which matches exactly what deployment shows. Worth the working group's
attention as a sequencing question.

### 2.4 Key lifetime is unspecified and unevenly practised

18 of 82 publish keys carrying `exp`; 19 publish `nbf`. Observed windows range
from days to years — one operator's key expires 6 days out, another's 840. The
draft says nothing about key lifetime or how long a verifier may cache a
directory, so a key without `exp` is valid until manually withdrawn.

---

## Recipient 3 — People Inc.

**Route:** the `contentlicensing@people.inc` address their own 402 response
directs machine traffic to.

Their 20 properties return `402 Payment Required` to a signed request while
serving the identical unsigned one. There is no price header and no
machine-readable payment path in the response — only a `mailto:`. We are
telling them because the paper will name them, they are the only publisher in
the sample doing this, and they may not know the behaviour is
signature-conditional rather than general bot policy.

No embargo is requested from them and none is offered; this is notification,
not negotiation.

---

## What we will publish regardless, and when

The 90-day clock covers §1.1, §1.2 and §1.3 — the three items a party could
act on. §1.3 is the most urgent of them: it affects customers' own
integrations, not third-party traffic. Everything else is measurement of public behaviour and is not embargoed.

If a recipient asks for more time to fix §1.1, we will grant a single
extension of up to 30 days and say in the paper that we did. We will not
remove a finding, soften a number, or accept a correction that is not
accompanied by evidence. If a recipient disputes a measurement, their response
goes into the paper next to ours.

If there is no reply within 90 days, we publish and record that we received
none. Silence is a fact about the process and belongs in the write-up.

---

## Log

| date | recipient | action | response |
|---|---|---|---|
| | Cloudflare | | |
| | IETF `webbotauth` WG | | |
| | People Inc. | | |

*Fill this in as it happens. An empty log at submission time is itself
reportable, and reviewers ask.*
