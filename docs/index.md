# Web Bot Auth deployment measurement

An academic study of how the **Web Bot Auth** protocol
(`draft-ietf-webbotauth-httpsig-protocol`, adopted by the IETF
on 1 September 2026, layered over
[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421))
is deployed on the web.

**Researchers:** Sumit Sagar, Tanishka Sharma, Gautam Bajaj
**Institution:** Netaji Subhas University of Technology, New Delhi, India
**Contact:** sumit.sagar.ug23@nsut.ac.in, tanishka.sharma.ug23@nsut.ac.in, gautam.bajaj.ug23@nsut.ac.in
**Code:** [github.com/Sumit-Sagar/signed-lane](https://github.com/Sumit-Sagar/signed-lane)

---

## If you are here because of traffic in your logs

This study has run several distinct measurements. Each identifies itself in the
`User-Agent`, and each names this page and a contact address:

```
wba-census/0.x          one GET to /.well-known/http-message-signatures-directory
wba-differential/0.x    GET / , unsigned and signed, to compare the responses
wba-confound/0.x        GET / with several header combinations
wba-keyfetch/0.x        one signed GET /
wba-tollbooth/0.x       GET / , unsigned then signed
wba-decompose/0.x       GET / with one protocol header at a time
wba-admitted-probe/0.x  one GET to a key directory a service already publishes

  (+https://sumit-sagar.github.io/signed-lane/; academic measurement;
   contact / opt out: sumit.sagar.ug23@nsut.ac.in)
```

### What it does

Two kinds of request, and nothing else.

**The key directory.** One HTTPS GET to
`/.well-known/http-message-signatures-directory`. That path is defined by the
specification to be publicly fetchable — it is where a service publishes the
public keys it signs its automated requests with.

**The site root.** A GET to `/`, sometimes repeated with different request
headers, in order to compare how a site responds to an anonymous request
against a cryptographically signed one. Comparing those responses is the object
of the study, and it cannot be done without sending both.

In all cases:

- **A small, bounded number of requests per host** — between one and ten,
  depending on the measurement, spaced roughly a second apart. Never a crawl.
- **Only `/` and the well-known directory path.** Nothing is spidered,
  followed or indexed. No links are extracted.
- **No credentials are sent.** No cookies, no authentication, no forms, no
  POSTs. Only GET.
- **Nothing non-public is touched.**
- **Only our own identity is ever presented.** Signed requests carry a key
  published at this site. We never send another operator's key, key
  identifier, or agent URL to a third party.
- **Rate limited**, and a `429`, or a `503` carrying `Retry-After`, pauses the
  run rather than retrying.

### What is recorded

The HTTP status code, response headers, response size, latency, and the page
title. Where a key directory exists, the public keys and any self-declared
metadata it publishes. All of that is information the specification or the
HTTP response intends to be public.

No page content beyond the title is retained, and no personal data.

### To be excluded

Email **sumit.sagar.ug23@nsut.ac.in** with your domain or IP range. It is added to
a permanent exclusion list and never contacted again. You do not need to give a
reason, and you will not be asked for one.

---

## Why this study exists

Major content delivery networks now grant preferential access to automated
traffic that carries a valid Web Bot Auth signature — a "signed lane" that
skips most bot checks. What earns a service a place in that lane is partly
cryptographic and partly a set of claims it makes about its own behaviour: its
purpose, its request rate, whether it obeys `robots.txt`.

The cryptography is verifiable. The claims are not currently checked by anyone.

This work measures three things:

1. **How widely the protocol is deployed**, and who holds the keys.
2. **Whether origins that accept these signatures correctly reject malformed
   ones**, following the conformance-testing method used for TLS and QUIC.
3. **Whether services that make declarations actually honour them** in the
   traffic they send.

The intent is constructive. The protocol is still an Internet-Draft and its
IETF working group is active, so findings can inform the specification before
it is finalised. Anything affecting a specific operator is disclosed privately
first, on a 90-day timeline, before publication.

---

## Method and ethics

The measurement code, the conformance test matrix, and the pre-registered
analysis plan are all public in the repository linked above. The pre-registration
fixes the hypotheses and the statistical analysis **before** data collection, so
the analysis cannot be chosen after seeing the results.

Internet-wide measurement of publicly-served well-known paths is established
practice in network security research and is regularly published at venues
including the ACM Internet Measurement Conference and USENIX Security. This
study follows the same norms: identify yourself, request once, rate limit,
publish the method, and honour every exclusion request without argument.

---

*Last updated: 14 September 2026. This page is revised whenever the
measurements change; earlier versions understated the number of requests per
host, and that is corrected above.*
