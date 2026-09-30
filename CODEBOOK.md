# Codebook — operator classification

For H3: *among directory publishers classifiable by primary business, AI agent
operators are fewer than half.*

**Written 10 September 2026, before Phase 2 collection.** Fixing the categories
in advance is the whole point: if they are drawn after seeing the operators,
the boundaries get placed where they make the hypothesis come out, and the
classification stops being evidence.

Six observations existed when this was written (the pilot, plus `fpjs.io` from
the early deep census). They are listed in §5 with their codes, so a reader can
see exactly what was known when the categories were set.

---

## 1. Unit

One **operator**, not one host. Where an operator publishes directories at
several hosts, code the operator once and record the hosts against it.

## 2. Procedure

1. Two coders work **independently**, from the operator's own public
   description of its primary product — its homepage, product page or about
   page, retrieved on the coding date and archived.
2. Coding happens **before any density analysis**, so it cannot be influenced
   by where in the ranking an operator sits.
3. Disagreements are recorded verbatim, then resolved by discussion. Both the
   pre-resolution and post-resolution codes are kept.
4. Report **Cohen's κ** on the pre-resolution codes. If κ < 0.6, the categories
   are not doing their job; say so and report the disagreement pattern rather
   than quietly resolving everything and presenting a clean table.

## 3. Categories

Assign the **primary** business. One code per operator.

### AI-AGENT
Operates an LLM assistant, chatbot or autonomous agent that fetches web content
on behalf of end users or for model training.
*Positive:* chatgpt.com. *Boundary:* a company with an AI product but whose
crawler serves a different purpose is coded by the crawler's purpose.

### SEARCH-SEO
Operates a crawler building an index of the web for search, SEO analytics,
backlink analysis or site auditing.
*Positive:* ahrefs.com.

### SECURITY-FRAUD
Sells detection of malicious traffic, fraud, bots or vulnerabilities. Includes
anti-bot and fingerprinting vendors, threat intelligence, and security scanners.
*Positive:* forter.com, checkpoint.com, fpjs.io.
*Note:* this category has an interesting property — these operators sell the
solution to the identity problem the protocol addresses, and their own crawlers
face it from the other side. **Do not let that observation influence coding.**
It is a finding to report if the counts support it, not a lens for assigning
codes.

### PLATFORM-SOCIAL
Operates a large consumer platform, social network or marketplace whose crawlers
serve link previews, content ingestion or integrity work.
*Positive:* meta.com.

### INFRA-CDN
Provides content delivery, DNS, hosting or network infrastructure as its primary
product.

### COMMERCE-MEDIA
Primary business is selling goods, services or content — retail, publishing,
banking, streaming. A crawler is incidental to the business.

### OTHER
Genuinely does not fit above. **Use sparingly.** If OTHER exceeds 15% of coded
operators, the scheme is inadequate and that must be reported.

### UNCLASSIFIABLE
No public description of the business is retrievable at coding time — a parked
domain, a holding page, or a site in a language neither coder reads without a
usable translation. Excluded from the H3 denominator and **counted and reported
separately**; a large unclassifiable share is itself a limitation.

## 4. Rules for hard cases

**Code the crawler's purpose, not the company's size.** A large company running
an SEO crawler is SEARCH-SEO, not PLATFORM-SOCIAL.

**Where two categories genuinely apply, prefer the one the operator leads with**
on its own homepage. Record that the case was ambiguous.

**Do not infer purpose from the directory contents.** Key count, declared
fields and rank are not inputs to coding. Coding uses the operator's public
self-description and nothing else, so that classification stays independent of
the measurements it will be crossed against.

**Do not code from the domain name alone.** Retrieve the page.

## 5. Codes assigned before Phase 2 (for transparency)

These six were visible when the codebook was written. They are provisional,
will be re-coded blind by both coders alongside everything else, and are
recorded here only so the reader can see what the categories were drawn against.

| host | provisional code |
|---|---|
| chatgpt.com | AI-AGENT |
| ahrefs.com | SEARCH-SEO |
| forter.com | SECURITY-FRAUD |
| checkpoint.com | SECURITY-FRAUD |
| fpjs.io | SECURITY-FRAUD |
| meta.com | PLATFORM-SOCIAL |

If the final coding of these six differs from the provisional codes above, that
difference is reported.

## 6. Analysis

H3 tests AI-AGENT against all other coded categories combined, one-sided
binomial against 0.5, over classifiable operators only.

Secondary and **exploratory, labelled as such**: the distribution across all
categories. If SECURITY-FRAUD is prominent, that is worth reporting — but as an
observation generated by this data, not a hypothesis it tested.
