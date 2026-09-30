# Running this at zero cost

Nothing in T1 or E2 requires paid infrastructure. Only E3 benefits from paid
domains, and E3 is the component gated on time rather than money anyway — so
the order of work below is also the order that spends nothing for longest.

---

## 1. The study page — free

The `--info-url` has to be a live https page explaining what you are doing.
**GitHub Pages gives you this for nothing**, and a repository you already need
for the artifact:

1. Create a public repo, e.g. `signed-lane`.
2. Add `docs/index.md` describing the study (there is a template below).
3. Settings → Pages → source `main`, folder `/docs`.
4. You get `https://<username>.github.io/signed-lane/` — a real https URL.

That is a perfectly respectable info URL. A GitHub Pages site belonging to a
named researcher with the code visible in the same repository is *more*
credible to an administrator than an anonymous domain, not less, because they
can read exactly what you are doing.

GitLab Pages, Codeberg Pages and Cloudflare Pages all work the same way.

### Template for the page

> **Web Bot Auth deployment measurement**
>
> This is an academic study of how the Web Bot Auth protocol
> (draft-meunier-web-bot-auth-architecture, over RFC 9421) is deployed on the
> web. Conducted by Sumit Sagar, Tanishka Sharma and Gautam Bajaj, Netaji Subhas
> University of Technology, New Delhi, India.
>
> **What the traffic does.** One HTTPS GET per host, to
> `/.well-known/http-message-signatures-directory` — a path defined by the
> specification to be publicly fetchable. No other paths are requested, no
> credentials are sent, no forms are submitted, and no attempt is made to
> access anything not already public. Hosts are visited once.
>
> **What is recorded.** The HTTP status, and where a directory exists, the
> public keys and self-declared metadata it publishes. Nothing else.
>
> **To be excluded.** Email sumit.sagar.ug23@nsut.ac.in with your domain and it will be added to
> a permanent exclusion list, honoured without question and without needing a
> reason.
>
> **Method and code.** https://github.com/Sumit-Sagar/signed-lane

---

## 2. The contact address — free

Use your **university address** if you have one. `@nsut.ac.in` carries far more
weight with an abuse desk than a Gmail address, and it costs nothing. A
personal address works if that is what you have; it just has to be one you
actually read.

Whichever you use, watch it for the duration of the scan and answer promptly.
One polite reply resolves almost every complaint that ever arrives.

---

## 3. Where to scan from — free

**Oracle Cloud Always Free** is the standout: two AMD VMs, permanently free,
not a trial, each with a public IP. You can set reverse DNS on it. That gives
you a disposable, non-residential address for the price of a signup.

Also genuinely free for this purpose:

- **Google Cloud** — $300 credit over 90 days
- **AWS** / **Azure** free tiers — 12 months
- **Your department** — ask. Universities frequently have research VMs sitting
  idle, and a supervisor who says yes also solves your sign-off problem in the
  same conversation.

**Do not use GitHub Actions, Colab, or similar.** Their acceptable-use terms
prohibit network scanning, and the consequence is losing the account rather
than a polite email.

### Reverse DNS

Once you have the VM, set a PTR record on its IP to something self-explanatory
like `wba-research.<your-page-host>`. This is the highest-value step after the
User-Agent. An administrator seeing unfamiliar traffic looks up the reverse DNS
first; ZMap, Censys and Shodan all do this. A PTR that explains itself turns
"unknown scanner" into "identified researcher" before anyone has to ask.

---

## 4. Can you run the pilot from home?

**For 5,000 hosts, realistically yes**, with two conditions:

- a real `--contact` and a live `--info-url`, exactly as above
- a modest rate — use `--rate 10`, which spreads 5,000 hosts over eight
  minutes rather than two

Five thousand identified GETs at ten per second is comparable to ordinary
crawler traffic, and with an honest User-Agent it is very unlikely to cause you
any trouble.

**Do not run the full million from home.** Seven hours of sustained scanning
from a residential connection is a different proposition: some ISP acceptable-
use policies prohibit it outright, and a residential IP that ends up on a
blocklist is shared, sticky, and impossible to dispose of. Move to the free VM
before the full census.

---

## 5. What actually costs money

Only **E3 domains**, and only because a honeypot needs to look like an ordinary
site and needs to have existed for a while before crawlers take an interest.

- A `.com` is roughly €10 a year. Several would be better than one, since
  varying crawl-delay across domains is what gives you the rate dimension.
- Free alternatives exist — `eu.org` issues real domains at no cost, and
  FreeDNS offers subdomains — but a free subdomain on a shared parent inherits
  whatever reputation that parent has, which is a confound you would rather not
  write into your limitations section.
- **Ask your department.** €50 for research domains is a small, ordinary
  request, and it is a much easier conversation to have while showing a working
  measurement pipeline than as a hypothetical.

---

## Order of work, spending nothing

1. **Publish the study page** on GitHub Pages. Free, and it unblocks everything.
2. **Run the pilot from home** at `--rate 10`, with real contact details.
3. **Take the pilot result to your supervisor.** A concrete number is a far
   stronger opening than a proposal, and that conversation is where sign-off,
   a departmental VM, and possibly domain funding all come from at once.
4. **Run the full census** from the free VM once sign-off is in hand.
5. **E3 last**, when domains exist — it is gated on domain age regardless, so
   nothing else is waiting on it.

The pipeline does not care that you are running it on a laptop. Every result it
produces is as real as one produced on funded infrastructure.
