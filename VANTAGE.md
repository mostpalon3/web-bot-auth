# Second vantage point — running E1 from your VM

The drift analysis showed the laptop's IP accumulated reputation damage during
collection: the unsigned baseline rose from 13.2% to 19.2% blocked. The paired
effect survived that, which is what licenses the causal claim — but every
**absolute** rate in the paper is from one address that was getting
progressively more suspicious to bot-management systems.

A VM gives you a clean IP on a different network. If the paired effect
replicates there, external validity stops being a limitation and becomes a
result.

---

## 1. Publish the VM's key first

The bundle contains a **separate** key, `vantage.pem`. Two vantages with
distinct keys is better than copying one private key between machines: it keeps
the laptop key on the laptop, and it lets you tell the two vantages apart in
any origin's logs.

Add this to `docs/.well-known/http-message-signatures-directory` in the GitHub
repo, so the directory carries **both** public keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "fw5_IB1MB7TGzHEPz6S91-Dhf2Xg2Vfi88PVyrSuys0"
    },
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "aN0FXic2uZt4pp7iCEXpcY7ge3Qh2WVHwMGPEIHPYto"
    }
  ]
}
```

Wait for Pages to redeploy, then confirm the file shows both keys. **The VM's
signatures are unverifiable until this is live** — and sending unverifiable
signatures is exactly the malformed behaviour this study measures in others.

## 2. Copy the bundle

From the laptop:

```bash
scp -r vantage_bundle you@your-vm:~/wba
```

The bundle holds only what a vantage run needs: `differential.py`,
`confound.py`, `scan.py`, the `wba/` package, `vantage.pem`, `blockers.txt`,
and `tranco_3k.csv`.

## 3. Set up

```bash
ssh you@your-vm
cd ~/wba
sudo apt update && sudo apt install -y python3-pip
pip3 install -r requirements.txt
mkdir -p keys && mv vantage.pem keys/research.pem
```

The rename matters: `differential.py` looks for `keys/research.pem`.

## 4. Set reverse DNS on the VM

Before sending anything. In the cloud console, set the instance's PTR record to
something self-explanatory — `wba-research.<something you control>`. An
administrator seeing unfamiliar traffic checks reverse DNS first; a PTR that
explains itself turns "unknown scanner" into "identified researcher" before
anyone has to ask.

## 5. The replication run

```bash
python3 -u differential.py \
  --hosts tranco_3k.csv --limit 3000 --repeats 2 \
  --workers 28 --rate 8 --delay 1.0 --timeout 12 \
  --contact sumit.sagar.ug23@nsut.ac.in \
  --info-url https://sumit-sagar.github.io/signed-lane/ \
  --i-have-signoff
```

**3,000 origins is enough.** The laptop's effect was ~4pp on 7,267 pairs; at
3,000 origins with ~70% clean you get ~2,100 pairs, which detects an effect
that size comfortably. Roughly 40 minutes.

**Keep 28 workers and a 12-second timeout.** That configuration produced 70–73%
clean pairs. The 96-worker/6-second variant produced 29% and a **false null** —
timeouts generate spurious transitions in both directions that cancel out. Do
not tune this for speed.

## 6. The confound replication

Worth doing second, and it is short — 298 origins, ~20 minutes:

```bash
python3 -u confound.py \
  --hosts blockers.txt --limit 298 --repeats 2 \
  --workers 16 --delay 1.0 --timeout 12 \
  --contact sumit.sagar.ug23@nsut.ac.in \
  --info-url https://sumit-sagar.github.io/signed-lane/ \
  --i-have-signoff
```

This re-tests the finding that matters most: that arm D — real header names,
invalid signature — blocks as hard as a valid one. If that replicates from a
clean IP, "the enforcement path does not verify" is established rather than
observed once.

## 7. Bring the results back

```bash
scp -r you@your-vm:~/wba/results/differential ./results/vantage_differential
scp -r you@your-vm:~/wba/results/confound      ./results/vantage_confound
```

---

## What each outcome means

**The paired effect replicates (b ≫ c, similar magnitude).**
External validity established. The finding is not an artefact of one network,
one country, or one damaged IP reputation. This is the strongest outcome and it
removes the paper's main remaining limitation.

**The paired effect replicates but the absolute rates differ.**
Expected, and still good. It confirms what the drift analysis implies —
absolute rates are IP-dependent, the paired difference is not. Report both and
say so; it makes the methodological point concrete.

**The effect vanishes from the VM.**
Then blocking is IP-reputation-dependent rather than signature-dependent, and
the paper's central claim needs restating. That would be a genuine and
important negative result, and finding it yourself is far better than a
reviewer finding it.

**Data-centre IPs are treated differently from residential ones.**
Worth anticipating: bot-management systems commonly score cloud ranges more
harshly. If the VM's *unsigned* baseline is much higher than the laptop's
13–19%, say so — it is a real confound between the vantages, and the paired
comparison is still valid within each.

## Recording it

Note in `FINDINGS.md`: VM provider, region, IP type (data centre), whether a
PTR was set, and the date. Vantage characteristics belong in the methods
section, not in a footnote — a reader cannot interpret two vantages without
knowing how they differ.
