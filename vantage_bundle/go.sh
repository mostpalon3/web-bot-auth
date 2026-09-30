#!/bin/bash
# Everything, in one command. Nothing silent, nothing to follow up on.
#
#   bash go.sh          full run   (~55 min)
#   bash go.sh quick    short run  (~15 min)
#
# Stages 1-5 set up and verify. Stage 5 is a hard gate: if the signature does
# not verify against the published directory, nothing external is sent.
# Stages 6-9 collect. Stage 10 compares against the laptop baseline and prints
# what the result licenses.

set -o pipefail
cd "$(dirname "$0")"
START=$(date +%s)

MODE=${1:-full}
if [ "$MODE" = "quick" ]; then
    E1_N=400; CONF_N=100; CENSUS_N=500
else
    E1_N=1500; CONF_N=298; CENSUS_N=3000
fi

CONTACT="sumit.sagar.ug23@nsut.ac.in"
INFO="https://sumit-sagar.github.io/signed-lane/"

say() { echo; echo "=============================================================="; echo "  $*"; echo "=============================================================="; }

say "1/10  python"
python3 --version || { echo "no python3 - install it and rerun"; exit 1; }

say "2/10  dependencies"
if python3 -c "import cryptography, requests" 2>/dev/null; then
    PY=python3; echo "cryptography and requests already present"
elif [ -x ./venv/bin/python ] && ./venv/bin/python -c "import cryptography, requests" 2>/dev/null; then
    PY=./venv/bin/python; echo "existing venv is usable"
else
    echo "creating a venv..."
    python3 -m venv venv 2>/dev/null || { sudo apt-get install -y python3-venv && python3 -m venv venv; }
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install cryptography requests
    PY=./venv/bin/python
fi
echo "interpreter: $PY"

say "3/10  signing key"
[ -f research.pem ] && { mkdir -p keys; mv -f research.pem keys/research.pem; }
chmod 600 keys/research.pem
ls -l keys/research.pem

say "4/10  public IP"
IP=$(curl -s --max-time 20 https://api64.ipify.org)
echo "$IP" | tee vantage_ip.txt
if [ "$IP" = "202.59.209.34" ]; then
    echo "-> same address as the laptop: this varies the TLS stack, not the network"
else
    echo "-> different address: this is a genuine second vantage point"
fi

say "5/10  verifying the signature resolves  (HARD GATE)"
$PY - <<'PY'
import sys, base64, requests
sys.path.insert(0, '.')
from wba.keys import SigningKey, jwk_to_public, thumbprint_of_jwk, verify
from wba.signature import Request, SigParams, sign, signature_base
AGENT = 'https://sumit-sagar.github.io/signed-lane/'
key = SigningKey.from_pem('keys/research.pem')
print('  our keyid :', key.thumbprint())
jwks = requests.get(AGENT.rstrip('/') + '/.well-known/http-message-signatures-directory',
                    timeout=25).json()
kids = [thumbprint_of_jwk(k) for k in jwks['keys']]
print('  published :', kids)
pub_ok = key.thumbprint() in kids
print('  key is published   :', pub_ok)
req = Request('GET', 'https://example.org/', {'Signature-Agent': f'"{AGENT}"'})
p = SigParams.fresh(key.thumbprint()); h = sign(key, req, p)
ok = False
if pub_ok:
    pub = jwk_to_public(next(k for k in jwks['keys'] if thumbprint_of_jwk(k) == key.thumbprint()))
    ok = verify(pub, base64.b64decode(h['Signature'].split(':')[1]), signature_base(req, p))
print('  signature verifies :', ok)
sys.exit(0 if ok else 1)
PY
if [ $? -ne 0 ]; then
    echo; echo "ABORTED - the signature does not verify."
    echo "Publish the key before sending signatures nobody can check."
    exit 1
fi

say "6/10  E1 differential   ($E1_N origins, ~$((E1_N*4/8/60)) min)"
echo "Ctrl+C within 10 seconds to abort all collection."
sleep 10
$PY -u differential.py --hosts tranco_3k.csv --limit "$E1_N" --repeats 2 \
    --workers 28 --rate 8 --delay 1.0 --timeout 12 --verbose \
    --contact "$CONTACT" --info-url "$INFO" --i-have-signoff

say "7/10  E1b confound   ($CONF_N origins x 4 arms)"
$PY -u confound.py --hosts blockers.txt --limit "$CONF_N" --repeats 2 \
    --workers 16 --delay 1.0 --timeout 12 \
    --contact "$CONTACT" --info-url "$INFO" --i-have-signoff

say "8/10  census slice   ($CENSUS_N hosts)"
$PY -u scan.py --hosts tranco_3k.csv --limit "$CENSUS_N" --rate 10 --workers 32 \
    --timeout 8 --contact "$CONTACT" --info-url "$INFO" --i-have-signoff

say "9/10  what was collected"
ls -1 results/differential/ 2>/dev/null | tail -3
ls -1 results/confound/ 2>/dev/null | tail -2
ls -1 results/scans/ 2>/dev/null | tail -2

say "10/10  comparison against the laptop baseline"
$PY compare.py

END=$(date +%s)
say "finished in $(( (END-START)/60 )) minutes"
echo "Copy the whole results/ directory back to the laptop:"
echo "  the folder is $(pwd)/results"
