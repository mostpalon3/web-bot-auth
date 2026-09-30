#!/bin/bash
# Stand up the instrumented Signature Agent origin.
#
#   bash setup.sh
#
# Run `npx wrangler login` first - it opens a browser and asks you to approve
# CLI access to your own Cloudflare account. Everything after that is
# automatic. Nothing here touches any third party.
set -e
cd "$(dirname "$0")"

W="npx wrangler"

echo "== 1/5  account"
$W whoami | tail -5

echo
echo "== 2/5  KV namespace for the directory-fetch log"
if grep -q 'kv_namespaces' wrangler.toml; then
    echo "already bound in wrangler.toml"
else
    OUT=$($W kv namespace create WBA_LOG 2>&1)
    echo "$OUT"
    ID=$(echo "$OUT" | grep -oE '[0-9a-f]{32}' | head -1)
    if [ -z "$ID" ]; then
        echo "could not parse the namespace id from the output above."
        echo "add it to wrangler.toml by hand:"
        echo '  [[kv_namespaces]]'
        echo '  binding = "WBA_LOG"'
        echo '  id = "<the id>"'
        exit 1
    fi
    printf '\n[[kv_namespaces]]\nbinding = "WBA_LOG"\nid = "%s"\n' "$ID" >> wrangler.toml
    echo "bound WBA_LOG = $ID"
fi

echo
echo "== 3/5  read token for /hits"
# The log holds third-party IP addresses; it must not be world-readable.
if [ -f .hits_token ]; then
    echo "reusing existing .hits_token"
else
    head -c 24 /dev/urandom | base64 | tr -d '/+=' > .hits_token
    echo "generated a new token"
fi
tr -d '\n' < .hits_token | $W secret put HITS_TOKEN
echo "token stored as a Worker secret (kept locally in worker/.hits_token)"

echo
echo "== 4/5  deploy"
$W deploy

echo
echo "== 5/5  verify"
BASE="https://wba-probe.$($W whoami 2>/dev/null | grep -oE '[a-z0-9-]+\.workers\.dev' | head -1 | sed 's/\.workers\.dev//').workers.dev"
echo "checking the directory media type and that the key is unchanged..."
curl -sSI "https://wba-probe.aniksaha4049.workers.dev/.well-known/http-message-signatures-directory" | head -6 || true
echo
curl -sS "https://wba-probe.aniksaha4049.workers.dev/.well-known/http-message-signatures-directory"
echo
echo
echo "read the fetch log with:"
echo "  curl -sS \"https://wba-probe.aniksaha4049.workers.dev/hits?token=\$(cat worker/.hits_token)\""
