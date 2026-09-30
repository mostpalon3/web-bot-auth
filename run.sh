#!/usr/bin/env bash
#
# Project runner for: Web Bot Auth — From Signatures to Enforcement
#
# Everything here is split into two halves, deliberately.
#
#   OFFLINE  — setup, validation and re-analysis of the committed result files.
#              Touches nothing but this directory. Safe to run anywhere, any
#              number of times. This is what you want for a demo or a viva.
#
#   LIVE     — the measurement experiments, which send real requests to real
#              third-party websites. Gated behind explicit confirmation and a
#              monitored contact address, because they are Internet measurement
#              and carry the obligations that go with it.
#
# Run ./run.sh with no arguments for the offline pipeline.
#
set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PY="$VENV/bin/python"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
rule() { printf '%s\n' "------------------------------------------------------------"; }
step() { printf '\n'; bold "==> $*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ───────────────────────────── offline ──────────────────────────────

cmd_setup() {
  step "Setting up the environment"
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$VENV/bin/pip" -q install --upgrade pip
  "$VENV/bin/pip" -q install -r requirements.txt
  printf 'python  : '; "$PY" --version
  printf 'deps    : '; tr '\n' ' ' < requirements.txt; printf '\n'
}

cmd_check() {
  step "Validating the instrument (offline)"
  echo "The harness must reproduce RFC 9421's own published test vector."
  echo "If it does not, every 'blocked' result would be our bug, not a finding."
  rule
  "$PY" tests/test_rfc9421_vectors.py
  "$PY" tests/test_directory.py
}

cmd_reproduce() {
  step "Reproducing the principal result"
  "$PY" verify_e1.py

  step "Reproducing every headline figure from the committed data"
  "$PY" reproduce.py
}

cmd_analyze() {
  step "Per-experiment analysis (E7 header decomposition)"
  "$PY" decompose_analyze.py
}

cmd_all() {
  cmd_setup
  cmd_check
  cmd_reproduce
  step "Done"
  echo "All offline checks passed. Nothing was sent over the network."
}

# ─────────────────────────────── live ───────────────────────────────

cmd_measure() {
  local contact="" info="" experiment="${1:-}" ; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --contact)  contact="${2:-}"; shift 2 ;;
      --info-url) info="${2:-}";    shift 2 ;;
      *) die "unknown option: $1" ;;
    esac
  done

  [ -n "$experiment" ] || die "usage: ./run.sh measure <census|e1|e4|e7> --contact <email> --info-url <https url>"
  case "$experiment" in
    census|e1|e4|e7) ;;
    *) die "unknown experiment: $experiment  (census|e1|e4|e7)" ;;
  esac
  [ -n "$contact" ] || die "--contact is required and must be an address you actually monitor"
  [ -n "$info" ]    || die "--info-url is required and must be a live page describing the study"
  case "$info" in https://*) ;; *) die "--info-url must be https" ;; esac

  cat <<WARNING

  This sends real requests to real third-party websites.

  Before continuing you must have:
    - institutional sign-off, in writing
    - a monitored address at $contact
    - a live page at $info describing the study and offering opt-out
    - read DISCLOSURE.md and PREREGISTRATION.md

  Requests are rate limited and target public paths only. Every request
  carries the contact address above. Exclusion requests are honoured
  without asking for a reason.

WARNING
  printf 'Type I HAVE SIGNOFF to continue: '
  read -r reply
  [ "$reply" = "I HAVE SIGNOFF" ] || die "aborted"

  local args=(--contact "$contact" --info-url "$info")
  step "Running $experiment"
  case "$experiment" in
    census) "$PY" scan.py         --limit 5000 "${args[@]}" --i-have-signoff ;;
    e1)     "$PY" differential.py --limit 1000 "${args[@]}" --i-have-signoff ;;
    e4)     "$PY" keyfetch.py     "${args[@]}" ;;
    e7)     "$PY" decompose.py    "${args[@]}" ;;
    *) die "unknown experiment: $experiment (census|e1|e4|e7)" ;;
  esac
}

# ─────────────────────────────── help ───────────────────────────────

cmd_help() {
  cat <<'USAGE'
Web Bot Auth — From Signatures to Enforcement

  ./run.sh                 offline pipeline: setup, validate, reproduce  [default]
  ./run.sh setup           create .venv and install dependencies
  ./run.sh check           validate the signer against RFC 9421 test vectors
  ./run.sh reproduce       recompute every published figure from results/
  ./run.sh analyze         per-experiment analysis of the committed data
  ./run.sh help            this message

  ./run.sh measure <experiment> --contact <email> --info-url <https url>
                           LIVE measurement. Sends requests to third-party
                           sites. Requires institutional sign-off.
                           experiments: census | e1 | e4 | e7

Nothing except `measure` touches the network.
USAGE
}

case "${1:-all}" in
  all|"")     cmd_all ;;
  setup)      cmd_setup ;;
  check)      cmd_check ;;
  reproduce)  cmd_reproduce ;;
  analyze)    cmd_analyze ;;
  measure)    shift; cmd_measure "$@" ;;
  help|-h|--help) cmd_help ;;
  *) die "unknown command: $1  (try ./run.sh help)" ;;
esac
