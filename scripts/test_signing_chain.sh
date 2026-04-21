#!/usr/bin/env bash
#
# End-to-end signing chain test for the Sweeps trio.
# Runs: Scout signs fingerprints → Intel verifies → Intel produces signed snapshot → Relief verifies.
# Exits non-zero if any hop fails. Prints a clear summary at each step.
#
# Paths configurable via env vars:
#   SCOUT_REPO, INTEL_REPO, RELIEF_REPO (default: ~/Sweeps_Scout, etc.)
#
# Requires: Python 3.11+, each repo having its venv at .venv/ with packages installed
# and keys present (run --generate-keypair commands first if needed — see docs/end_to_end_test.md)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEL_REPO="${INTEL_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SCOUT_REPO="${SCOUT_REPO:-$HOME/Sweeps_Scout}"
RELIEF_REPO="${RELIEF_REPO:-$HOME/Sweeps_Relief}"

readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; }
sep() { echo -e "${DIM}────────────────────────────────────────────────────────${NC}"; }

step_banner() {
  local n="$1" total="$2" msg="$3"
  echo ""
  sep
  echo -e "Step ${n}/${total}: ${msg}"
  sep
}

ensure_scout_seed_domains() {
  local f="$SCOUT_REPO/data/candidates/discovered_domains.json"
  mkdir -p "$(dirname "$f")"
  export SCOUT_DISCOVERED_JSON="$f"
  python3 - <<PY
import json
import os
from pathlib import Path
p = Path(os.environ["SCOUT_DISCOVERED_JSON"])
p.parent.mkdir(parents=True, exist_ok=True)
empty = True
if p.is_file():
    try:
        data = json.loads(p.read_text(encoding="utf-8") or "[]")
        empty = not (isinstance(data, list) and len(data) > 0)
    except json.JSONDecodeError:
        empty = True
if empty:
    p.write_text(
        '[{"domain": "example.com"}, {"domain": "iana.org"}]\n',
        encoding="utf-8",
    )
PY
}

require_venv() {
  local repo="$1" name="$2"
  if [[ ! -d "$repo/.venv" ]]; then
    fail "Missing venv at $repo/.venv ($name). See docs/end_to_end_test.md"
    exit 10
  fi
}

TOTAL_STEPS=6

# --- Step 1: Scout signs fingerprints
step_banner 1 "$TOTAL_STEPS" "Scout signs fingerprints"
require_venv "$SCOUT_REPO" "Scout"
ensure_scout_seed_domains
t0=$(date +%s)
(
  cd "$SCOUT_REPO"
  # shellcheck source=/dev/null
  source .venv/bin/activate
  python -m sweep_scout.fingerprint --sign \
    --private-key ./keys/private.pem \
    --key-id scout-fingerprint-key-v1 \
    --max-domains 2
) || { fail "Step 1 failed: Scout fingerprint/sign"; exit 1; }
t1=$(date +%s)
FP_OUT="$SCOUT_REPO/data/candidates/domain_fingerprints.json"
if [[ ! -f "$FP_OUT" ]]; then
  fail "Step 1 failed: expected $FP_OUT"
  exit 1
fi
export SCOUT_FP_OUT="$FP_OUT"
python3 - <<PY || { fail "Step 1 failed: output is not a signed envelope"; exit 1; }
import json
import os
from pathlib import Path
p = Path(os.environ["SCOUT_FP_OUT"])
d = json.loads(p.read_text(encoding="utf-8"))
assert "payload" in d and "signature" in d, "not a signed envelope"
assert d["signature"].get("algorithm") == "ed25519"
PY
ok "Scout wrote signed domain_fingerprints.json ($((t1 - t0))s)"

# --- Step 2: Hand off to Intel
step_banner 2 "$TOTAL_STEPS" "Hand off to Intel"
SCOUT_IMPORT="$INTEL_REPO/data/research_candidates/scout_import"
mkdir -p "$SCOUT_IMPORT"
cp "$FP_OUT" "$SCOUT_IMPORT/domain_fingerprints.json" || { fail "Step 2 failed: copy to Intel"; exit 2; }
ok "Copied domain_fingerprints.json → Intel scout_import/"

# --- Step 3: Intel verifies Scout's signature
step_banner 3 "$TOTAL_STEPS" "Intel verifies Scout's signature"
require_venv "$INTEL_REPO" "Intel"
t0=$(date +%s)
FP_COUNT="$(
  cd "$INTEL_REPO"
  # shellcheck source=/dev/null
  source .venv/bin/activate
  python - <<'PY'
from pathlib import Path
from intel._trust_store import load_trust_store
from intel.scout_fingerprint_loader import load_fingerprints

repo = Path.cwd()
ts = load_trust_store(repo / "trust_store.json")
path = repo / "data/research_candidates/scout_import/domain_fingerprints.json"
fps = load_fingerprints(path, trust_store=ts, require_signed=True)
print(len(fps))
PY
)" || { fail "Step 3 failed: Intel could not verify Scout fingerprints"; exit 3; }
t1=$(date +%s)
ok "Intel verified Scout envelope (${FP_COUNT} domain records) ($((t1 - t0))s)"

# --- Step 4: Intel signs snapshot + blocklist
step_banner 4 "$TOTAL_STEPS" "Intel signs snapshot and blocklist"
t0=$(date +%s)
(
  cd "$INTEL_REPO"
  # shellcheck source=/dev/null
  source .venv/bin/activate
  python -m intel.exporters \
    --sign-snapshot \
    --snapshot-private-key keys/snapshot/private.pem \
    --snapshot-key-id intel-snapshot-key-v1 \
    --sign-blocklist \
    --blocklist-private-key keys/blocklist/private.pem \
    --blocklist-key-id intel-blocklist-key-v1
) || { fail "Step 4 failed: Intel exporters"; exit 4; }
t1=$(date +%s)
PUB="$INTEL_REPO/data/published"
for f in intel_snapshot.json block_candidates.json; do
  if [[ ! -f "$PUB/$f" ]]; then
    fail "Step 4 failed: missing $PUB/$f"
    exit 4
  fi
done
export INTEL_PUBLISHED_DIR="$PUB"
python3 - <<PY || { fail "Step 4 failed: published files are not signed envelopes"; exit 4; }
import json
import os
from pathlib import Path
root = Path(os.environ["INTEL_PUBLISHED_DIR"])
for name in ("intel_snapshot.json", "block_candidates.json"):
    d = json.loads((root / name).read_text(encoding="utf-8"))
    assert "payload" in d and "signature" in d, f"{name} not signed"
PY
ok "Intel wrote signed intel_snapshot.json and block_candidates.json ($((t1 - t0))s)"

# --- Step 5: Hand off to Relief
step_banner 5 "$TOTAL_STEPS" "Hand off to Relief"
HANDOFF="$RELIEF_REPO/data/intel_handoff"
mkdir -p "$HANDOFF"
cp "$PUB/intel_snapshot.json" "$HANDOFF/"
cp "$PUB/block_candidates.json" "$HANDOFF/" || { fail "Step 5 failed: copy to Relief"; exit 5; }
ok "Copied published artifacts → Relief data/intel_handoff/"

# --- Step 6: Relief verifies Intel's signatures
step_banner 6 "$TOTAL_STEPS" "Relief verifies Intel's signatures"
require_venv "$RELIEF_REPO" "Relief"
t0=$(date +%s)
COUNTS="$(
  cd "$RELIEF_REPO"
  # shellcheck source=/dev/null
  source .venv/bin/activate
  python - <<'PY'
from pathlib import Path
from sweeps_relief.envelope._trust_store import load_trust_store
from sweeps_relief.envelope.ingest import load_verified_blocklist, load_verified_snapshot

repo = Path.cwd()
ts = load_trust_store(repo / "trust_store.json")
snap = load_verified_snapshot(repo / "data/intel_handoff/intel_snapshot.json", ts)
blk = load_verified_blocklist(repo / "data/intel_handoff/block_candidates.json", ts)
assert snap.get("artifact_type") == "intel_snapshot"
assert blk.get("artifact_type") == "intel_block_candidates"
print(
    len(snap.get("entities", [])),
    len(snap.get("relationships", [])),
    len(snap.get("affiliations", [])),
    sep=",",
)
PY
)" || { fail "Step 6 failed: Relief could not verify Intel artifacts"; exit 6; }
t1=$(date +%s)
IFS=',' read -r ENTITIES RELS AFFILS <<<"$COUNTS"
ok "Relief verified snapshot and blocklist ($((t1 - t0))s)"

# --- Final summary
echo ""
sep
echo -e "${GREEN}✓ Signing chain verified end-to-end${NC}"
echo "  fingerprints: ${FP_COUNT}"
echo "  entities: ${ENTITIES}"
echo "  relationships: ${RELS}"
echo "  affiliations: ${AFFILS}"
sep
exit 0
