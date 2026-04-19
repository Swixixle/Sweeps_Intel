#!/bin/bash
set -euo pipefail

MARKER_BEGIN="# BEGIN SWEEPS_RELIEF_MANAGED"
MARKER_END="# END SWEEPS_RELIEF_MANAGED"
HOSTS_FILE="/etc/hosts"
BASE_DIR="${BASE_DIR:-/Library/Application Support/SweepsRelief}"
DOMAINS_FILE="${DOMAINS_FILE:-$BASE_DIR/domains.txt}"
LOG_FILE="${LOG_FILE:-/var/log/sweeps_relief.log}"

mkdir -p "$BASE_DIR"
touch "$LOG_FILE"

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") ERROR missing domains file: $DOMAINS_FILE" >> "$LOG_FILE"
  exit 1
fi

TMP_BLOCK="$(mktemp)"
TMP_HOSTS="$(mktemp)"

{
  echo "$MARKER_BEGIN"
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    domain="$(echo "$raw" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ -z "$domain" ]] && continue
    [[ "$domain" == \#* ]] && continue
    echo "0.0.0.0 $domain"
    echo "0.0.0.0 www.$domain"
  done < "$DOMAINS_FILE"
  echo "$MARKER_END"
} > "$TMP_BLOCK"

if [[ ! -f "$HOSTS_FILE" ]]; then
  touch "$HOSTS_FILE"
fi

python3 - "$HOSTS_FILE" "$TMP_BLOCK" "$TMP_HOSTS" <<'PY'
import sys
from pathlib import Path

hosts_path = Path(sys.argv[1])
block_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])

begin = "# BEGIN SWEEPS_RELIEF_MANAGED"
end = "# END SWEEPS_RELIEF_MANAGED"

existing = hosts_path.read_text(encoding="utf-8", errors="ignore")
block = block_path.read_text(encoding="utf-8")

lines = existing.splitlines()
begin_idx = next((i for i, line in enumerate(lines) if line.strip() == begin), None)
end_idx = next((i for i, line in enumerate(lines) if line.strip() == end), None)

if begin_idx is None and end_idx is None:
    merged = existing
    if merged and not merged.endswith("\n"):
        merged += "\n"
    if merged and not merged.endswith("\n\n"):
        merged += "\n"
    merged += block
    if not merged.endswith("\n"):
        merged += "\n"
elif begin_idx is not None and end_idx is not None and end_idx > begin_idx:
    before = lines[:begin_idx]
    after = lines[end_idx+1:]
    merged_lines = before + block.splitlines() + after
    merged = "\n".join(merged_lines)
    if not merged.endswith("\n"):
        merged += "\n"
else:
    raise SystemExit("orphan managed-section markers in /etc/hosts")

out_path.write_text(merged, encoding="utf-8")
PY

if cmp -s "$TMP_HOSTS" "$HOSTS_FILE"; then
  rm -f "$TMP_BLOCK" "$TMP_HOSTS"
  exit 0
fi

cp "$HOSTS_FILE" "$HOSTS_FILE.sweeps_relief.backup.$(date +%Y%m%d-%H%M%S)"
cat "$TMP_HOSTS" > "$HOSTS_FILE"

dscacheutil -flushcache >/dev/null 2>&1 || true
killall -HUP mDNSResponder >/dev/null 2>&1 || true

COUNT=$(grep -cvE '^\s*$|^\s*#' "$DOMAINS_FILE" || true)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") APPLIED managed block with $COUNT domains from $DOMAINS_FILE" >> "$LOG_FILE"

rm -f "$TMP_BLOCK" "$TMP_HOSTS"
