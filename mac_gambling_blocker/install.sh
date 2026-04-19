#!/bin/bash
set -euo pipefail

BASE_DIR="/Library/Application Support/SweepsRelief"
BIN_DIR="$BASE_DIR/bin"
CONFIG_DIR="$BASE_DIR"
PLIST_PATH="/Library/LaunchDaemons/com.sweepsrelief.reassert.plist"
SCRIPT_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_SRC_DIR" && pwd)"

mkdir -p "$BIN_DIR" "$CONFIG_DIR"

cp "$ROOT_DIR/bin/apply_blocklist.sh" "$BIN_DIR/apply_blocklist.sh"
cp "$ROOT_DIR/config/domains.txt" "$CONFIG_DIR/domains.txt"
chmod 755 "$BIN_DIR/apply_blocklist.sh"

cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.sweepsrelief.reassert</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DIR/apply_blocklist.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>StandardOutPath</key>
  <string>/var/log/sweeps_relief_launchd.out</string>
  <key>StandardErrorPath</key>
  <string>/var/log/sweeps_relief_launchd.err</string>
</dict>
</plist>
PLIST

chmod 644 "$PLIST_PATH"
launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable system/com.sweepsrelief.reassert

"$BIN_DIR/apply_blocklist.sh"

echo "Installed. Reassertion runs every 300 seconds."
echo "Domains file: $CONFIG_DIR/domains.txt"
echo "LaunchDaemon: $PLIST_PATH"
