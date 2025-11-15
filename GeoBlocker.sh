#!/usr/bin/env bash
#
# GeoBlocker.sh — SSH US-only Geo-Limit helper for nftables (Ubuntu 24.04)
# VERSION: v1.1.1
#
# AUTHORS / ORIGIN:
#   - R. Scott Baer <baerrs@gmail.com>
#   - OpenAI GPT-5.1 Thinking (AI-assisted design and implementation)
#
# LICENSE: MIT
#
# MIT License
# Copyright (c) 2025 R. Scott Baer and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# GEO IP DATA SOURCE:
#   IPv4 and IPv6 US ranges are downloaded from IPdeny:
#     - https://www.ipdeny.com
#     - Usage limits and terms: https://www.ipdeny.com/usagelimits.php
#
# CHANGELOG
# - v1.1.1:
#     * FIX: Corrected function call syntax in fast_load_sets()
#       (bulk_load_one_set "$SET_V4" "$FILE_V4" style) to avoid
#       "syntax error near unexpected token" on some shells.
# - v1.1.0:
#     * Added SSH client information to --investigate output:
#         - SSH_CONNECTION and SSH_CLIENT
#         - Detected client public IP (first field of SSH_CONNECTION)
#       This can be used later to build a whitelist feature.
# - v1.0.0:
#     * Initial public release for Ubuntu 24.04.
#     * Unified:
#         - Investigation of nftables and geo data
#         - Geo data download from IPdeny
#         - Fast bulk loading of inet filter us_v4/us_v6
#         - Optional commented SSH geo-snippet append to /etc/nftables.conf
#
# TARGET PLATFORM:
#   - Ubuntu Server 24.04 (fresh install or similar)
#   - nftables available (nft command present)
#   - Default nftables config at /etc/nftables.conf
#   - Geo data directory: /etc/nftables.d
#
# PURPOSE:
#   Provide an all-in-one helper for:
#     - Managing US-only IP ranges for SSH geo-limiting via nftables.
#     - Setting up /etc/nftables.d/us-v4.txt and us-v6.txt from IPdeny.
#     - Fast-loading inet filter us_v4/us_v6 sets from those files.
#     - Optionally appending a commented SSH geo-limit snippet into
#       /etc/nftables.conf for manual integration.
#
# SAFETY NOTES:
#   - This script does NOT automatically apply nftables configs.
#   - It only modifies:
#       * /etc/nftables.d/us-v4.txt
#       * /etc/nftables.d/us-v6.txt
#       * /etc/nftables.conf (only when --append-ssh-geo-snippet is used,
#         and only by appending a commented block with a backup first).
#   - You remain in control of:
#       * When to apply nftables rules (sudo nft -f /etc/nftables.conf).
#       * Where to place the sets and SSH drop rules in your ruleset.
#
# TYPICAL WORKFLOW (Ubuntu 24.04 fresh-ish install):
#   1) Ensure nftables is installed and enabled:
#        sudo apt update
#        sudo apt install nftables -y    # (optional: fail2ban)
#        sudo systemctl enable --now nftables
#
#   2) Edit /etc/nftables.conf to define:
#        - table inet filter
#        - sets us_v4/us_v6
#        - SSH geo-limit rules (tcp dport 22 ... drop)
#      (You can use --append-ssh-geo-snippet as a guided template.)
#
#   3) Apply nftables config:
#        sudo nft -c -f /etc/nftables.conf
#        sudo nft -f /etc/nftables.conf
#
#   4) Use this script to manage geo data and sets:
#        sudo ./GeoBlocker.sh --setup-geo-data
#        sudo ./GeoBlocker.sh --fast-load
#        sudo ./GeoBlocker.sh --verify-sets
#
#   5) (Optional) Add a cron/systemd timer to refresh IPdeny lists and reload
#      sets daily using --setup-geo-data and --fast-load.
#

set -euo pipefail
IFS=$'\n\t'

VERSION='v1.1.1'
SCRIPT_NAME="$(basename "$0")"

# Paths and names (Ubuntu 24.04 defaults)
NFT_CONF="/etc/nftables.conf"
GEO_DIR="/etc/nftables.d"
FILE_V4="$GEO_DIR/us-v4.txt"
FILE_V6="$GEO_DIR/us-v6.txt"

FAMILY="inet"
TABLE="filter"
SET_V4="us_v4"
SET_V6="us_v6"

CHUNK_SIZE=512   # number of CIDRs per bulk add command

log() {
  printf '%s [%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$SCRIPT_NAME" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die "Required command '$cmd' not found in PATH"
  fi
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    local ts
    ts="$(date +'%Y%m%d.%H%M%S')"
    local backup="${path}.${ts}.bak"
    cp -a -- "$path" "$backup" || die "Failed to create backup of '$path' at '$backup'"
    log "Backup created: $backup"
  else
    log "No existing '$path' to back up (file not present)"
  fi
}

download_file_atomic() {
  local url="$1"
  local dest="$2"

  require_cmd curl
  require_cmd install

  local tmp
  tmp="$(mktemp)" || die "mktemp failed for '$dest'"

  log "Downloading '$url' -> '$dest'"
  log "NOTE: IP data source is IPdeny (https://www.ipdeny.com)."
  log "      Please review IPdeny usage limits: https://www.ipdeny.com/usagelimits.php"
  if ! curl -fsSL "$url" -o "$tmp"; then
    rm -f -- "$tmp"
    die "Download failed from '$url'"
  fi

  if [[ ! -s "$tmp" ]]; then
    rm -f -- "$tmp"
    die "Downloaded file from '$url' is empty; aborting"
  fi

  backup_file "$dest"
  install -m 0644 "$tmp" "$dest" || {
    rm -f -- "$tmp"
    die "Failed to install '$dest'"
  }
  rm -f -- "$tmp"
  log "Installed '$dest' successfully (atomic write)"
}

setup_geo_data() {
  mkdir -p "$GEO_DIR" || die "Failed to create directory '$GEO_DIR'"

  download_file_atomic "https://www.ipdeny.com/ipblocks/data/countries/us.zone" "$FILE_V4"
  download_file_atomic "https://www.ipdeny.com/ipv6/ipaddresses/blocks/us.zone" "$FILE_V6"

  log "Geo data setup complete in '$GEO_DIR'"
}

append_ssh_geo_snippet() {
  require_cmd install

  if [[ ! -f "$NFT_CONF" ]]; then
    die "nftables config '$NFT_CONF' not found"
  fi

  if grep -q 'RSBB_SSH_GEO_LIMIT BEGIN' "$NFT_CONF"; then
    log "SSH geo-limit snippet already present in '$NFT_CONF'; skipping append"
    return 0
  fi

  backup_file "$NFT_CONF"

  local tmp
  tmp="$(mktemp)" || die "mktemp failed for nftables.conf tmp"

  # Copy existing config, then append commented snippet
  cat "$NFT_CONF" >"$tmp" || {
    rm -f -- "$tmp"
    die "Failed to copy '$NFT_CONF' into temp file"
  }

  cat >>"$tmp" <<'EOF_SNIPPET'

# =====================================================================
# RSBB_SSH_GEO_LIMIT BEGIN
# This is a commented example snippet for SSH geo-limiting to US IPs.
# You MUST manually integrate the sets and rules into your existing
# table inet filter / chain input (before your SSH ACCEPT rule).
#
# Example nftables structure (Ubuntu 24.04 compatible):
#
# table inet filter {
#     # (your existing sets & rules...)
#
#     set us_v4 {
#         type ipv4_addr
#         flags interval
#         # Initially empty; elements are loaded at runtime.
#     }
#
#     set us_v6 {
#         type ipv6_addr
#         flags interval
#         # Initially empty; elements are loaded at runtime.
#     }
#
#     chain input {
#         type filter hook input priority filter; policy accept;
#
#         # SSH Geo-Limit (apply BEFORE allowing SSH)
#         # Uncomment and insert BEFORE your SSH ACCEPT rule:
#         #   tcp dport 22 ip  saddr != @us_v4 drop
#         #   tcp dport 22 ip6 saddr != @us_v6 drop
#
#         # (rest of your chain...)
#     }
# }
#
# After editing:
#   sudo nft -c -f /etc/nftables.conf   # validate
#   sudo nft -f /etc/nftables.conf      # apply
#
# RSBB_SSH_GEO_LIMIT END
# =====================================================================

EOF_SNIPPET

  install -m 0644 "$tmp" "$NFT_CONF" || {
    rm -f -- "$tmp"
    die "Failed to write updated '$NFT_CONF'"
  }
  rm -f -- "$tmp"
  log "Appended commented SSH geo-limit snippet to '$NFT_CONF'"
}

check_sets_exist() {
  require_cmd nft

  if ! nft list set "$FAMILY" "$TABLE" "$SET_V4" >/dev/null 2>&1; then
    die "Set '$FAMILY $TABLE $SET_V4' not found. Ensure /etc/nftables.conf defines it and is applied."
  fi
  if ! nft list set "$FAMILY" "$TABLE" "$SET_V6" >/dev/null 2>&1; then
    die "Set '$FAMILY $TABLE $SET_V6' not found. Ensure /etc/nftables.conf defines it and is applied."
  fi
}

check_files_exist() {
  if [[ ! -f "$FILE_V4" ]]; then
    die "IPv4 geo file '$FILE_V4' not found. Run --setup-geo-data first."
  fi
  if [[ ! -f "$FILE_V6" ]]; then
    die "IPv6 geo file '$FILE_V6' not found. Run --setup-geo-data first."
  fi

  if [[ ! -s "$FILE_V4" ]]; then
    die "IPv4 geo file '$FILE_V4' is empty."
  fi
  if [[ ! -s "$FILE_V6" ]]; then
    die "IPv6 geo file '$FILE_V6' is empty."
  fi
}

flush_sets() {
  check_sets_exist
  log "Flushing set $FAMILY $TABLE $SET_V4"
  nft flush set "$FAMILY" "$TABLE" "$SET_V4"

  log "Flushing set $FAMILY $TABLE $SET_V6"
  nft flush set "$FAMILY" "$TABLE" "$SET_V6"

  log "Flush complete."
}

bulk_load_one_set() {
  local set_name="$1"
  local src_file="$2"

  check_sets_exist

  if [[ ! -f "$src_file" ]]; then
    die "Source file '$src_file' not found."
  fi

  local total=0
  local batch=""
  local count=0

  log "Starting bulk load into $FAMILY $TABLE $set_name from '$src_file' (chunk size: $CHUNK_SIZE)"

  while IFS= read -r cidr; do
    [[ -n "$cidr" ]] || continue

    if [[ -z "$batch" ]]; then
      batch="$cidr"
    else
      batch="$batch, $cidr"
    fi

    count=$((count + 1))
    total=$((total + 1))

    if (( count >= CHUNK_SIZE )); then
      nft add element "$FAMILY" "$TABLE" "$set_name" "{ $batch }"
      batch=""
      count=0
    fi
  done <"$src_file"

  if [[ -n "$batch" ]]; then
    nft add element "$FAMILY" "$TABLE" "$set_name" "{ $batch }"
  fi

  log "Finished bulk load: $total elements added to $FAMILY $TABLE $set_name"
}

fast_load_sets() {
  check_sets_exist
  check_files_exist

  log "Starting fast-load of $FAMILY $TABLE $SET_V4 and $SET_V6"

  flush_sets

  bulk_load_one_set "$SET_V4" "$FILE_V4"
  bulk_load_one_set "$SET_V6" "$FILE_V6"

  log "Fast-load completed for both sets."
}

verify_sets() {
  check_sets_exist

  local count_v4
  local count_v6
  local lines_v4
  local lines_v6

  count_v4="$(nft list set "$FAMILY" "$TABLE" "$SET_V4" | wc -l || echo 0)"
  count_v6="$(nft list set "$FAMILY" "$TABLE" "$SET_V6" | wc -l || echo 0)"

  if [[ -f "$FILE_V4" ]]; then
    lines_v4="$(wc -l <"$FILE_V4" 2>/dev/null || echo 0)"
  else
    lines_v4="0"
  fi
  if [[ -f "$FILE_V6" ]]; then
    lines_v6="$(wc -l <"$FILE_V6" 2>/dev/null || echo 0)"
  else
    lines_v6="0"
  fi

  echo "=== Verification for inet filter us_v4/us_v6 ==="
  echo "Set: $FAMILY $TABLE $SET_V4 -> approx $count_v4 lines in nft list output"
  echo "  Geo file: $FILE_V4 -> $lines_v4 lines"
  echo
  echo "Set: $FAMILY $TABLE $SET_V6 -> approx $count_v6 lines in nft list output"
  echo "  Geo file: $FILE_V6 -> $lines_v6 lines"
  echo
  echo "NOTE: 'nft list set' output may contain multiple elements per line."
  echo "      The loader's own logs show the exact element counts."
}

investigate() {
  echo "=== SSH Geo-Limit Investigation ==="
  echo "Script version: $VERSION"
  echo

  echo "--- Commands ---"
  if command -v nft >/dev/null 2>&1; then
    echo "nft:        present"
  else
    echo "nft:        MISSING"
  fi
  if command -v curl >/dev/null 2>&1; then
    echo "curl:       present"
  else
    echo "curl:       MISSING"
  fi
  if command -v install >/dev/null 2>&1; then
    echo "install:    present"
  else
    echo "install:    MISSING"
  fi
  echo

  echo "--- nftables main config ---"
  if [[ -f "$NFT_CONF" ]]; then
    echo "$NFT_CONF: present"
  else
    echo "$NFT_CONF: MISSING"
  fi
  echo

  echo "--- nftables tables & sets ---"
  if command -v nft >/dev/null 2>&1; then
    if nft list tables >/dev/null 2>&1; then
      if nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1; then
        echo "table $FAMILY $TABLE: present"
      else
        echo "table $FAMILY $TABLE: NOT FOUND"
      fi

      if nft list set "$FAMILY" "$TABLE" "$SET_V4" >/dev/null 2>&1; then
        echo "set $FAMILY $TABLE $SET_V4: present"
      else
        echo "set $FAMILY $TABLE $SET_V4: NOT FOUND"
      fi

      if nft list set "$FAMILY" "$TABLE" "$SET_V6" >/dev/null 2>&1; then
        echo "set $FAMILY $TABLE $SET_V6: present"
      else
        echo "set $FAMILY $TABLE $SET_V6: NOT FOUND"
      fi
    else
      echo "Unable to list nftables tables (nft list tables failed)."
    fi
  else
    echo "nft command not available; skipping nftables inspection."
  fi
  echo

  echo "--- Geo data files ---"
  if [[ -d "$GEO_DIR" ]]; then
    echo "Directory $GEO_DIR: present"
  else
    echo "Directory $GEO_DIR: NOT PRESENT"
  fi

  if [[ -f "$FILE_V4" ]]; then
    local lines4
    lines4="$(wc -l <"$FILE_V4" 2>/dev/null || echo 0)"
    echo "$FILE_V4: present ($lines4 lines)"
  else
    echo "$FILE_V4: NOT PRESENT"
  fi

  if [[ -f "$FILE_V6" ]]; then
    local lines6
    lines6="$(wc -l <"$FILE_V6" 2>/dev/null || echo 0)"
    echo "$FILE_V6: present ($lines6 lines)"
  else
    echo "$FILE_V6: NOT PRESENT"
  fi
  echo

  echo "--- Snippet marker in $NFT_CONF ---"
  if [[ -f "$NFT_CONF" ]]; then
    if grep -q 'RSBB_SSH_GEO_LIMIT BEGIN' "$NFT_CONF"; then
      echo "RSBB_SSH_GEO_LIMIT snippet: FOUND"
    else
      echo "RSBB_SSH_GEO_LIMIT snippet: NOT FOUND"
    fi
  else
    echo "Cannot check snippet; $NFT_CONF not found."
  fi
  echo

  echo "--- SSH Client Info ---"
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local conn client_ip
    conn="$SSH_CONNECTION"
    client_ip="${conn%% *}"
    echo "SSH_CONNECTION: $conn"
    echo "SSH_CLIENT:     ${SSH_CLIENT:-"(not set)"}"
    echo "Client public IP (from SSH_CONNECTION): $client_ip"
    echo
    echo "NOTE: This client IP can be used in future to build a whitelist"
    echo "      (e.g., separate ssh_whitelist set in nftables)."
  else
    echo "Not an SSH session (SSH_CONNECTION is empty)."
  fi

  echo
  echo "Investigation complete."
}

print_help() {
  cat <<EOF
$SCRIPT_NAME (version $VERSION) — SSH US-only Geo-Limit helper for nftables (Ubuntu 24.04)

USAGE:
  sudo ./$SCRIPT_NAME [ACTION]

ACTIONS:
  --investigate
      Show:
        - Presence of nft / curl / install
        - Presence of $NFT_CONF
        - table $FAMILY $TABLE and sets $SET_V4 / $SET_V6
        - Geo data files and RSBB SSH snippet marker.
        - SSH client information (SSH_CONNECTION, SSH_CLIENT, and detected client IP).

  --setup-geo-data
      Create $GEO_DIR (if needed) and download from IPdeny:
        - $FILE_V4 (IPv4 US ranges)
        - $FILE_V6 (IPv6 US ranges)
      Existing files are backed up with timestamped .bak copies.
      Writes atomically using 'install'.
      IPdeny usage limits: https://www.ipdeny.com/usagelimits.php

  --append-ssh-geo-snippet
      Backup $NFT_CONF and append a COMMENTED example snippet
      (RSBB_SSH_GEO_LIMIT block) describing how to:
        - Define us_v4/us_v6 sets
        - Add SSH geo-limit rules for port 22
      You must manually integrate these into your inet filter table.

  --fast-load
      Flush and bulk-load nftables sets:
        - $FAMILY $TABLE $SET_V4 from $FILE_V4
        - $FAMILY $TABLE $SET_V6 from $FILE_V6
      Uses chunked inserts (${CHUNK_SIZE} CIDRs per nft add command) for speed.

  --flush-sets
      Flush $FAMILY $TABLE $SET_V4 and $SET_V6 only.

  --verify-sets
      Show approximate line counts in:
        - $FAMILY $TABLE $SET_V4
        - $FAMILY $TABLE $SET_V6
      And compare to the geo files' line counts.

  --help, -h
      Show this help.

DEFAULT:
  If no ACTION is specified, --help is shown.

NOTES:
  - This script does NOT automatically apply nftables configs.
  - After editing $NFT_CONF, you typically run:
        sudo nft -c -f $NFT_CONF   # validate
        sudo nft -f $NFT_CONF      # apply
  - Ensure table $FAMILY $TABLE and sets $SET_V4/$SET_V6 are defined
    in your nftables config and applied before using --fast-load.
  - Geo IP data source: IPdeny (https://www.ipdeny.com).
    Please review their usage limits: https://www.ipdeny.com/usagelimits.php
EOF
}

main() {
  local action="${1:-"--help"}"

  case "$action" in
    --help|-h)
      print_help
      ;;
    --investigate)
      investigate
      ;;
    --setup-geo-data)
      setup_geo_data
      ;;
    --append-ssh-geo-snippet)
      append_ssh_geo_snippet
      ;;
    --fast-load)
      fast_load_sets
      ;;
    --flush-sets)
      flush_sets
      ;;
    --verify-sets)
      verify_sets
      ;;
    *)
      die "Unknown action '$action'. Use --help for usage."
      ;;
  esac
}

main "$@"
