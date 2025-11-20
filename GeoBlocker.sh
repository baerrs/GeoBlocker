#!/usr/bin/env bash
#
# GeoBlocker.sh — SSH US-only Geo-Limit helper for nftables (Ubuntu 24.04)
# VERSION: v1.2.2
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
#   IPv4 and IPv6 ranges are downloaded from IPdeny (default country: US):
#     - https://www.ipdeny.com
#     - Usage limits and terms: https://www.ipdeny.com/usagelimits.php
#
# CHANGELOG
# - v1.2.2:
#     * Allow overriding the IPdeny country via COUNTRY_CODE (default: 'us').
#     * Minor argument handling cleanup for whitelist add/remove actions.
# - v1.2.1:
#     * Added explicit privilege detection helpers:
#         - require_root(): enforce root for actions that modify system files.
#         - require_nft_priv(): verify that 'nft list tables' works (privileges).
#       Integrated into geo-data setup, config editing, and nft-modifying actions.
#       Investigation output now exposes privilege context more clearly.
# - v1.2.0:
#     * Added SSH whitelist support (IPv4 + IPv6) with:
#         - ssh_whitelist_v4 / ssh_whitelist_v6 sets (user-defined in nftables).
#         - Actions:
#             - --whitelist-add-current
#             - --whitelist-add IP
#             - --whitelist-remove IP
#             - --whitelist-list
#         - --investigate reports whitelist set presence and whether the
#           current SSH client IP (v4 or v6) is whitelisted.
# - v1.1.1:
#     * FIX: Corrected function call syntax in fast_load_sets() to avoid
#       syntax errors on some shells.
# - v1.1.0:
#     * Added SSH client information to --investigate output.
# - v1.0.0:
#     * Initial public release for Ubuntu 24.04.
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
#     - Managing SSH whitelist sets (ssh_whitelist_v4 / ssh_whitelist_v6).
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
#        - OPTIONAL whitelist sets:
#             set ssh_whitelist_v4 { type ipv4_addr; flags interval; }
#             set ssh_whitelist_v6 { type ipv6_addr; flags interval; }
#          And in chain input (order matters):
#             tcp dport 22 ip  saddr  @ssh_whitelist_v4 accept
#             tcp dport 22 ip6 saddr @ssh_whitelist_v6 accept
#             tcp dport 22 ip  saddr != @us_v4 drop
#             tcp dport 22 ip6 saddr != @us_v6 drop
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
#   5) Manage whitelist:
#        sudo ./GeoBlocker.sh --whitelist-add-current   # add your current IP
#        sudo ./GeoBlocker.sh --whitelist-list
#
#   6) (Optional) Add a cron/systemd timer to refresh IPdeny lists and reload
#      sets daily using --setup-geo-data and --fast-load.
#

set -euo pipefail
IFS=$'\n\t'

# Country code for Geo IP data (IPdeny, ISO 3166-1 alpha-2, lowercase)
COUNTRY_CODE="${COUNTRY_CODE:-us}"

VERSION='v1.2.1'
SCRIPT_NAME="$(basename "$0")"
ACTION="${1:-"--help"}"

# Paths and names (Ubuntu 24.04 defaults)
NFT_CONF="/etc/nftables.conf"
GEO_DIR="/etc/nftables.d"
FILE_V4="$GEO_DIR/us-v4.txt"
FILE_V6="$GEO_DIR/us-v6.txt"

FAMILY="inet"
TABLE="filter"
SET_V4="us_v4"
SET_V6="us_v6"

WL_SET_V4="ssh_whitelist_v4"
WL_SET_V6="ssh_whitelist_v6"

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

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "This action requires root privileges. Try: sudo $SCRIPT_NAME $ACTION ..."
  fi
}

require_nft_priv() {
  require_cmd nft
  if ! nft list tables >/dev/null 2>&1; then
    die "Unable to run 'nft list tables'. You likely need root. Try: sudo $SCRIPT_NAME $ACTION ..."
  fi
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    local ts backup
    ts="$(date +'%Y%m%d.%H%M%S')"
    backup="${path}.${ts}.bak"
    cp -a -- "$path" "$backup" || die "Failed to create backup of '$path' at '$backup'"
    log "Backup created: $backup"
  else
    log "No existing '$path' to back up (file not present)"
  fi
}

download_file_atomic() {
  local url="$1"
  local dest="$2"

  require_root
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
  require_root
  mkdir -p "$GEO_DIR" || die "Failed to create directory '$GEO_DIR'"

  download_file_atomic "https://www.ipdeny.com/ipblocks/data/countries/${COUNTRY_CODE}.zone" "$FILE_V4"
  download_file_atomic "https://www.ipdeny.com/ipv6/ipaddresses/blocks/${COUNTRY_CODE}.zone" "$FILE_V6"

  log "Geo data setup complete in '$GEO_DIR' (COUNTRY_CODE=${COUNTRY_CODE})"
}


append_ssh_geo_snippet() {
  require_root
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
#     set ssh_whitelist_v4 {
#         type ipv4_addr
#         flags interval
#     }
#
#     set ssh_whitelist_v6 {
#         type ipv6_addr
#         flags interval
#     }
#
#     chain input {
#         type filter hook input priority filter; policy accept;
#
#         # Whitelist (always allow these SSH clients)
#         #   tcp dport 22 ip  saddr  @ssh_whitelist_v4 accept
#         #   tcp dport 22 ip6 saddr @ssh_whitelist_v6 accept
#
#         # SSH Geo-Limit (apply AFTER whitelist, BEFORE generic SSH ACCEPT)
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
  require_nft_priv

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

  local count_v4 count_v6 lines_v4 lines_v6

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

# ---------- Whitelist helpers (IPv4 + IPv6) ----------

whitelist_set_for_ip() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then
    echo "$WL_SET_V6"
  else
    echo "$WL_SET_V4"
  fi
}

whitelist_check_set_exists_for_ip() {
  local ip="$1"
  local set_name
  set_name="$(whitelist_set_for_ip "$ip")"
  require_nft_priv
  if ! nft list set "$FAMILY" "$TABLE" "$set_name" >/dev/null 2>&1; then
    die "Whitelist set '$FAMILY $TABLE $set_name' not found. Define it in /etc/nftables.conf and apply it first."
  fi
}

whitelist_add_ip() {
  local ip="$1"
  if [[ -z "$ip" ]]; then
    die "No IP provided for whitelist-add."
  fi

  local set_name
  set_name="$(whitelist_set_for_ip "$ip")"

  whitelist_check_set_exists_for_ip "$ip"

  # Idempotent: check if already present
  if nft list set "$FAMILY" "$TABLE" "$set_name" 2>/dev/null | grep -qw "$ip"; then
    log "IP '$ip' already present in whitelist set '$set_name'; nothing to do."
    return 0
  fi

  log "Adding IP '$ip' to whitelist set '$set_name'"
  nft add element "$FAMILY" "$TABLE" "$set_name" "{ $ip }"
  log "IP '$ip' added to whitelist set '$set_name'"
}

whitelist_remove_ip() {
  local ip="$1"
  if [[ -z "$ip" ]]; then
    die "No IP provided for whitelist-remove."
  fi

  local set_name
  set_name="$(whitelist_set_for_ip "$ip")"

  whitelist_check_set_exists_for_ip "$ip"

  if ! nft list set "$FAMILY" "$TABLE" "$set_name" 2>/dev/null | grep -qw "$ip"; then
    log "IP '$ip' is not present in whitelist set '$set_name'; nothing to remove."
    return 0
  fi

  log "Removing IP '$ip' from whitelist set '$set_name'"
  nft delete element "$FAMILY" "$TABLE" "$set_name" "{ $ip }"
  log "IP '$ip' removed from whitelist set '$set_name'"
}

whitelist_add_current() {
  if [[ -z "${SSH_CONNECTION:-}" ]]; then
    die "SSH_CONNECTION is empty; not an SSH session. Run this from an SSH login."
  fi

  local conn client_ip
  conn="$SSH_CONNECTION"
  client_ip="${conn%% *}"

  if [[ -z "$client_ip" ]]; then
    die "Unable to parse client IP from SSH_CONNECTION='$SSH_CONNECTION'"
  fi

  whitelist_add_ip "$client_ip"
}

whitelist_list() {
  require_nft_priv

  echo "=== SSH Whitelist Sets ==="

  if nft list set "$FAMILY" "$TABLE" "$WL_SET_V4" >/dev/null 2>&1; then
    echo
    echo "Set $FAMILY $TABLE $WL_SET_V4 (IPv4):"
    nft list set "$FAMILY" "$TABLE" "$WL_SET_V4"
  else
    echo
    echo "Set $FAMILY $TABLE $WL_SET_V4 (IPv4): NOT FOUND"
  fi

  if nft list set "$FAMILY" "$TABLE" "$WL_SET_V6" >/dev/null 2>&1; then
    echo
    echo "Set $FAMILY $TABLE $WL_SET_V6 (IPv6):"
    nft list set "$FAMILY" "$TABLE" "$WL_SET_V6"
  else
    echo
    echo "Set $FAMILY $TABLE $WL_SET_V6 (IPv6): NOT FOUND"
  fi
}

# ---------- Investigation ----------

investigate() {
  echo "=== SSH Geo-Limit Investigation ==="
  echo "Script version: $VERSION"
  echo

  echo "--- Privileges ---"
  echo "EUID:       $EUID"
  echo "USER:       ${USER:-"(unknown)"}"
  echo "SUDO_USER:  ${SUDO_USER:-"(not set)"}"
  if [[ $EUID -eq 0 ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
      echo "Running as: root (via sudo from user '${SUDO_USER}')"
    else
      echo "Running as: root (direct)"
    fi
  else
    echo "Running as: non-root"
  fi
  echo

  echo "--- Commands ---"
  if command -v nft >/dev/null 2>&1; then
    if nft list tables >/dev/null 2>&1; then
      echo "nft:        present (privileges OK)"
    else
      echo "nft:        present, but 'nft list tables' FAILED (likely insufficient privileges; try sudo)"
    fi
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

      if nft list set "$FAMILY" "$TABLE" "$WL_SET_V4" >/dev/null 2>&1; then
        echo "set $FAMILY $TABLE $WL_SET_V4: present (whitelist IPv4)"
      else
        echo "set $FAMILY $TABLE $WL_SET_V4: NOT FOUND (whitelist IPv4)"
      fi

      if nft list set "$FAMILY" "$TABLE" "$WL_SET_V6" >/dev/null 2>&1; then
        echo "set $FAMILY $TABLE $WL_SET_V6: present (whitelist IPv6)"
      else
        echo "set $FAMILY $TABLE $WL_SET_V6: NOT FOUND (whitelist IPv6)"
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
  local client_ip=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local conn
    conn="$SSH_CONNECTION"
    client_ip="${conn%% *}"
    echo "SSH_CONNECTION: $conn"
    echo "SSH_CLIENT:     ${SSH_CLIENT:-"(not set)"}"
    echo "Client public IP (from SSH_CONNECTION): $client_ip"
  else
    echo "Not an SSH session (SSH_CONNECTION is empty)."
  fi
  echo

  echo "--- SSH Whitelist Status ---"
  if ! command -v nft >/dev/null 2>&1; then
    echo "Cannot inspect whitelist: nft command is missing."
  else
    local wl_v4_present="NO"
    local wl_v6_present="NO"
    if nft list set "$FAMILY" "$TABLE" "$WL_SET_V4" >/dev/null 2>&1; then
      wl_v4_present="YES"
    fi
    if nft list set "$FAMILY" "$TABLE" "$WL_SET_V6" >/dev/null 2>&1; then
      wl_v6_present="YES"
    fi

    echo "Whitelist set $WL_SET_V4 (IPv4): $wl_v4_present"
    echo "Whitelist set $WL_SET_V6 (IPv6): $wl_v6_present"

    if [[ -n "$client_ip" ]]; then
      local wl_set_for_client whitelisted
      wl_set_for_client="$(whitelist_set_for_ip "$client_ip")"
      whitelisted="UNKNOWN"

      if nft list set "$FAMILY" "$TABLE" "$wl_set_for_client" >/dev/null 2>&1; then
        if nft list set "$FAMILY" "$TABLE" "$wl_set_for_client" 2>/dev/null | grep -qw "$client_ip"; then
          whitelisted="YES (in $wl_set_for_client)"
        else
          whitelisted="NO (not in $wl_set_for_client)"
        fi
      else
        whitelisted="N/A (whitelist set $wl_set_for_client not defined)"
      fi

      echo "Current SSH client whitelisted: $whitelisted"
    else
      echo "Current SSH client whitelisted: N/A (no SSH client IP detected)"
    fi
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
        - Privilege context (EUID, USER, SUDO_USER)
        - Presence of nft / curl / install (and whether nft has privileges)
        - Presence of $NFT_CONF
        - table $FAMILY $TABLE and sets $SET_V4 / $SET_V6
        - Geo data files and RSBB SSH snippet marker.
        - SSH client information (SSH_CONNECTION, SSH_CLIENT, client IP).
        - Whitelist sets ($WL_SET_V4 / $WL_SET_V6) and whether the current
          SSH client IP is whitelisted.

  --setup-geo-data
      (Requires root) Create $GEO_DIR (if needed) and download from IPdeny:
        - $FILE_V4 (IPv4 ranges for COUNTRY_CODE, default: us)
        - $FILE_V6 (IPv6 ranges for COUNTRY_CODE, default: us)
      Existing files are backed up with timestamped .bak copies.
      Writes atomically using 'install'.
      IPdeny usage limits: https://www.ipdeny.com/usagelimits.php

  --append-ssh-geo-snippet
      (Requires root) Backup $NFT_CONF and append a COMMENTED example snippet
      (RSBB_SSH_GEO_LIMIT block) describing how to:
        - Define us_v4/us_v6 sets
        - Define ssh_whitelist_v4/ssh_whitelist_v6 sets
        - Add SSH geo-limit rules for port 22
      You must manually integrate these into your inet filter table.

  --fast-load
      (Requires nft privileges) Flush and bulk-load nftables sets:
        - $FAMILY $TABLE $SET_V4 from $FILE_V4
        - $FAMILY $TABLE $SET_V6 from $FILE_V6
      Uses chunked inserts (${CHUNK_SIZE} CIDRs per nft add command) for speed.

  --flush-sets
      (Requires nft privileges) Flush $FAMILY $TABLE $SET_V4 and $SET_V6 only.

  --verify-sets
      (Requires nft privileges) Show approximate line counts in:
        - $FAMILY $TABLE $SET_V4
        - $FAMILY $TABLE $SET_V6
      And compare to the geo files' line counts.

  --whitelist-add-current
      (Requires nft privileges) Add the current SSH client IP (IPv4 or IPv6)
      to the appropriate whitelist set:
        - IPv4 -> $WL_SET_V4
        - IPv6 -> $WL_SET_V6

  --whitelist-add IP
      (Requires nft privileges) Add the given IP (IPv4 or IPv6) to the
      appropriate whitelist set.

  --whitelist-remove IP
      (Requires nft privileges) Remove the given IP (IPv4 or IPv6) from the
      appropriate whitelist set. No error if the IP is not already present.

  --whitelist-list
      (Requires nft privileges) List the contents of:
        - $FAMILY $TABLE $WL_SET_V4 (if present)
        - $FAMILY $TABLE $WL_SET_V6 (if present)

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
  - Ensure whitelist sets $WL_SET_V4/$WL_SET_V6 are defined if you intend
    to use whitelist actions.
  - Geo IP data source: IPdeny (https://www.ipdeny.com).
    Please review their usage limits: https://www.ipdeny.com/usagelimits.php
  - You can override the IPdeny country when setting up geo data via:
    COUNTRY_CODE=<cc> sudo ./$SCRIPT_NAME --setup-geo-data
EOF
}

main() {
  case "$ACTION" in
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
    --whitelist-add-current)
      whitelist_add_current
      ;;
    --whitelist-add)
      shift || die "Missing IP argument for --whitelist-add"
      whitelist_add_ip "$1"
      ;;
    --whitelist-remove)
      shift || die "Missing IP argument for --whitelist-remove"
      whitelist_remove_ip "$1"
      ;;
    --whitelist-list)
      whitelist_list
      ;;
    *)
      die "Unknown action '$ACTION'. Use --help for usage."
      ;;
  esac
}

main "$@"
