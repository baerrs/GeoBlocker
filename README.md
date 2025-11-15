# GeoBlocker

GeoBlocker.sh (version v1.2.1) — SSH US-only Geo-Limit helper for nftables (Ubuntu 24.04)

USAGE:
  sudo ./GeoBlocker.sh [ACTION]

ACTIONS:
  --investigate
      Show:
        - Privilege context (EUID, USER, SUDO_USER)
        - Presence of nft / curl / install (and whether nft has privileges)
        - Presence of /etc/nftables.conf
        - table inet filter and sets us_v4 / us_v6
        - Geo data files and RSBB SSH snippet marker.
        - SSH client information (SSH_CONNECTION, SSH_CLIENT, client IP).
        - Whitelist sets (ssh_whitelist_v4 / ssh_whitelist_v6) and whether the current
          SSH client IP is whitelisted.

  --setup-geo-data
      (Requires root) Create /etc/nftables.d (if needed) and download from IPdeny:
        - /etc/nftables.d/us-v4.txt (IPv4 US ranges)
        - /etc/nftables.d/us-v6.txt (IPv6 US ranges)
      Existing files are backed up with timestamped .bak copies.
      Writes atomically using 'install'.
      IPdeny usage limits: https://www.ipdeny.com/usagelimits.php

  --append-ssh-geo-snippet
      (Requires root) Backup /etc/nftables.conf and append a COMMENTED example snippet
      (RSBB_SSH_GEO_LIMIT block) describing how to:
        - Define us_v4/us_v6 sets
        - Define ssh_whitelist_v4/ssh_whitelist_v6 sets
        - Add SSH geo-limit rules for port 22
      You must manually integrate these into your inet filter table.

  --fast-load
      (Requires nft privileges) Flush and bulk-load nftables sets:
        - inet filter us_v4 from /etc/nftables.d/us-v4.txt
        - inet filter us_v6 from /etc/nftables.d/us-v6.txt
      Uses chunked inserts (512 CIDRs per nft add command) for speed.

  --flush-sets
      (Requires nft privileges) Flush inet filter us_v4 and us_v6 only.

  --verify-sets
      (Requires nft privileges) Show approximate line counts in:
        - inet filter us_v4
        - inet filter us_v6
      And compare to the geo files' line counts.

  --whitelist-add-current
      (Requires nft privileges) Add the current SSH client IP (IPv4 or IPv6)
      to the appropriate whitelist set:
        - IPv4 -> ssh_whitelist_v4
        - IPv6 -> ssh_whitelist_v6

  --whitelist-add IP
      (Requires nft privileges) Add the given IP (IPv4 or IPv6) to the
      appropriate whitelist set.

  --whitelist-remove IP
      (Requires nft privileges) Remove the given IP (IPv4 or IPv6) from the
      appropriate whitelist set. No error if the IP is not already present.

  --whitelist-list
      (Requires nft privileges) List the contents of:
        - inet filter ssh_whitelist_v4 (if present)
        - inet filter ssh_whitelist_v6 (if present)

  --help, -h
      Show this help.

DEFAULT:
  If no ACTION is specified, --help is shown.

NOTES:
  - This script does NOT automatically apply nftables configs.
  - After editing /etc/nftables.conf, you typically run:
        sudo nft -c -f /etc/nftables.conf   # validate
        sudo nft -f /etc/nftables.conf      # apply
  - Ensure table inet filter and sets us_v4/us_v6 are defined
    in your nftables config and applied before using --fast-load.
  - Ensure whitelist sets ssh_whitelist_v4/ssh_whitelist_v6 are defined if you intend
    to use whitelist actions.
  - Geo IP data source: IPdeny (https://www.ipdeny.com).
    Please review their usage limits: https://www.ipdeny.com/usagelimits.php

