# GeoBlocker

GeoBlocker is a Bash helper script for **Ubuntu 24.04** servers that want to:

- Restrict **SSH (port 22)** to **Country-Specific** IP ranges using nftables (US by default)
- **Run safely alongside UFW:** Uses a separate table with **Priority -150** to filter traffic *before* it hits UFW
- Keep IPv4/IPv6 ranges updated from **IPdeny**
- Bulk-load those ranges into nftables sets
- Optionally maintain **SSH whitelists** (IPv4 + IPv6) for trusted addresses
- Inspect your current setup with a safe **investigation** mode

> ⚠️ GeoBlocker does **not** automatically modify your live nftables ruleset or apply configs.  
> You stay in control of `/etc/nftables.conf` and when `nft -f` is run.

---

## Features

- ✅ **UFW Compatible:** Runs as a "Pre-Filter" (Priority -150). Drops bad traffic immediately; hands valid traffic (`return`) to UFW.
- ✅ Downloads Country-Specific IPv4/IPv6 ranges from **IPdeny** (Default: US)
- ✅ Stores them in:
  - `/etc/nftables.d/us-v4.txt`
  - `/etc/nftables.d/us-v6.txt`
- ✅ Bulk-loads them into nftables sets:
  - `inet geoblocker us_v4`
  - `inet geoblocker us_v6`
- ✅ Optional SSH whitelist sets:
  - `ssh_whitelist_v4`
  - `ssh_whitelist_v6`
- ✅ `--investigate` mode shows:
  - User/privilege context
  - nftables status
  - Required sets
  - Geo data presence
  - SSH client IP + whitelist status
- ✅ Safety:
  - Timestamped backups of changed files
  - Atomic writes via `install`
  - No automatic config application

---

## Requirements

- Ubuntu **24.04**
- `nft` (nftables)
- Root or sudo
- Network access to:  
  `https://www.ipdeny.com`

### Install nftables

```bash
sudo apt update
sudo apt install nftables -y
sudo systemctl enable --now nftables
```

---

# Installation

Clone the repo and make the script executable:

```bash
git clone https://github.com/baerrs/GeoBlocker.git
cd GeoBlocker
chmod +x GeoBlocker.sh
```

*(Note: The repo may already mark the file executable.)*

---

# Example nftables Configuration

Add this to **/etc/nftables.conf**.

> **Critical:** Priority **-150** ensures this runs before UFW (priority 0).  
> **auto-merge** is required for overlapping IPdeny ranges.

```nft
#!/usr/sbin/nft -f

table inet geoblocker {
    # Sets
    set us_v4 { type ipv4_addr; flags interval; auto-merge; }
    set us_v6 { type ipv6_addr; flags interval; auto-merge; }
    set ssh_whitelist_v4 { type ipv4_addr; flags interval; }
    set ssh_whitelist_v6 { type ipv6_addr; flags interval; }

    chain input_chain {
        type filter hook input priority -150; policy accept;

        # Local bypass
        iif "lo" accept
        ip saddr 10.0.0.0/8 return
        ip saddr 172.16.0.0/12 return
        ip saddr 192.168.0.0/16 return

        # Whitelist
        ip saddr @ssh_whitelist_v4 return
        ip6 saddr @ssh_whitelist_v6 return

        # Existing connections
        ct state established,related accept

        # US traffic
        ip saddr @us_v4 return
        ip6 saddr @us_v6 return

        # Block all others
        drop
    }
}
```

Apply:

```bash
sudo nft -c -f /etc/nftables.conf   # validate
sudo nft -f /etc/nftables.conf      # apply
```

---

# Typical Workflow

### 1. Prepare nftables config  
Make sure `/etc/nftables.conf` defines:

- `table inet geoblocker`
- `us_v4` / `us_v6` sets (with auto-merge)
- `ssh_whitelist_v4` / `ssh_whitelist_v6` (optional)
- Pre-filter chain (priority -150)

### 2. Apply config

```bash
sudo nft -c -f /etc/nftables.conf
sudo nft -f /etc/nftables.conf
```
*Note: If an existing IP is whitelisted, running these commands will remove them unless they are hard coded into nftables.conf*

### 3. Whitelist your current SSH IP

```bash
sudo -E ./GeoBlocker.sh --whitelist-add-current
```

### 4. Download US geo data

```bash
sudo ./GeoBlocker.sh --setup-geo-data
```
### 5. Investigate

```bash
sudo ./GeoBlocker.sh --investigate
```

### 6. Fast-load nftables sets

```bash
sudo ./GeoBlocker.sh --fast-load
```

---

# Automation (Systemd Timer)

Create service:  
`/etc/systemd/system/geoblocker-update.service`

```ini
[Unit]
Description=Update GeoBlocker IP Lists and Reload Firewall
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/GeoBlocker.sh --setup-geo-data
ExecStart=/usr/local/sbin/GeoBlocker.sh --fast-load
```

Create timer:  
`/etc/systemd/system/geoblocker-update.timer`

```ini
[Unit]
Description=Run GeoBlocker Update Daily at 4am

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now geoblocker-update.timer
```

---

# Usage

```bash
sudo ./GeoBlocker.sh [ACTION]
```

---

# Actions

### `--investigate`
Checks system + config state.

### `--setup-geo-data`
Downloads US (or COUNTRY_CODE override) IPdeny lists with backup + atomic write.

### `--append-ssh-geo-snippet`
Appends commented nftables example snippet.

### `--fast-load`
Bulk-loads large CIDR sets efficiently.

### `--flush-sets`
Flushes `us_v4` and `us_v6`.

### `--verify-sets`
Compares set counts to file counts.

### `--whitelist-add-current`
Adds current SSH client IP.

### `--whitelist-add <IP>`  
Add IP.

### `--whitelist-remove <IP>`  
Remove IP.

### `--whitelist-list`  
Show whitelist contents.

### `--help`  
Show help.

---

# Notes & Safety

- GeoBlocker never applies nftables configs automatically.
- Use `auto-merge` for IPdeny ranges.
- Validate nftables config manually:

```bash
sudo nft -c -f /etc/nftables.conf
sudo nft -f /etc/nftables.conf
```

Geo IP source:  
https://www.ipdeny.com  
Usage limits: https://www.ipdeny.com/usagelimits.php

---

# License

MIT — see the LICENSE file.

---

# Fix Gemini AI “Could Not Download” Error  
https://www.youtube.com/watch?v=5X0qZA4Tk5g
