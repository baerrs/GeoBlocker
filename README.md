# GeoBlocker

GeoBlocker is a Bash helper script for **Ubuntu 24.04** servers that want to:
- Restrict **SSH (port 22)** to **Contry spicific-only** IP ranges using nftables. US by default
- Keep US IPv4/IPv6 ranges updated from **IPdeny**.
- Quickly bulk-load those ranges into nftables sets.
- Optionally maintain **SSH whitelists** (IPv4 + IPv6) for trusted addresses.
- Inspect your current setup with a safe **investigation** mode.

> ⚠️ GeoBlocker does **not** automatically modify your live nftables ruleset or apply configs.
> You stay in control of `/etc/nftables.conf` and when `nft -f` is run.

---

## Features

- ✅ Downloads Contry spicific -only IPv4 and IPv6 ranges from **IPdeny**
- ✅ Stores them in `/etc/nftables.d/us-v4.txt` and `/etc/nftables.d/us-v6.txt` <-- file names will be for US, but are for any country.  I will change this later
- ✅ Bulk-loads them into nftables sets:
  - `inet filter us_v4`
  - `inet filter us_v6`
- ✅ Optional SSH whitelist sets:
  - `ssh_whitelist_v4` (IPv4)
  - `ssh_whitelist_v6` (IPv6)
- ✅ `--investigate` mode shows:
  - Privilege context (root/sudo/non-root)
  - nftables status and required sets
  - Geo data presence
  - SSH client IP and whitelist status
- ✅ Safer operations:
  - Timestamped backups for changed files
  - Atomic writes using `install`
  - No automatic rule application

---

## Requirements

- Ubuntu Server **24.04** (or similar)
- `nft` (nftables) installed
- Root or sudo privileges for most actions
- Network access to:
  - `https://www.ipdeny.com`

Install nftables if needed:

```bash
sudo apt update
sudo apt install nftables -y
sudo systemctl enable --now nftables
```

---

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/baerrs/GeoBlocker.git
cd GeoBlocker
chmod +x GeoBlocker.sh
```

> Note: The repo may already mark `GeoBlocker.sh` as executable; `chmod` is just a safety step.

---

## Example nftables Configuration

Below is a **minimal example** of how your `/etc/nftables.conf` might define the needed sets and SSH rules.

```nft
#!/usr/sbin/nft -f

table inet filter {
    set us_v4 {
        type ipv4_addr
        flags interval
    }

    set us_v6 {
        type ipv6_addr
        flags interval
    }

    set ssh_whitelist_v4 {
        type ipv4_addr
        flags interval
    }

    set ssh_whitelist_v6 {
        type ipv6_addr
        flags interval
    }

    chain input {
        type filter hook input priority filter; policy accept;

        # Always allow SSH from whitelisted IPs
        tcp dport 22 ip  saddr  @ssh_whitelist_v4 accept
        tcp dport 22 ip6 saddr @ssh_whitelist_v6 accept

        # Geo-limit: only US IPs may reach SSH
        tcp dport 22 ip  saddr != @us_v4 drop
        tcp dport 22 ip6 saddr != @us_v6 drop

        # ...your remaining rules (e.g., generic SSH accept) ...
    }
}
```

After editing your config, always validate and apply:

```bash
sudo nft -c -f /etc/nftables.conf   # validate
sudo nft -f /etc/nftables.conf      # apply
```

---

## Typical Workflow

1. **Prepare nftables config**  
   Make sure `/etc/nftables.conf` defines:
   - `table inet filter`
   - `us_v4` / `us_v6` sets
   - (Optional) `ssh_whitelist_v4` / `ssh_whitelist_v6` sets
   - SSH rules that reference those sets

2. **Apply the config**

   ```bash
   sudo nft -c -f /etc/nftables.conf
   sudo nft -f /etc/nftables.conf
   ```

3. **Download US geo data**

   ```bash
   sudo ./GeoBlocker.sh --setup-geo-data
   ```

4. **Fast-load the nftables sets**

   ```bash
   sudo ./GeoBlocker.sh --fast-load
   ```

5. **Optionally whitelist your current IP**

   ```bash
   sudo ./GeoBlocker.sh --whitelist-add-current
   ```

6. **Check everything**

   ```bash
   sudo ./GeoBlocker.sh --investigate
   ```

---

## Usage

```bash
sudo ./GeoBlocker.sh [ACTION]
```

---

## Actions

### `--investigate`
Shows detailed system and configuration status:

- Privilege context (`EUID`, `USER`, `SUDO_USER`)
- Presence of required commands (`nft`, `curl`, `install`)
- Whether `nft` has sufficient privileges
- Presence of `/etc/nftables.conf`
- Existence of `table inet filter` and sets `us_v4` / `us_v6`
- Geo data file availability
- Presence of the `RSBB_SSH_GEO_LIMIT` snippet
- SSH client information:
  - `SSH_CONNECTION`
  - `SSH_CLIENT`
  - Client public IP extracted from the session
- Whitelist sets:
  - `ssh_whitelist_v4`
  - `ssh_whitelist_v6`
- Whether the current SSH client IP is whitelisted

---

### `--setup-geo-data`
(Requires **root**)  

Creates `/etc/nftables.d` if missing and downloads US IP ranges from IPdeny:

- `/etc/nftables.d/us-v4.txt` (IPv4 US ranges)
- `/etc/nftables.d/us-v6.txt` (IPv6 US ranges)

Additional notes:

- Existing files are backed up with timestamped `.bak` copies.
- Writes use atomic operations via `install`.
- IPdeny usage limits: <https://www.ipdeny.com/usagelimits.php>

---

### `--append-ssh-geo-snippet`
(Requires **root**)  

Backs up `/etc/nftables.conf` and appends a **commented example snippet** showing how to:

- Define `us_v4` and `us_v6`
- Define `ssh_whitelist_v4` and `ssh_whitelist_v6`
- Add SSH geo-limit rules for port 22

👉 You must manually integrate these into your `inet filter` table.

---

### `--fast-load`
(Requires **nft privileges**)  

Flushes and bulk-loads nftables sets:

- `inet filter us_v4` ← `/etc/nftables.d/us-v4.txt`
- `inet filter us_v6` ← `/etc/nftables.d/us-v6.txt`

Uses chunked loads (512 CIDRs per batch) for speed.

---

### `--flush-sets`
(Requires **nft privileges**)  

Flushes only:

- `inet filter us_v4`
- `inet filter us_v6`

---

### `--verify-sets`
(Requires **nft privileges**)  

Shows approximate line counts in:

- `inet filter us_v4`
- `inet filter us_v6`

And compares them to the geo file line counts.

---

### `--whitelist-add-current`
(Requires **nft privileges**)  

Adds the SSH client’s current IP to the appropriate whitelist:

- IPv4 → `ssh_whitelist_v4`
- IPv6 → `ssh_whitelist_v6`

---

### `--whitelist-add <IP>`
(Requires **nft privileges**)  

Adds a specific IP (IPv4 or IPv6) to the correct whitelist set.

---

### `--whitelist-remove <IP>`
(Requires **nft privileges**)  

Removes the IP from the whitelist set.  
No error is thrown if the IP is already absent.

---

### `--whitelist-list`
(Requires **nft privileges**)  

Lists the contents of:

- `inet filter ssh_whitelist_v4` (if present)
- `inet filter ssh_whitelist_v6` (if present)

---

### `--help`, `-h`
Shows the help text.

---

## Default Behavior

If no action is specified, the script displays `--help`.

---

## Notes & Safety

- The script **does not automatically apply nftables configs**.
- After editing `/etc/nftables.conf`, always validate and apply manually:

  ```bash
  sudo nft -c -f /etc/nftables.conf   # validate
  sudo nft -f /etc/nftables.conf      # apply
  ```

- Ensure `table inet filter` and sets `us_v4` / `us_v6` are defined before using `--fast-load`.
- Define whitelist sets (`ssh_whitelist_v4`, `ssh_whitelist_v6`) if you plan to use whitelist actions.
- Geo IP data source: **IPdeny**
  - <https://www.ipdeny.com>
  - Usage limits: <https://www.ipdeny.com/usagelimits.php>

---

## License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.
