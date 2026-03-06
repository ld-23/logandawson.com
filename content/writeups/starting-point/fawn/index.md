---
title: "fawn"
date: 2026-01-30
draft: false
tags: [""]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Unix"
    difficulty: ""
ShowToc: true
---

# Fawn

Fawn is one of HackTheBox's introductory "Starting Point" machines, designed to teach the basics of FTP enumeration and the dangers of misconfigured anonymous access. It's a single-step box — but the lesson it demonstrates shows up in real-world penetration tests far more often than you'd expect.

## Reconnaissance

I kicked things off with a standard Nmap service scan against the target. The `-sC` flag runs Nmap's default scripts (which includes FTP anonymous login detection), and `-sV` pulls version banners. I'm saving all output formats with `-oA` for later reference.

```bash
nmap -sC -sV -oA nmap/fawn $TARGET
```

![terminal output](terminal_01.png)

One open port, one critical finding. Nmap's `ftp-anon` script has already done the heavy lifting — it not only confirmed anonymous login is permitted, but also listed the directory contents and spotted `flag.txt` sitting in the FTP root. This is about as loud as a misconfiguration gets.

The service is **vsftpd 3.0.3** on a Unix host. vsftpd is a common, lightweight FTP daemon, and while it's generally considered secure when properly configured, the operative phrase is *when properly configured*.

## Foothold

With anonymous FTP confirmed, there's no exploitation needed here — just a login. Anonymous FTP access is granted with the username `anonymous` and typically either a blank password or an arbitrary email address. I connected with the system's built-in `ftp` client:

```bash
ftp $TARGET
```

![terminal output](terminal_02.png)

Once inside, `flag.txt` was already visible from the Nmap scan, so I pulled it down directly:

```bash
ftp> get flag.txt
```

![terminal output](terminal_03.png)

That's it. The flag was sitting in plaintext in the FTP root, world-readable, requiring zero authentication to retrieve.

## Privilege Escalation

Not applicable — this box is a single-step compromise. Anonymous FTP handed us the target file directly, with no need to escalate privileges or pivot further.

## Lessons Learned

**Anonymous FTP is almost never appropriate in production.** FTP was designed in an era when networks were trusted and encryption was an afterthought. Anonymous access compounds that by removing the only remaining control — authentication. If you see port 21 open during a pentest, anonymous login should be one of the first things you check.

**vsftpd ships with `anonymous_enable=YES` as a default in some configurations.** It's easy to stand up an FTP server and not realize the anonymous access is on. The fix is explicit: in `/etc/vsftpd.conf`, set `anonymous_enable=NO` and restart the service. Don't assume defaults are secure — audit them.

**Nmap's default scripts are powerful for quick wins.** Running `-sC` alongside `-sV` added essentially no time cost here but immediately surfaced the anonymous login and directory listing without a separate manual step. Making this a habit during initial recon pays dividends.

**Sensitive files should never live in FTP roots, even on authenticated servers.** Defense in depth means that even if anonymous access were somehow required, `flag.txt` — or in a real scenario, configuration files, credentials, backups — should never be accessible to unauthenticated users. Least privilege applies to file placement too.
