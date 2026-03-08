---
title: "Meow — HackTheBox Starting Point Walkthrough"
date: 2026-01-30
draft: false
tags: ["htb-walkthrough", "linux", "privilege-escalation", "easy", "oscp-prep"]
categories: ["writeups"]
series: ["Starting Point"]
description: "HackTheBox Meow walkthrough: exploit an exposed Telnet service with blank root credentials for an instant shell. Perfect intro to CTF methodology."
keywords: ["Meow HTB", "HackTheBox Meow walkthrough", "telnet exploit", "blank root credentials", "default credentials", "nmap reconnaissance", "hackthebox walkthrough", "penetration testing basics", "telnet misconfiguration", "linux privilege escalation", "CTF beginner"]
summary: "Meow is HTB's gentlest introduction to penetration testing — a single open Telnet port, no password on the root account, and an immediate lesson in why legacy services are dangerous."
cover:
  image: "cover.png"
  alt: "Meow — Easy Linux machine walkthrough cover"
  hidden: false
params:
  box:
    os: "Linux"
    difficulty: "1/5"
ShowToc: true
---


# HackTheBox — Meow

Meow is HackTheBox's most welcoming entry point: a single misconfigured service, no password standing between you and a root shell, and a textbook example of why legacy protocols have no place on a modern network. Don't let the simplicity fool you — the lessons here underpin some of the most impactful real-world breaches.

---

## Overview

| Field | Details |
|---|---|
| **IP** | <TARGET> |
| **OS** | Linux |
| **Difficulty** | 1/5 |

---

## Reconnaissance

Every engagement starts the same way: figure out what's listening. I kicked off an Nmap service-version scan against the target to enumerate open ports and identify what software is running on them.

```bash
nmap -sV <TARGET>
```

![terminal output](terminal_01.png)

![nmap scan revealing a single open port — TCP 23 running Linux telnetd](terminal_01.png)

Port 23. Telnet. That's it — one port, one service, one glaring red flag.

Telnet is a protocol from the early days of networked computing. It predates the concept of encrypted communications entirely: everything you send over a Telnet connection — keystrokes, credentials, data — travels in cleartext. It was largely replaced by SSH in the late 1990s for exactly this reason. Seeing it exposed on a machine in 2026 is the network equivalent of leaving your front door open with a neon "WELCOME" sign.

At this point the mental checklist is short:
1. Can I connect at all?
2. Does it accept any default or well-known accounts?
3. Does anything work with a blank password?

---

## Foothold

I connected to the Telnet service directly using the system's built-in `telnet` client. No special tooling needed — this is about as low-tech as exploitation gets.

```bash
telnet <TARGET>
```

The service responded with a login prompt. I tried the most privileged account imaginable — `root` — and when prompted for a password, I simply pressed Enter.

![terminal output](terminal_02.png)

![root shell obtained immediately via Telnet with a blank password on Meow](terminal_02.png)

And that's it. No exploit, no CVE, no lateral movement. The root account had no password set, meaning the system accepted an empty string as valid authentication and dropped me straight into a root shell.

I grabbed the flag from the expected location:

```bash
cat /root/flag.txt
```

![terminal output](terminal_03.png)

![root flag retrieved from /root/flag.txt](terminal_03.png)

---

## Privilege Escalation

There's nothing to escalate — I landed as `root` on the first connection attempt. This is less a privilege escalation story and more a story about what happens when a service is deployed with zero hardening.

---

## Lessons Learned

Simple boxes teach the most durable lessons. Here's what Meow reinforces:

**1. Always check for blank and default credentials before anything else.**
Before reaching for an exploit framework, try the obvious things. A surprising number of real-world compromises — including high-profile industrial control system and IoT incidents — trace back to factory-default or empty credentials that were never changed after deployment. It costs thirty seconds to check; skipping it can cost you the whole assessment.

**2. Telnet should not exist on any production network.**
Telnet transmits everything — including passwords — in plaintext. Any attacker with a position on the same network segment (or an ISP-level vantage point) can read your credentials with a passive packet capture. If you encounter Telnet on a real engagement, it's an automatic critical finding. SSH exists for a reason; use it.

**3. Running internet-facing services as root compounds every other mistake.**
Even if there had been a password on this account, running the login service as `root` means a successful authentication immediately grants full system control. Services should run as the least-privileged user that can accomplish their task. A compromise of a low-privilege account is a problem; a compromise of root is a disaster.

**4. Defense in depth matters even for "internal" services.**
Telnet is often found on internal networks with the assumption that the perimeter firewall makes it safe. The moment an attacker gets inside — through phishing, a VPN credential, a misconfigured cloud security group — every unprotected internal service becomes a direct path to full compromise.

Meow is a beginner box by design, but the misconfiguration it demonstrates is not theoretical. It shows up in embedded devices, legacy industrial systems, and network appliances on real corporate networks every day.
