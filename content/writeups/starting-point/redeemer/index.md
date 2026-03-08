---
title: "Redeemer — HackTheBox Starting Point Walkthrough"
date: 2026-01-30
draft: false
tags: ["htb-walkthrough", "linux", "privilege-escalation"]
categories: ["writeups"]
series: ["Starting Point"]
description: "HackTheBox Redeemer walkthrough: exploiting unauthenticated Redis access to retrieve flags. A beginner-friendly intro to Redis enumeration and misconfiguration."
keywords: ["Redeemer", "HackTheBox", "redis exploitation", "unauthenticated redis", "redis-cli", "nmap full port scan", "hackthebox walkthrough", "penetration testing", "redis misconfiguration", "CTF writeup"]
summary: "Redeemer proves that sometimes the simplest misconfigurations are the most dangerous — an open Redis instance with no password stands between you and the flag."
cover:
  image: "cover.png"
  alt: "Redeemer — HackTheBox Linux machine walkthrough cover"
  hidden: false
params:
  box:
    os: "Linux"
    difficulty: ""
ShowToc: true
---


# HackTheBox — Redeemer

Redeemer is a beginner-friendly Linux box that demonstrates one of the most common and dangerous misconfigurations in modern infrastructure: a Redis instance exposed to the network with no authentication. Getting the flag requires nothing more than knowing where to look and how to talk to the service.

---

## Overview

Redis is an in-memory key-value store that's ubiquitous in web stacks — used for caching, session management, queues, and more. By default, Redis ships with no password requirement and listens on all interfaces, which is catastrophic when it's reachable from untrusted networks. This box is a clean illustration of why full port scans matter and why "default secure" is a phrase that doesn't apply to Redis.

---

## Reconnaissance

### Full Port Scan

The first thing I always do on any HTB box is a full port scan. Nmap's default behavior only checks the top 1000 ports, and Redis listens on 6379 — a port that doesn't make that list. If I had stopped at a default scan, I'd have seen nothing.

```bash
nmap -p- --min-rate 5000 $TARGET
```

The `--min-rate 5000` flag tells Nmap to send at least 5000 packets per second, which makes scanning all 65,535 ports practical rather than a multi-hour wait. Once the full scan surfaced port 6379, I ran a targeted service scan:

```bash
nmap -p 6379 -sC -sV $TARGET
```

![terminal output](terminal_01.png)

One open port: Redis 5.0.7. The version is slightly dated, but more importantly — no authentication banner, no TLS, just a wide-open key-value store.

---

## Foothold

### Connecting to Redis Unauthenticated

Redis exposes a straightforward text-based protocol, and `redis-cli` is the standard client for interacting with it. Since there's no password configured, connecting is as simple as pointing the tool at the target host:

```bash
redis-cli -h $TARGET
```

Once connected, I ran `INFO` to confirm we had a working connection and to pull basic server metadata — things like the Redis version, OS, memory usage, and importantly, whether `requirepass` is set. It wasn't.

With a foothold on the service, the next step is figuring out what data is actually stored. The `KEYS *` command dumps every key in the current database — something you'd never run in production against a large dataset, but perfectly reasonable in a CTF context:

![terminal output](terminal_02.png)

Four keys. One of them is named `flag`, which isn't subtle. Retrieving a value from Redis is a single command:

```bash
GET flag
```

![terminal output](terminal_03.png)

That's it. No exploit, no shellcode, no lateral movement — just unauthenticated access to a misconfigured service handing over its data.

---

## Privilege Escalation

There's no privilege escalation path here. The flag was stored as a plain Redis key, accessible to anyone who could reach the port. The "vulnerability" is entirely at the access control layer — or rather, the complete absence of one.

---

## Lessons Learned

**Scan all 65,535 ports.** This is the most important takeaway from this box. If you run a default Nmap scan and call it done, you'll miss services like Redis (6379), MongoDB (27017), and plenty of others that live outside the top-1000 list. The `-p-` flag combined with `--min-rate 5000` is my standard first pass on HTB machines — fast enough to be practical, thorough enough to not miss anything.

**Redis has no authentication by default.** This is a well-documented issue that keeps showing up in real-world breach reports. Redis was designed to run inside a trusted network perimeter, not exposed to the internet or untrusted segments. The fix is straightforward: set `requirepass` in `redis.conf` and bind the service to localhost or a specific interface rather than `0.0.0.0`. In 2024, there's no excuse for an internet-facing Redis instance without authentication.

**`KEYS *` and `GET` are all you need to pillage a misconfigured instance.** In a real engagement, you'd also want to look at `CONFIG GET *` (which can reveal sensitive configuration details), `CONFIG SET dir` and `CONFIG SET dbfilename` (which can be abused to write files to disk, potentially achieving RCE), and `SLAVEOF` (which can be used in replication-based exploitation chains). Redeemer keeps it simple, but the rabbit hole goes much deeper.

**Simple misconfigurations are often the most dangerous.** Redeemer isn't a box about obscure CVEs or complex exploit chains — it's about a default setting that's been wrong since Redis was first released. In real penetration tests, these are frequently the findings that have the highest impact: not because they're clever, but because they're overlooked.
