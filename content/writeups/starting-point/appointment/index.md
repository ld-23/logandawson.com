---
title: "Appointment — HackTheBox Starting Point Walkthrough"
date: 2026-02-01
draft: false
tags: ["htb-walkthrough", "linux", "web", "mysql", "sql-injection", "very easy"]
categories: ["writeups"]
series: ["Starting Point"]
description: "HackTheBox Appointment walkthrough: exploit a PHP login form with SQL injection authentication bypass on this Very Easy Linux box. Perfect intro to SQLi."
keywords: ["Appointment HackTheBox", "SQL injection authentication bypass", "hackthebox walkthrough", "SQLi login bypass", "admin comment bypass", "PHP login form exploitation", "very easy HTB box", "nmap", "Apache httpd", "penetration testing beginner"]
summary: "Appointment is a deceptively simple box that teaches one of the most fundamental web vulnerabilities: SQL injection authentication bypass. One payload, one flag — but the lesson lasts a career."
cover:
  image: "cover.png"
  alt: "Appointment — Very Easy Linux machine walkthrough cover"
  hidden: false
params:
  box:
    os: "Linux (Debian)"
    difficulty: "Very Easy"
ShowToc: true
---


# HackTheBox — Appointment

Sometimes the most valuable lessons come in the smallest packages. Appointment is a single-service Linux box running a PHP login form vulnerable to SQL injection — and it teaches the classic authentication bypass technique that has been breaking web applications for decades.

---

## Overview

Appointment strips everything away: one open port, one login form, one vulnerability. The goal is to exploit a SQL injection flaw in the authentication logic to bypass the password check entirely and log in as `admin` without knowing the real credentials. It's an ideal introductory box precisely because there are no distractions — just you, a login prompt, and the question of how that query is constructed on the backend.

---

## Reconnaissance

### Port Scanning

I always start with an Nmap service scan. Even on a "very easy" box, confirming the attack surface before you start poking at things is good hygiene.

![terminal output](terminal_01.png)

![nmap scan showing only port 80 open running Apache 2.4.38 on Debian with a Login page title](terminal_01.png)

The result is about as minimal as it gets: port 80 only, Apache 2.4.38 on Debian, and the page title is literally "Login". No SSH, no FTP, no extra services to pivot through. The entire attack surface is this one web page.

### Web Enumeration

Visiting `http://<TARGET>/` presents a straightforward username/password form. A quick check confirms this is a PHP application:

```bash
curl -I http://<TARGET>/index.php
```

The server returns a `200 OK`, confirming `index.php` exists and the backend is PHP. The form POSTs the `username` and `password` fields back to itself.

At this point, I made a deliberate choice *not* to launch a directory brute-force or run gobuster. The attack surface is a single login form, and the most likely vulnerability on a PHP login page is SQL injection. Spraying tools at a box before testing the obvious is a habit worth breaking early.

---

## Foothold

### Understanding the Vulnerability

Before throwing payloads at the form, it helps to think about what the backend query probably looks like. A typical PHP authentication query follows this pattern:

```sql
SELECT * FROM users WHERE username='[input]' AND password='[input]';
```

If the application drops user input directly into this query without sanitization or parameterized queries, we control part of the SQL syntax itself — not just the values. That's the essence of SQL injection.

### Crafting the Bypass Payload

The classic authentication bypass payload is:

```
admin'-- -
```

Let's walk through exactly what this does. When the application interpolates our input into the query, it becomes:

```sql
SELECT * FROM users WHERE username='admin'-- -' AND password='anything';
```

Two things happen here:

1. The single quote `'` after `admin` **closes the string literal** that the application opened around our username input.
2. The `-- -` sequence is a **SQL comment** in MySQL/MariaDB. Everything after it — including the `AND password='...'` check — is ignored by the database engine.

The database only evaluates `WHERE username='admin'`, which returns a valid row (assuming the `admin` account exists), and authentication succeeds without ever validating the password.

The trailing space or extra dash in `-- -` is intentional. Some MySQL configurations require whitespace after the double-dash comment marker, and the extra dash ensures the comment is parsed correctly regardless of the server configuration. It's a small detail that saves you from head-scratching when `--` alone doesn't work.

### Executing the Attack

I submitted the payload through the login form with the username field set to `admin'-- -` and the password field set to anything — I used `password` since the value is irrelevant.

![terminal output](terminal_02.png)

![HTTP POST request showing SQL injection payload in username field](terminal_02.png)

The server responded with a successful login and presented the flag.

The flag is: `[redacted]`

---

## Why This Works (and Why It Still Happens)

It's worth pausing on why SQL injection authentication bypass is still a relevant technique in the real world, not just CTF boxes.

The root cause is **string concatenation instead of parameterization**. A vulnerable PHP snippet looks something like this:

```php
$query = "SELECT * FROM users WHERE username='" . $_POST['username'] . "' AND password='" . $_POST['password'] . "'";
$result = mysqli_query($conn, $query);
```

The fix is straightforward — use prepared statements with bound parameters:

```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $_POST['username'], $_POST['password']);
$stmt->execute();
```

With parameterized queries, user input is never interpreted as SQL syntax. The single quote in `admin'-- -` is treated as a literal character, not as a string delimiter. The vulnerability disappears.

Despite this being well-understood for decades, SQL injection still appears in real applications — particularly in legacy codebases, custom-built admin panels, and anywhere that shortcuts were taken under deadline pressure. That's why it remains a first-check item on any login form assessment.

---

## Dead Ends and What I Skipped

I briefly considered trying `' OR '1'='1` style payloads first, but `admin'-- -` is actually preferable when you have a known username. The `OR 1=1` variant returns every row in the users table, and some application logic only authenticates if *exactly one* row is returned — meaning the OR variant might fail even on a vulnerable application. Targeting a specific username is cleaner and more reliable.

I also skipped running a SQL injection scanner like `sqlmap`. On a box this focused, it's more valuable to understand the manual payload than to let a tool handle it. `sqlmap` is a powerful tool, but reaching for it before understanding what it's doing is a trap that leaves gaps in your methodology.

---

## Lessons Learned

**Test login forms for SQL injection before anything else.** An authentication bypass check takes thirty seconds and the payoff is complete access. It should be muscle memory.

**The `-- -` comment syntax is your friend.** The trailing dash-space pattern (`-- -`) is more reliable than `--` alone across MySQL and MariaDB configurations. Keep it in your toolkit.

**Match the payload to the scenario.** `admin'-- -` targets a known username and bypasses only the password check. `' OR '1'='1` is a "return everything" approach that may behave differently depending on the application's authentication logic. Understanding why you're using a payload makes you a better attacker than just knowing that it works.

**Resist the urge to over-enumerate.** When the attack surface is a single login form, the most valuable next step is testing that form — not running gobuster for twenty minutes. Calibrating your tool usage to what's actually in scope is a skill that matters in real engagements.
