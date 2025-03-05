## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.3.18
# HOSTNAME //Found Post Initial Enumeration
WIN-LU09299160F
# OPERATING SYSTEM //Found Post Initial Enumeration
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
# CREDENTIALS   //Found Post Initial Enumeration
sg:UmbracoIsTheBest!
administrator:ChangeMeBaby1MoreTime
```
## OPEN PORTS DETAILS
```bash
80/tcp   open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
```
# ENUMERATION
## PORT 80
```bash
# Recon
sudo whatweb -v $url                                                                      
WhatWeb report for http://10.10.3.18                                                          
Status    : 200 OK
Title     : Anthem.com - Welcome to our blog
IP        : 10.10.3.18
Country   : RESERVED, ZZ                                                                      
Summary   : 
Bootstrap, HTML5, 
JQuery[1.11.0],
Open-Graph-Protocol, 
OpenSearch[http://10.10.3.18/opensearch/1073],
Script[text/javascript], 
X-UA-Compatible[IE=edge]

# Checking robots.txt
UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/

- Possible Credentials
UmbracoIsTheBest!

- Umbraco Login Page
http://10.10.3.18/umbraco/
	- Reuqires Email Id as username and Password to login

- From web page contents seems like the poem is related to "solomon grundy"
- Since the Author Name of Jane Doe is relates with email id JD@anthem.com
- Try guesing the another author name as "solomon grundy" to sg@anthem.com

# Worked Credential and Username
sg@anthem.com and UmbracoIsTheBest!
```
## INITIAL FOOTHOLD
```bash
# Credentials
sg:UmbracoIsTheBest!

sudo xfreerdp /u:administrator /v:$ip +clipboard
- RDP Worked as user sg !!! 
```
## PRIVILEGE ESCALATION
```bash
- Checking Files and Directories on C:\ 
- Changing the Options via GUI to Show Hidden Files
- Able to find a folder Name backup on C:\backup
- backup folder contains a text file named restore.txt bu cna be viewed with administrator Permissions
- restore.txt > right click > Properties > Security Tab > Edit > Add user SG > with Read and Execute Permission
- Able to view the contents of the file 
- ChangeMeBaby1MoreTime

# Possible Credentials
ChangeMeBaby1MoreTime

# Start > powershell (As Administrator ) > Use the Credentials
PS C:\Windows\system32> whoami
win-lu09299160f\administrator
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Mar  5 13:54:07 2025 as: /usr/lib/nmap/nmap -p 80,3389 -sC -sV -Pn -vv -oN nmap/scan-script-version 10.10.3.18
Nmap scan report for 10.10.3.18
Host is up, received user-set (0.35s latency).
Scanned at 2025-03-05 13:54:09 IST for 101s

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-03-05T08:25:49+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-05T08:24:29+00:00
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Issuer: commonName=WIN-LU09299160F
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-04T08:22:44
| Not valid after:  2025-09-03T08:22:44
| MD5:   dfc9:0849:58d3:f56e:5d5d:86ae:e87c:61cd
| SHA-1: 7a2e:9b5b:4e9d:b672:e7e2:941a:8bbf:b894:a433:b7ef
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQWjr1pGweFpNGs+qcXTSizTANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwHhcNMjUwMzA0MDgyMjQ0WhcNMjUw
| OTAzMDgyMjQ0WjAaMRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDszzgecCSe7z0xV+dX3dmJiRMKVVgnblkb
| YZZGOq4LtAxdWh5iKBEzLhzyGRjlS+B8kcw8ksEhki+Ed46yoH/KrddjyCipX2w8
| jsMEIg2zoY/dBOvYdUdPcfPpqdvMp2I3hi4I5XEvzn1150xP9ho2XdIFBsxpdCQO
| 2DYGIlc5Bbdq7ybTeE52UodgC5mFcxrevjopk5TNUcf7GSCxqP7/ATczgpWM5jWn
| sqQy0PMPiApQ/QKxFmD9NaXAShFtuk12cRTxVRVt4VjS6Q0neznCI3Qysp7m0HsR
| GpKl1olDi/gW+ns423fHzyU4BSJyZ/CZmrjws4PEwEuYg2EpwCZVAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAwH+x1rAyVlleh3DOJCcN8kFY1AieLfHo9F/W5GPBDdzWws09SvqgdRRN
| Kq3z+pVkB9NXnwuOrtT2/KFblNW3YUiRnqAScmAQMAsKeENS+2Xf28W4KnoQwqTk
| hfg31lbLY+6/a3lIqraPJIX7tddkcRhojbMAgEAYh3J6U1OubksrYA5xNP+17rku
| vnipz7RiFCzBnqpTdrn2G7wOOfiXCD17Px+ToTqEchd6NOnF3USLGqsjeZdqowQB
| t7aH2WhoGZiPdd27nenQgZeptKajmEMcRkpXKOnXdwB6n8yhLQ+MXpDgQ9wETcZW
| U7M/4n9DgnOFDuHapQATupKyVYmBqg==
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar  5 13:55:50 2025 -- 1 IP address (1 host up) scanned in 103.02 seconds
```
