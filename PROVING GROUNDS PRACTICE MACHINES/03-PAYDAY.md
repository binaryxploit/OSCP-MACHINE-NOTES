## OPEN PORTS 
```bash
# Open Ports
22/tcp  open  ssh         syn-ack ttl 61 OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
80/tcp  open  http        syn-ack ttl 61 Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
110/tcp open  pop3        syn-ack ttl 61 Dovecot pop3d
139/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        syn-ack ttl 61 Dovecot imapd
445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    syn-ack ttl 61 Dovecot imapd
995/tcp open  ssl/pop3    syn-ack ttl 61 Dovecot pop3d
```
## INITIAL FOOTHOLD
```bash
# Port 80 - CS-Cart 2006
- Uses default password admin:admin

# Exploit + Reference
https://gist.github.com/momenbasel/ccb91523f86714edb96c871d4cf1d05c

- Visit "cs-cart" /admin.php and login
- Under Look and Feel section click on "template editor"
- create a php-reverse shell and rename as shell.phtml
- upload shell.phtml
- access url http://192.168.247.39/skins/shell.phtml

# www-data shell
```
## PRIVILEGE ESCALTION
```bash
# cat /etc/passwd
- Found user patrick

# username as password
patrick:patrick

# sudo -l
User patrick may run the following commands on this host:
    (ALL) ALL

sudo su
# root
```