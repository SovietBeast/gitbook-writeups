---
description: >-
  Easy linux machine that involve ticketing system, default credential, memory
  dump, desserts and owning a root account!
---

# Keeper

## Credentials

| Username  | Password          | Description                    |
| --------- | ----------------- | ------------------------------ |
| root      | password          | default RT credentials for web |
| lnorgaard | Welcome2023!      | User description in RT         |
| keepass   | rødgrød med fløde | dumped from memory             |

## Enumeration

### Nmap

```
# Nmap 7.94 scan initiated Tue Sep 26 15:50:48 2023 as: nmap -p22,80 -A -oA nmap/fullscan 10.10.11.227
Nmap scan report for 10.10.11.227
Host is up (0.038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   36.88 ms 10.10.14.1
2   36.98 ms 10.10.11.227

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 26 15:50:59 2023 -- 1 IP address (1 host up) scanned in 11.50 seconds

```

### WebServer

According to this forum thread [Forum](https://forum.bestpractical.com/t/default-password/20088) default password is `password` and login is `root` as mentioned in first answer.

<figure><img src="../../.gitbook/assets/Pasted image 20230926215500.png" alt=""><figcaption><p>Login page of RT</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Pasted image 20230926220230.png" alt=""><figcaption><p>Successful login with default credentials</p></figcaption></figure>

After searching through portal, one user `lnorgaard` have plaintext password in description field. `Welcome2023!`

<figure><img src="../../.gitbook/assets/Pasted image 20230926222204.png" alt=""><figcaption><p>data of lnorgaard user</p></figcaption></figure>

This set of credentials allowed for login in SSH

<figure><img src="../../.gitbook/assets/Pasted image 20230926222412.png" alt=""><figcaption><p>Login through SSH</p></figcaption></figure>

### Privilege Escalation

User have `RT30000.zip` file, after unzipping it inside there are memory dump and keepas database.

<figure><img src="../../.gitbook/assets/Pasted image 20230926230300.png" alt=""><figcaption></figcaption></figure>

There was one vulnerability that allow dumping `master password` from memory, researcher that discovered this vuln shared a PoC:

{% embed url="https://github.com/vdohney/keepass-password-dumper" %}

<figure><img src="../../.gitbook/assets/Pasted image 20230926230414.png" alt=""><figcaption><p>Partialy recovered master password</p></figcaption></figure>

After googling whats was dumped correctly it is some kind of dessert

<figure><img src="../../.gitbook/assets/Pasted image 20230926230504.png" alt=""><figcaption></figcaption></figure>

So password is `rødgrød med fløde`. Inside keepass there is some kind of ssh key in putty format.

<figure><img src="../../.gitbook/assets/Pasted image 20230926230743.png" alt=""><figcaption></figcaption></figure>

This can be converted to `PEM` key with one command as shown here:

{% embed url="https://tecadmin.net/convert-ppk-to-pem-using-command/" %}

```bash
puttygen key -O private-openssh -o root.key
```

This allowed for login to `root` account with converted key.

<figure><img src="../../.gitbook/assets/Pasted image 20230926230927.png" alt=""><figcaption></figcaption></figure>
