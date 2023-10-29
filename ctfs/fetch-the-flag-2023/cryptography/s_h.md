# S\_H

Challenge starts with redacted `SSH` key

```
-----BEGIN RSA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAePgPfju1DWgxJZWKh/qXof
f+N3PjCCPKSpAoIBAQDYetLlj1ZjnEa4lgbf7K9ri+oVhhcIGqaQ867E2Hn4NxHT
GkVBMKqhHmH2Awc/lorAYrcQhl8et6nB1X6qk6w19kLXaMoGM1Ta4jnDBQzJ0A8+
ty8EuMvRdNilHBEUP/lKjcrY4WSgiaeaXFHMBqo8FWhJqlN9DgrPBZ19NhlTvITW
9+CeXJe3gVelCDgptrQnX/YTr2OVq5Jsb/91S1D4Hj72fP/BKzuPA3gVVMJOdW9N
jnDVWcM9MWqwLN+2UYVWRcY8XFFSeiAXN2IDe/U2tUdCPWglgmq7B/otmySf5/Gj
BdauMkI3A95ozOvjgjah/wIeRN/Bo4zKlJ2WE2J9AoIBAQDfqA9NbeHlAJe4x7p7
86q60nNiBVtZZTwdWgXntjZMpliaW1UQyOf2n8XNFoHCN9cS+kbyFEhJAfG365R4
GIyA6hr0ZKjSRPW/5grI6jct+qBjbde6nzrZe91yLlu/6NE61hJ/UDPEsuEGkxpm
fNK6Z4G1Vdb5Kc9xrjQvi1TOnfO4yq3Nd2r2VHaxXkNJKMI1mSDTuHggiEaNKY5k
evHmfNpgxGSUpGVhMqPT9hS/og1xMg3Lbs5YjcGbjZSFUtSLaY0JD3qxqI79Fqgs
f1Fxrzupb9qPkOwNDJjVEAlYmv877X6jXCO/nr7/tth3a9OWVfjBcSkVGE4rfyJC
PgFJAoIBAFbCqDIqgUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END RSA PRIVATE KEY-----
```

First and last line is crusial to discover what format key is exported here there is:

```
-----BEGIN RSA PRIVATE KEY-----
```

That means this is using `DER Distinguished Encoding Rules` But it can be also

```
-----BEGIN OPENSSH PRIVATE KEY-----
```

which mean key is exported in slightly differetnt format this challengese use first option. But for OPENSSH format description is here https://dnaeon.github.io/openssh-private-key-binary-format/

and looks like that

```C
// AUTH_MAGIC is a hard-coded, null-terminated string,
// set to "openssh-key-v1".
byte[n] AUTH_MAGIC

// ciphername determines the cipher name (if any),
// or is set to "none", when no encryption is used.
string   ciphername

// kdfname determines the KDF function name, which is
// either "bcrypt" or "none"
string   kdfname

// kdfoptions field.
// This one is actually a buffer with size determined by the
// uint32 value, which preceeds it.
// If no encryption was used to protect the private key,
// it's contents will be the [0x00 0x00 0x00 0x00] bytes (empty string).
// You should read the embedded buffer, only if it's size is
// different than 0.
uint32 (size of buffer)
    string salt
    uint32 rounds

// Number of keys embedded within the blob.
// This value is always set to 1, at least in the
// current implementation of the private key format.
uint32 number-of-keys

// Public key section.
// This one is a buffer, in which the public key is embedded.
// Size of the buffer is determined by the uint32 value,
// which preceeds it.
// The public components below are for RSA public keys.
uint32 (size of buffer)
    string keytype ("ssh-rsa")
    mpint  e       (RSA public exponent)
    mpint  n       (RSA modulus)

// Encrypted section
// This one is a again a buffer with size
// specified by the uint32 value, which preceeds it.
// The fields below are for RSA private keys.
uint32 (size of buffer)
    uint32  check-int
    uint32  check-int  (must match with previous check-int value)
    string  keytype    ("ssh-rsa")
    mpint   n          (RSA modulus)
    mpint   e          (RSA public exponent)
    mpint   d          (RSA private exponent)
    mpint   iqmp       (RSA Inverse of Q Mod P, a.k.a iqmp)
    mpint   p          (RSA prime 1)
    mpint   q          (RSA prime 2)
    string  comment    (Comment associated with the key)
    byte[n] padding    (Padding according to the rules above)
```

But that is out of the scope of this challenge. This use use DER and this is **type-length-value** encoding.

Each **type** is defined as follows:

<table><thead><tr><th width="181">type (hex)</th><th>Description</th></tr></thead><tbody><tr><td>02</td><td>Integer</td></tr><tr><td>03</td><td>Bit String</td></tr><tr><td>04</td><td>Octet String</td></tr><tr><td>05</td><td>NULL</td></tr><tr><td>06</td><td>Object Identifier</td></tr><tr><td>0C</td><td>UTF8String</td></tr><tr><td>10 (or 30)*</td><td>Sequence and Sequence of</td></tr><tr><td>11 (or 31)*</td><td>Set and Set of</td></tr><tr><td>13</td><td>PrintableString</td></tr><tr><td>16</td><td>IA5String</td></tr><tr><td>17</td><td>UTCTime</td></tr><tr><td>18</td><td>GeneralizedTime</td></tr></tbody></table>

Two types with \* are always encoded as 0x30 or 0x31, because 6th bit is used to indicate wheter a field is Constructed or Primitive, these two tags are always Constructed so thier encoding has bit 6 set to 1.

{% embed url="https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/" %}
Source
{% endembed %}

Example:

| type | length | value  |
| ---- | ------ | ------ |
| 02   | 03     | 110011 |

This can be read as **INT** that is 3byte long and its value is 0b110011

But **length** can be saved in more deliberete way: if first octet after **type** have 8th bit set to 1 then it shows that **length** is written in **long form** so if next byte after **type** starts with 0x8X it means that it uses long form of length encoding and value of X **describe length in bytes**

<figure><img src="../../../.gitbook/assets/Pasted image 20231029162233.png" alt=""><figcaption></figcaption></figure>

Example:

| type | length   | value                     |
| ---- | -------- | ------------------------- |
| 02   | 82 01 01 | 00 D8 7A ...\[snipped]... |

So here it is type **INT** with long form of length

* 0x82 0x80 confirm long from and 2 says that length is encoded on 2 byte so 0x0101 is full length

{% embed url="https://en.wikipedia.org/wiki/X.690#Length_octets" %}
Source
{% endembed %}

Key can be decoded from `base64` and saved as raw bytes. This allows for decoding it by hand. To do that first and last line need to be deleted as `-----BEGIN RSA PRIVATE KEY-----` isn't valid base64.

Decoded and save key looks like this:&#x20;

![](<../../../.gitbook/assets/Pasted image 20231029162600.png>)

Most of the key is missing but compare it with **dummy generated key** This article says that 0x0282 is header where the most important values are `p`,`q`,`dp`,`dq`,`N`,&#x20;

{% embed url="https://blog.cryptohack.org/twitter-secrets" %}
Source
{% endembed %}

Seraching through **dummy key** there are 7 hits&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 20231029162950.png" alt=""><figcaption></figcaption></figure>

Running it on obfuscated key it results only in 3 hits, but offsets are simillar.&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 20231029163033.png" alt=""><figcaption></figcaption></figure>

```go
RSAPrivateKey ::= SEQUENCE {
version           Version,
modulus           INTEGER,  -- n
publicExponent    INTEGER,  -- e
privateExponent   INTEGER,  -- d
prime1            INTEGER,  -- p
prime2            INTEGER,  -- q
exponent1         INTEGER,  -- d mod (p-1)
exponent2         INTEGER,  -- d mod (q-1)
coefficient       INTEGER,  -- (inverse of q) mod p
otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

By keeping in mind this **private key format** and applying it to **dummy key** also assuming that `e` is small so it isn't using long lenght encoding and `coefficient` can be quite big so it is using it. Data should be as follow:

* `coefficient` at offset 829
* `dq` at offset 724
* `dp` at offset 61F
* `q` at offset 51A
* `p` at offset 415
* `d` at offset 211

So applying it to challenge redacted key:

* coefficient is missing
* there are some first bytes of `dq` (offset 723)
* there is whole `dp` (offset 61E)
* there is whole prime `q` (offset 519)

And all of this allows for recovering private key as according to (page 8)

{% embed url="https://hal.science/hal-03045663/document" %}

```
e*dp = kp*(p-1) + 1
```

and this allows for `p` bruteforcing as `kp < e` After some maths shananigans

```
p = (e*dp-1)/kp + 1
```

Appart from `p` value some other values needs to be calculated

* Private exponent `d = pow(e, -1, (possible_p-1)*(q-1))`&#x20;
* Second exponent `dq = d % (q-1)`
* Modulus `N = possible_p * q`

Putting it togheter:

```python
from Crypto.Util.number import isPrime
from Crypto.PublicKey import RSA

# RSAPrivateKey ::= SEQUENCE {
#   version           Version,
#   modulus           INTEGER,  -- n
#   publicExponent    INTEGER,  -- e
#   privateExponent   INTEGER,  -- d
#   prime1            INTEGER,  -- p
#   prime2            INTEGER,  -- q
#   exponent1         INTEGER,  -- d mod (p-1)
#   exponent2         INTEGER,  -- d mod (q-1)
#   coefficient       INTEGER,  -- (inverse of q) mod p
#   otherPrimeInfos   OtherPrimeInfos OPTIONAL
# }

  
  

#upper bits of dq
dq = 0x56C2A8322A8140

#whole dp
dp=0x00DFA80F4D6DE1E50097B8C7BA7BF3AABAD27362055B59653C1D5A05E7B6364CA6589A5B5510C8E7F69FC5CD1681C237D712FA46F214484901F1B7EB9478188C80EA1AF464A8D244F5BFE60AC8EA372DFAA0636DD7BA9F3AD97BDD722E5BBFE8D13AD6127F5033C4B2E106931A667CD2BA6781B555D6F929CF71AE342F8B54CE9DF3B8CAADCD776AF65476B15E434928C2359920D3B8782088468D298E647AF1E67CDA60C46494A4656132A3D3F614BFA20D71320DCB6ECE588DC19B8D948552D48B698D090F7AB1A88EFD16A82C7F5171AF3BA96FDA8F90EC0D0C98D51009589AFF3BED7EA35C23BF9EBEFFB6D8776BD39655F8C1712915184E2B7F22423E0149

#whole q
q=0x00D87AD2E58F56639C46B89606DFECAF6B8BEA158617081AA690F3AEC4D879F83711D31A454130AAA11E61F603073F968AC062B710865F1EB7A9C1D57EAA93AC35F642D768CA063354DAE239C3050CC9D00F3EB72F04B8CBD174D8A51C11143FF94A8DCAD8E164A089A79A5C51CC06AA3C156849AA537D0E0ACF059D7D361953BC84D6F7E09E5C97B78157A5083829B6B4275FF613AF6395AB926C6FFF754B50F81E3EF67CFFC12B3B8F03781554C24E756F4D8E70D559C33D316AB02CDFB651855645C63C5C51527A20173762037BF536B547423D6825826ABB07FA2D9B249FE7F1A305D6AE32423703DE68CCEBE38236A1FF021E44DFC1A38CCA949D9613627D

#Acording to Recovering cryptographic keys from partial information, by example https://hal.science/hal-03045663/document
# e*dp = kp*(p-1) + 1
# e*dq=1+kq*(q-1) + 1

#kp < e and kq > e
#This allows for bruteforcing `p` value
#with  p=(e*dp-1)/kp + 1
public_exponent = 65537

#we need to bruteforce both values `e` and `kp` for finding p
killswitch = False
for e in range(3, public_exponent):
    for kp in range(1,e):
        possible_p = (e * dp -1)//kp +1
        if isPrime(possible_p):
            print(f"p candidate {str(possible_p)[:20]}...[snipp]...")
            N = possible_p * q
            #math is hard there is some error for some primes base is non invertable so i just skip it i hope it work #todd_howard
            try:
                d = pow(e, -1, (possible_p-1)*(q-1))
            except:
                continue
            possible_dp = d % (possible_p-1)
            if possible_dp == dp:
                possible_dq = d % (q-1)
                if hex(possible_dq).startswith(hex(dq)):
                    dq = possible_dq
                    print("It just works - dq match")
                    print(f"found exact prime: {possible_p}")
                    print(f"Found e: {e}")
                    print(f"Found d: {d}")
                    print(f"Found N: {N}")
                    p = possible_p
                    found_e = e
                    found_d = d
                    found_N = N

                killswitch = True
    if killswitch:
        break

  

# so now we know everything to construct RSA key (N,p,q,e,d)
reconstructed_key = RSA.construct((found_N,found_e,found_d,p,q))
pem = reconstructed_key.exportKey("PEM")
print(pem.decode())
```

There is one assumption done as there is no known `e` value I assumed it is no larger than usual `65537`

Output of code above is recovered  private SSH key

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

That allows login to the server

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption><p>Just a funny cat hacking into nsa</p></figcaption></figure>
