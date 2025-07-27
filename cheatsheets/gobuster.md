# Gobuster

## Gobuster Guide

Gobuster is a versatile tool written in Go that helps in discovering hidden directories, files, and virtual hosts on web servers. It's particularly useful during the enumeration phase of penetration testing.

### Key Features

* Directory and file brute forcing
* DNS subdomain brute forcing
* Virtual host discovery (vhost)
* Highly customizable output
* Fast and efficient due to Go's concurrency model
* Support for multiple wordlists

### Installation

Gobuster comes pre-installed on Kali Linux. For other systems:

```bash
# Using Go
go install github.com/OJ/gobuster/v3@latest

# On Debian-based systems
apt install gobuster
```

### Basic Usage

#### Directory Mode

The `dir` mode is used to discover directories and files on a web server:

```bash
gobuster dir -u http://10.10.11.217/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

#### Virtual Host Mode

The `vhost` mode is used to discover virtual hosts on a target web server:

```bash
gobuster vhost -u http://example.com/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

#### DNS Mode

The `dns` mode performs DNS subdomain enumeration:

```bash
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Advanced Options

#### Directory Mode Options

```bash
# Specify file extensions to look for
gobuster dir -u http://example.com/ -w wordlist.txt -x php,txt,html

# Specify status codes to display
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,204,301,302,307,401,403

# Exclude responses with specific content length
gobuster dir -u http://10.129.236.24/ -w wordlist.txt --exclude-length 400-600

# Follow redirects
gobuster dir -u http://example.com/ -w wordlist.txt -r

# Add custom headers
gobuster dir -u http://example.com/ -w wordlist.txt -H "Authorization: Bearer token"

# Use a proxy
gobuster dir -u http://example.com/ -w wordlist.txt --proxy http://127.0.0.1:8080
```

#### Virtual Host Options

```bash
# Append domain to wordlist entries
gobuster vhost -u http://example.com/ -w wordlist.txt --append-domain

# Exclude specific response lengths
gobuster vhost -u http://94.237.58.106:39481/ -w wordlist.txt --exclude-length 260-303
```

#### Threading and Performance

```bash
# Increase the number of threads (default: 10)
gobuster dir -u http://example.com/ -w wordlist.txt -t 50

# Set timeout for HTTP requests
gobuster dir -u http://example.com/ -w wordlist.txt --timeout 10s
```

#### Output Options

```bash
# Save output to a file
gobuster dir -u http://example.com/ -w wordlist.txt -o results.txt

# Verbose output
gobuster dir -u http://example.com/ -w wordlist.txt -v

# Quiet mode (only display results)
gobuster dir -u http://example.com/ -w wordlist.txt -q
```

### Real-World Examples

#### Common Web Directory Discovery

```bash
gobuster dir -u http://10.129.236.24:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --exclude-length 400-600 -t 50
```

#### Finding Admin Interfaces

```bash
gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/common-and-admin.txt -x php,html,txt
```

#### Discovering Virtual Hosts

```bash
gobuster vhost -u http://94.237.58.106:39481/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain --exclude-length 260-303 -t 50
```

#### Finding Web Application Backups

```bash
gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x zip,bak,old,backup,~
```

### Wordlist Selection

The effectiveness of Gobuster greatly depends on the wordlist used. Here are some recommended wordlists from SecLists:

* `/usr/share/seclists/Discovery/Web-Content/common.txt` - Common directories and files
* `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` - Comprehensive directory list
* `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` - Large collection of directories
* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` - Common subdomains
* `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` - Common file extensions

### Tips for Effective Usage

1. **Start broad, then narrow down**: Begin with common directories, then focus on specific areas
2. **Customize wordlists**: Create application-specific wordlists based on technologies in use
3. **Monitor response sizes**: Look for unusual response sizes that might indicate success
4. **Combine with other tools**: Use Gobuster findings as input for more targeted testing
5. **Consider rate limiting**: Adjust thread count and timing to avoid being blocked
6. **Check for false positives**: Manually verify findings, especially when using fuzzy matching

### Troubleshooting

* **Wildcard responses**: Some servers return 200 OK for all requests - use `--wildcard` flag to detect
* **Connection issues**: Try increasing timeout with `--timeout` or reducing threads with `-t`
* **Rate limiting**: If you're being blocked, reduce threads and add delays with `--delay`
* **False negatives**: Try different wordlists or extend the search with additional extensions

By mastering Gobuster, you can efficiently discover hidden resources within web applications, expanding your attack surface and identifying potential entry points for further testing.
