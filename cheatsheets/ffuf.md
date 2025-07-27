# FFUF

## FFUF Web Fuzzing Framework

FFUF (Fuzz Faster U Fool) is a powerful web fuzzing tool written in Go. It excels at web enumeration, parameter fuzzing, and virtually any task requiring HTTP requests with substitutable values.

### Key Features

* Fast multi-threaded design
* Versatile fuzzing capabilities (paths, files, parameters, headers, etc.)
* Recursive scanning
* Multiple filter options for responses
* Configurable output formats
* Support for multiple wordlists in single commands
* Automatically calibrated filtering

### Basic Syntax

The general syntax for FFUF follows this pattern:

```bash
ffuf -w wordlist.txt:KEYWORD -u https://target/KEYWORD
```

Where:

* `-w` specifies the wordlist and the keyword placeholder
* `-u` defines the target URL with the keyword placement
* `KEYWORD` is replaced with values from the wordlist

### Common Use Cases

#### Directory and File Enumeration

```bash
# Basic directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://target.com/FUZZ -mc all -fs 42 -c -v

# File extension fuzzing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://target.com/index.FUZZ

# Page fuzzing with specific extension
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://target.com/blog/FUZZ.php
```

#### Recursive Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://target.com/FUZZ -recursion -recursion-depth 1 -e .php -v
```

#### Subdomain and Vhost Fuzzing

```bash
# Subdomain enumeration
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.target.com/

# Virtual host discovery
ffuf -w hosts.txt -u https://target.com/ -H "Host: FUZZ" -mc 200
```

#### Parameter Fuzzing

```bash
# GET parameter discovery
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.target.com/admin.php?FUZZ=key -fs xxx

# POST parameter fuzzing
ffuf -w parameters.txt:PARAM -u http://target.com/api -X POST -d 'PARAM=value' -H 'Content-Type: application/x-www-form-urlencoded' -fs 123

# Value fuzzing
ffuf -w values.txt:FUZZ -u http://target.com/api -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

#### JSON Request Fuzzing

```bash
ffuf -w entries.txt -u https://api.target.com/ -X POST -H "Content-Type: application/json" \
  -d '{"username": "FUZZ", "password": "test123"}' -fr "error"
```

#### Multi-Parameter Fuzzing

```bash
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://target.com/?PARAM=VAL -mr "VAL" -c
```

### Filter Options

FFUF offers numerous ways to filter results:

```bash
# Filter by status code
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,301,302,307

# Filter by size
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 12345

# Filter by size range
ffuf -w wordlist.txt -u https://target.com/FUZZ --exclude-length 400-600

# Filter by words count
ffuf -w wordlist.txt -u https://target.com/FUZZ -fw 57

# Filter by lines count
ffuf -w wordlist.txt -u https://target.com/FUZZ -fl 25

# Filter with regex on response
ffuf -w wordlist.txt -u https://target.com/FUZZ -fr "not found"

# Match with regex on response
ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "admin"
```

### Performance Tuning

```bash
# Number of threads (default: 40)
ffuf -w wordlist.txt -u https://target.com/FUZZ -t 50

# Request delay
ffuf -w wordlist.txt -u https://target.com/FUZZ -p 0.1

# Request timeout
ffuf -w wordlist.txt -u https://target.com/FUZZ -timeout 5
```

### Output Options

```bash
# Colored output
ffuf -w wordlist.txt -u https://target.com/FUZZ -c

# Verbose output
ffuf -w wordlist.txt -u https://target.com/FUZZ -v

# Output to file (JSON format)
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.json

# Output to file (HTML format)
ffuf -w wordlist.txt -u https://target.com/FUZZ -of html -o results.html

# Silent mode (only show matches)
ffuf -w wordlist.txt -u https://target.com/FUZZ -s
```

### Advanced Usage with Examples

#### Auto-Calibration and Filtering

FFUF can automatically detect false positives:

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -acc
```

#### Using With Proxies

Useful for Burp Suite integration:

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -x http://127.0.0.1:8080
```

#### Real-world Examples

**Finding hidden administrative interfaces**

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt:FUZZ -u https://target.com/FUZZ -t 50 -mc 200,301,302 -e .php,.jsp,.aspx,.html
```

**API endpoint enumeration**

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt:FUZZ -u https://api.target.com/v1/FUZZ -mc all -fc 404
```

**Brute-forcing login credentials**

```bash
ffuf -w usernames.txt:USER -w passwords.txt:PASS -u https://target.com/login -X POST -d "username=USER&password=PASS" -fr "Invalid credentials"
```

**Discovering hidden parameters in web forms**

```bash
ffuf -w parameters.txt:PARAM -u https://target.com/search -X POST -d "PARAM=test" -H "Content-Type: application/x-www-form-urlencoded" -fr "invalid parameter"
```

### Comparison to Similar Tools

When compared to other web discovery tools:

* **Gobuster**: FFUF offers more flexibility with request types and filtering
* **Wfuzz**: FFUF is generally faster but Wfuzz has more payload processors
* **Dirbuster**: FFUF is command-line based and much faster
* **Burp Suite Intruder**: FFUF is free and typically faster for large wordlists

### Best Practices

1. **Start with small wordlists**: Begin with common.txt before using larger lists
2. **Use appropriate filters**: Learn to filter results effectively to reduce noise
3. **Recursive scanning**: Use recursion carefully as it can greatly increase scan time
4. **Rate limiting**: Be mindful of request rates, especially against production systems
5. **Custom wordlists**: Create targeted wordlists based on the application context
6. **Check results manually**: Always verify interesting findings manually

FFUF is an invaluable tool in a penetration tester's arsenal, offering unparalleled flexibility for web application discovery and testing. Its speed and versatility make it suitable for a wide range of tasks, from basic directory enumeration to complex parameter fuzzing.
