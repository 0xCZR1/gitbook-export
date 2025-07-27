# Web Application Discovery

## Web Application Discovery

Web application discovery is a crucial component of penetration testing that involves finding subdomains, virtual hosts, directories, files, and parameters to expand the attack surface.

### Subdomain and Virtual Host Enumeration

Subdomains and virtual hosts can reveal additional entry points into an application's infrastructure. These might host development environments, admin panels, or legacy applications with vulnerabilities.

#### Subdomain Enumeration

Subdomains can be discovered through various techniques:

* DNS brute forcing
* Certificate transparency logs
* Public datasets
* Virtual host brute forcing

### Directory and File Discovery

Directory enumeration helps identify hidden paths, backup files, configuration files, and other sensitive endpoints in web applications.

#### Using Gobuster for Directory Discovery

Gobuster is an effective tool for directory brute forcing:

```bash
gobuster dir -u http://10.129.236.24:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --exclude-length 400-600 -t 50
```

```bash
gobuster dir -u http://10.10.11.217/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

```bash
gobuster dir -u http://10.10.10.245/ -w /usr/share/seclists/Discovery/Web-Content/common.txt --exclude-length 400-600 -t 50
```

#### Using Gobuster for Virtual Host Discovery

```bash
gobuster vhost -u http://94.237.58.106:39481/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain --exclude-length 260-303 -t 50
```

### Advanced Web Fuzzing with FFUF

FFUF (Fuzz Faster U Fool) offers more flexibility for web fuzzing tasks including parameter fuzzing, value fuzzing, and header fuzzing.

#### Directory and Extension Fuzzing

```bash
# Directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://2million.htb/FUZZ -mc all -fs 42 -c -v

# Extension fuzzing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://checker.htb/blog/indexFUZZ
```

#### Targeted File Discovery

```bash
# Finding PHP files
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

#### Recursive Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

#### Subdomain Fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

#### Parameter Discovery and Fuzzing

```bash
# GET parameter fuzzing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx

# POST parameter fuzzing
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

#### Host Header Fuzzing

```bash
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200
```

#### Content Type and JSON Fuzzing

```bash
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"
```

#### Multi-Parameter Fuzzing

```bash
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr "VAL" -c
```

### Methodology for Comprehensive Discovery

For a thorough web application discovery process, follow this methodology:

1. **Initial Enumeration**
   * Identify technologies and frameworks using Wappalyzer or similar tools
   * Capture basic site architecture and features
   * Map visible endpoints and functionality
2. **Subdomain Discovery**
   * Use tools like Subfinder, Amass, or Sublist3r for passive discovery
   * Use Gobuster or FFUF for active brute forcing
   * Check SSL certificates for additional domain information
3. **Directory and File Enumeration**
   * Use wordlists specific to the identified technologies
   * Adjust extensions based on detected frameworks (.php, .aspx, .jsp, etc.)
   * Look for common sensitive files (.git, .env, backup files, etc.)
4. **Parameter Discovery**
   * Monitor requests in a proxy like Burp Suite to identify parameters
   * Use FFUF to discover hidden parameters
   * Test for parameter pollution and manipulation
5. **Analyze Results and Refine**
   * Prioritize findings based on potential impact
   * Customize wordlists based on discovered patterns
   * Perform focused testing on promising endpoints

### Discovery Wordlist Selection

Choosing the right wordlist for discovery is critical:

* **Technology-specific wordlists**: Match your wordlist to the technology stack
* **Size vs. speed**: Larger wordlists are more thorough but slower
* **Custom wordlists**: Create targeted lists based on the application's context
* **Recommended sources**: SecLists, jhaddix's all.txt, and custom application-specific lists

By systematically applying these techniques, you can effectively map a web application's attack surface and identify potential entry points for further testing.
