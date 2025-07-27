# NMAP Full

## Nmap Guide

Nmap (Network Mapper) is an open-source utility for network discovery and security auditing. It's considered the de facto standard for network scanning and is an essential tool in any security professional's toolkit.

### Core Functionality

Nmap can:

* Discover hosts on a network
* Identify open ports on target systems
* Determine services running on those ports
* Detect operating systems
* Probe for vulnerabilities using specialized scripts
* Map network topologies

### Basic Syntax

The general syntax for Nmap is:

```bash
nmap [scan type] [options] [target specification]
```

### Scan Types

#### Host Discovery

```bash
# Ping scan (no port scan)
nmap -sn 10.129.2.0/24

# List scan (no ping)
nmap -sL 10.129.2.0/24

# ARP scan (local network)
nmap -PR 10.129.2.0/24

# No ping scan (skip host discovery)
nmap -Pn 10.129.2.0/24
```

#### Port Scanning Techniques

```bash
# SYN scan (default)
nmap -sS 10.129.2.28

# TCP connect scan
nmap -sT 10.129.2.28

# UDP scan
nmap -sU 10.129.2.28

# FIN scan
nmap -sF 10.129.2.28

# NULL scan
nmap -sN 10.129.2.28

# XMAS scan
nmap -sX 10.129.2.28

# ACK scan
nmap -sA 10.129.2.28
```

#### Service and Version Detection

```bash
# Basic service detection
nmap -sV 10.129.2.28

# Intensity level 0-9 (0 is light, 9 is all probes)
nmap -sV --version-intensity 7 10.129.2.28

# Lighter/faster detection
nmap -sV --version-light 10.129.2.28

# Most intensive detection
nmap -sV --version-all 10.129.2.28
```

#### OS Detection

```bash
# Basic OS detection
nmap -O 10.129.2.28

# More aggressive OS detection
nmap -O --osscan-guess 10.129.2.28
```

#### Timing and Performance

```bash
# Timing templates (0-5)
nmap -T0 10.129.2.28  # Paranoid - Very slow
nmap -T1 10.129.2.28  # Sneaky
nmap -T2 10.129.2.28  # Polite
nmap -T3 10.129.2.28  # Normal (default)
nmap -T4 10.129.2.28  # Aggressive
nmap -T5 10.129.2.28  # Insane - Very fast

# Custom timing options
nmap --min-rate 1000 --max-retries 1 10.129.2.28
```

#### Output Options

```bash
# Normal output to file
nmap 10.129.2.28 -oN scan.txt

# XML output
nmap 10.129.2.28 -oX scan.xml

# Grepable output
nmap 10.129.2.28 -oG scan.grep

# All formats
nmap 10.129.2.28 -oA scans

# Verbose output
nmap -v 10.129.2.28

# Very verbose output
nmap -vv 10.129.2.28
```

### Port Selection

```bash
# Specific port
nmap -p 80 10.129.2.28

# Multiple ports
nmap -p 22,80,443 10.129.2.28

# Port range
nmap -p 1-1000 10.129.2.28

# All ports
nmap -p- 10.129.2.28

# Top ports
nmap --top-ports 100 10.129.2.28

# Fast mode (top 100 ports)
nmap -F 10.129.2.28
```

### NSE (Nmap Scripting Engine)

```bash
# Default scripts
nmap -sC 10.129.2.28

# Specific script
nmap --script=http-title 10.129.2.28

# Multiple scripts
nmap --script=http-title,http-headers 10.129.2.28

# Script categories
nmap --script=vuln 10.129.2.28

# Script with arguments
nmap --script=http-brute --script-args userdb=users.txt,passdb=passwords.txt 10.129.2.28
```

### Common Script Categories

* `default`: Default scripts run with `-sC`
* `discovery`: Information gathering scripts
* `safe`: Non-intrusive scripts
* `vuln`: Vulnerability detection
* `exploit`: Exploitation scripts (use with caution)
* `auth`: Authentication related scripts
* `brute`: Brute force scripts
* `dos`: Denial of Service scripts (use with explicit permission only)

### Advanced Features

#### Firewall Evasion

```bash
# Fragment packets
nmap -f 10.129.2.28

# Specify MTU
nmap --mtu 8 10.129.2.28

# Decoy scans
nmap -D RND:5 10.129.2.28

# Source port manipulation
nmap --source-port 53 10.129.2.28

# Append random data
nmap --data-length 200 10.129.2.28
```

#### Advanced Host Discovery

```bash
# Custom TCP SYN ping
nmap -PS22,80,443 10.129.2.0/24

# TCP ACK ping
nmap -PA80,443 10.129.2.0/24

# UDP ping
nmap -PU53,161 10.129.2.0/24

# ICMP echo ping
nmap -PE 10.129.2.0/24

# ICMP timestamp ping
nmap -PP 10.129.2.0/24

# ICMP address mask ping
nmap -PM 10.129.2.0/24
```

#### Custom Packet Parameters

```bash
# Custom TCP flags
nmap --scanflags URGACKPSHRSTSYNFIN 10.129.2.28

# Custom TTL
nmap --ttl 127 10.129.2.28

# Spoof MAC address
nmap --spoof-mac Dell 10.129.2.28
```

### Practical Examples

#### Quick Network Sweep

```bash
nmap -sn 10.129.2.0/24 --disable-arp-ping -oA network_sweep
```

#### Comprehensive Single Host Scan

```bash
nmap -sS -sV -sC -O -p- --min-rate 1000 10.129.2.28 -oA full_scan
```

#### Vulnerability Assessment

```bash
nmap -sV --script vuln 10.129.2.28 -oA vuln_scan
```

#### Low and Slow Scan (Evasion)

```bash
nmap -sS -T1 -f --data-length 200 --randomize-hosts 10.129.2.0/24 -oA stealth_scan
```

#### Web Server Scan

```bash
nmap -sV -p 80,443 --script "http-* and not http-brute" 10.129.2.28 -oA web_scan
```

#### Service-Specific Scans

**SMB/Windows**

```bash
nmap -p 139,445 --script "smb-*" 10.129.2.28 -oA smb_scan
```

**FTP**

```bash
nmap -p 21 --script "ftp-*" 10.129.2.28 -oA ftp_scan
```

**SSH**

```bash
nmap -p 22 --script "ssh-*" 10.129.2.28 -oA ssh_scan
```

### Interpreting Nmap Results

#### Port States

* `open`: Port is actively accepting connections
* `closed`: Port is accessible but no application is listening
* `filtered`: Firewall/filter is blocking access (no response)
* `unfiltered`: Port is accessible but state can't be determined
* `open|filtered`: Can't determine if port is open or filtered
* `closed|filtered`: Can't determine if port is closed or filtered

#### Service Detection

Nmap identifies services with varying confidence levels:

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
```

* Service name: `ssh`
* Software: `OpenSSH`
* Version: `8.2p1`
* Additional info: `Ubuntu 4ubuntu0.4`

### Nmap Optimization Tips

1. **Target wisely**: Limit scope to necessary hosts and ports
2. **Use proper timing**: Start with moderate timing (-T3 or -T4) and adjust as needed
3. **Be output-conscious**: Select appropriate output formats for your use case
4. **Optimize host discovery**: Use appropriate discovery methods for your network
5. **Leverage parallel scanning**: Multiple hosts can be scanned simultaneously
6. **Consider network conditions**: Adjust timing for high-latency links

### Ethical Considerations

* Always obtain proper permission before scanning
* Consider the potential impact on production systems
* Avoid aggressive scanning of critical infrastructure
* Document your activities
* Follow responsible disclosure for any findings

Nmap is a powerful tool that forms the foundation of most network security assessments. Understanding its capabilities and options allows security professionals to efficiently map networks, identify services, and discover potential vulnerabilities while minimizing impact on target systems.
