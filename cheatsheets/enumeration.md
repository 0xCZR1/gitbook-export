# Enumeration

## Enumeration Principles

Enumeration is the most crucial step of every attack. It dictates the possibilities and scope of the attack. The more targets we identify, the greater our chances of success.

As Hack The Box Academy states, enumeration is an art. Its difficulty is based on how well we understand certain services and not relying solely on automated tools.

Understanding services is a broad aspect starting from the syntax they use, input they expect, and so on.

### Network Scanning

Scan networks, find alive hosts, open ports, enumerate services running on those ports, and even OS versions. It can also identify network rules, firewall rules, and IDS/IPS.

#### Key Tools

* Nmap - Network Mapper
* Wireshark
* tcpdump

### Sub-Domain and Directory Enumeration

Against web applications, we will use sub-domains, vhost, or directory brute-forcing to discover more entry points. Directory brute-forcing applies for each domain and sub-domain.

#### Key Tools

* Gobuster
* ffuf

### Protocol Enumeration

Different protocols require specialized enumeration techniques:

#### Common Protocols to Enumerate

* FTP
* SMB and Samba
* RPC
* DNS
* NFS
* SMTP
* POP3/IMAP
* SNMP v1-2c
* MSSQL
* MySQL
* RDP

### Best Practices for Enumeration

1. **Be methodical**: Follow a structured approach to ensure nothing is missed
2. **Document everything**: Record all findings, even if they seem insignificant
3. **Save output files**: Store tool outputs for later reference
4. **Look beyond automated tools**: Manual inspection often reveals what tools miss
5. **Correlate findings**: Connect information from different sources
6. **Think creatively**: Consider non-standard use cases and edge cases

### Enumeration Workflow

1. Identify network scope and targets
2. Perform initial port scanning
3. Identify running services
4. Perform targeted service enumeration
5. Document discovered information
6. Analyze findings for potential attack vectors
7. Repeat process as new information is discovered
