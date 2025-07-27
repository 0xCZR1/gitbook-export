# POP3/IMAP

## POP3/IMAP Services

Email retrieval protocols are essential components of email infrastructure. The two main protocols for retrieving emails are POP3 (Post Office Protocol version 3) and IMAP (Internet Message Access Protocol). Understanding how these protocols function and their security implications is crucial for thorough penetration testing.

### Protocol Comparison

| Feature                 | POP3                                      | IMAP                                       |
| ----------------------- | ----------------------------------------- | ------------------------------------------ |
| Main Purpose            | Download and delete emails from server    | Synchronize emails across multiple devices |
| Default State           | Removes emails from server after download | Keeps emails on server                     |
| Ports                   | 110 (plain), 995 (SSL/TLS)                | 143 (plain), 993 (SSL/TLS)                 |
| Multiple Client Support | Limited                                   | Excellent                                  |
| Server Storage          | Minimal (emails typically removed)        | Higher (emails stored on server)           |
| Bandwidth Usage         | Lower (download once)                     | Higher (continuous synchronization)        |
| State Tracking          | Limited                                   | Tracks read/unread status across devices   |

### POP3 Protocol

POP3 is designed to download emails from a server to a client and typically (but not always) remove them from the server afterward.

#### Common POP3 Commands

| Command         | Description                                 |
| --------------- | ------------------------------------------- |
| `USER username` | Specifies the username for authentication   |
| `PASS password` | Specifies the password for authentication   |
| `STAT`          | Shows number of emails and total size       |
| `LIST`          | Lists messages with their sizes             |
| `RETR id`       | Retrieves a specific email by ID            |
| `DELE id`       | Deletes a specific email by ID              |
| `CAPA`          | Shows server capabilities                   |
| `RSET`          | Resets session state, undoing any deletions |
| `QUIT`          | Ends the session                            |

#### Typical POP3 Session

```
+OK POP3 server ready
USER user@example.com
+OK
PASS password123
+OK Logged in
STAT
+OK 3 4902
LIST
+OK 3 messages:
1 1839
2 1732
3 1331
RETR 1
+OK 1839 octets
[Message content appears here]
.
DELE 1
+OK Message 1 deleted
QUIT
+OK Bye
```

### IMAP Protocol

IMAP is designed for email synchronization across multiple devices, maintaining email state on the server.

#### Common IMAP Commands

| Command                   | Description                                    |
| ------------------------- | ---------------------------------------------- |
| `LOGIN username password` | Authentication credentials                     |
| `LIST "" "*"`             | Lists all available mailboxes                  |
| `SELECT INBOX`            | Selects a mailbox to access                    |
| `EXAMINE INBOX`           | Like SELECT but read-only                      |
| `FETCH id BODY[]`         | Retrieves an email by ID                       |
| `SEARCH SUBJECT "text"`   | Searches emails by criteria                    |
| `STORE id +FLAGS (\Seen)` | Modifies message flags (e.g., marking as read) |
| `CREATE "Folder"`         | Creates a new mailbox                          |
| `DELETE "Folder"`         | Deletes a mailbox                              |
| `LOGOUT`                  | Ends the session                               |

#### Typical IMAP Session

```
* OK IMAP server ready
a LOGIN user@example.com password123
a OK LOGIN completed
a LIST "" "*"
* LIST (\HasNoChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "Sent"
* LIST (\HasNoChildren) "." "Drafts"
* LIST (\HasNoChildren) "." "Trash"
a OK LIST completed
a SELECT INBOX
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted
* 3 EXISTS
* 0 RECENT
a OK [READ-WRITE] SELECT completed
a FETCH 1 BODY[HEADER]
* 1 FETCH (BODY[HEADER] {158}
From: sender@example.com
To: user@example.com
Subject: Test Email
Date: Wed, 15 Mar 2023 10:23:45 -0700

)
a OK FETCH completed
a LOGOUT
* BYE IMAP server terminating connection
a OK LOGOUT completed
```

### Enumeration Techniques

#### Port Scanning

```bash
# Basic scan
nmap -p 110,143,993,995 -sV 10.129.14.128

# Script scan
nmap -p 110,143,993,995 --script="pop3-*,imap-*" 10.129.14.128
```

#### Banner Grabbing

```bash
# POP3
nc -nv 10.129.14.128 110

# IMAP
nc -nv 10.129.14.128 143
```

Example outputs:

```
# POP3 banner
+OK POP3 server ready

# IMAP banner
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] IMAP server ready
```

### Authentication Testing

#### Basic Authentication

```bash
# POP3 authentication
telnet 10.129.14.128 110
USER username
PASS password

# IMAP authentication
telnet 10.129.14.128 143
a LOGIN username password
```

#### User Enumeration via POP3

POP3 can be used to verify valid usernames:

```bash
telnet 10.129.14.128 110
USER valid_user
+OK
USER invalid_user
-ERR
```

#### Brute Force Attacks

```bash
# Hydra against POP3
hydra -L users.txt -P passwords.txt pop3://10.129.14.128

# Hydra against IMAP
hydra -L users.txt -P passwords.txt imap://10.129.14.128
```

### Accessing Secure Services (SSL/TLS)

#### Using OpenSSL

```bash
# POP3S
openssl s_client -connect 10.129.14.128:995

# IMAPS
openssl s_client -connect 10.129.14.128:993
```

#### Using cURL

```bash
# IMAPS connection
curl -k 'imaps://10.129.14.128' --user user:password

# With verbose output
curl -k 'imaps://10.129.14.128' --user user:password -v
```

### Retrieving and Analyzing Emails

#### POP3 Email Retrieval

```bash
telnet 10.129.14.128 110
USER username
PASS password
LIST
RETR 1
```

#### IMAP Email Retrieval

```bash
telnet 10.129.14.128 143
a LOGIN username password
a LIST "" "*"
a SELECT INBOX
a FETCH 1 BODY[]
```

#### Extracting Email Attachments

For POP3/IMAP penetration testing, you may want to extract email attachments to search for sensitive data:

```bash
# Using Python to extract attachments (example code)
python3 extract_attachments.py
```

### Advanced Techniques

#### Capturing Login Credentials

Setting up a fake POP3/IMAP server to capture credentials:

```bash
sudo python3 fake_pop3_server.py
```

#### Email Content Analysis

Examining emails for sensitive information:

```bash
# Search for specific patterns in retrieved emails
grep -E "(password|credential|api.?key)" email_contents.txt
```

#### SSL/TLS Configuration Testing

```bash
# Test for weak ciphers
nmap --script ssl-enum-ciphers -p 993,995 10.129.14.128
```

### Common Vulnerabilities

#### Authentication Issues

1. **Cleartext Authentication**: POP3 and IMAP may transmit credentials in plaintext
2. **Brute Force Susceptibility**: Often lack account lockout mechanisms
3. **Man-in-the-Middle Attacks**: Especially when SSL/TLS is not used

#### Protocol-Specific Vulnerabilities

1. **POP3 Command Injection**: Some older servers vulnerable to command injection
2. **IMAP Format String Vulnerabilities**: Affecting specific implementations
3. **DoS Vulnerabilities**: Especially against resource-intensive SEARCH commands

### Practical Attack Scenarios

#### Scenario 1: Email Harvesting

1. Authenticate to the POP3/IMAP server
2. Retrieve all emails
3. Analyze content for:
   * Additional email addresses
   * Password reset links
   * Internal information
   * Credentials in plaintext

#### Scenario 2: Lateral Movement

1. Discover valid credentials through brute forcing
2. Access email account
3. Search for:
   * Access to other services
   * Stored credentials
   * VPN configurations
   * Information about internal systems

#### Scenario 3: SSL/TLS Downgrade

1. Set up a man-in-the-middle attack
2. Force downgrade from secure to plaintext communication
3. Capture authentication credentials

### Email Client Configurations

Understanding common email client configurations can help identify potential security issues:

```
# Typical Thunderbird configuration (example)
Server: mail.example.com
Protocol: IMAP
Port: 993
Security: SSL/TLS
Authentication: Normal password

# Outlook configuration (example)
Server: mail.example.com
Protocol: POP3
Port: 995
Security: SSL/TLS
Authentication: Normal password
```

### Defensive Measures

When reporting vulnerabilities, consider recommending:

1. **Enforce SSL/TLS**: Disable plaintext authentication
2. **Implement account lockout policies**: Prevent brute force attacks
3. **Use strong authentication methods**: Consider OAuth or MFA
4. **Regular security updates**: Keep email server software current
5. **Network segmentation**: Restrict access to email servers
6. **Logging and monitoring**: Detect unusual access patterns

### Penetration Testing Methodology

When testing POP3/IMAP services, follow these steps:

1. **Discovery**: Identify email retrieval services
2. **Banner Grabbing**: Determine server and version information
3. **Authentication Testing**: Test valid credentials and brute force resistance
4. **Encryption Testing**: Verify proper SSL/TLS implementation
5. **Access Control Testing**: Verify appropriate authorization controls
6. **Content Analysis**: Analyze accessible emails for sensitive information
7. **Client Configuration Testing**: Check for insecure client settings

### Practical Commands and Scripts

#### Automated POP3 Testing Script

```bash
#!/bin/bash
# Simple POP3 interaction script
SERVER=$1
USER=$2
PASS=$3

{
echo "USER $USER"
sleep 1
echo "PASS $PASS"
sleep 1
echo "LIST"
sleep 1
echo "RETR 1"
sleep 3
echo "QUIT"
} | nc -nv $SERVER 110
```

#### Automated IMAP Testing Script

```bash
#!/bin/bash
# Simple IMAP interaction script
SERVER=$1
USER=$2
PASS=$3

{
echo "a LOGIN $USER $PASS"
sleep 1
echo "a LIST \"\" \"*\""
sleep 1
echo "a SELECT INBOX"
sleep 1
echo "a FETCH 1 BODY[HEADER]"
sleep 3
echo "a LOGOUT"
} | nc -nv $SERVER 143
```

By understanding POP3 and IMAP services, penetration testers can effectively identify security weaknesses in email retrieval systems and provide valuable recommendations for improving security posture.
