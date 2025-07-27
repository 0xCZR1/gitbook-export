# SNMP

## SNMP Services

Simple Network Management Protocol (SNMP) is a widely used protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behavior. From a penetration testing perspective, SNMP can often provide valuable information about network devices and their configurations.

### Protocol Overview

SNMP operates primarily on UDP ports 161 (for general SNMP operations) and 162 (for SNMP traps). The protocol follows a client-server architecture:

* **SNMP Managers**: Systems that collect and process information from SNMP agents
* **SNMP Agents**: Software components on managed devices that provide information via SNMP

SNMP has evolved through several versions:

* **SNMPv1**: The original version with basic functionality but weak security
* **SNMPv2c**: Expanded functionality but still using community string authentication
* **SNMPv3**: Added security features including authentication and encryption

### SNMP Structure and MIB

At the core of SNMP is the Management Information Base (MIB), which holds information about network device parameters in a tree-like hierarchy. Each point in the hierarchy is addressed by an Object Identifier (OID).

#### Key MIB Trees and OIDs

These OIDs often contain valuable information for penetration testers:

| OID                    | Description                  |
| ---------------------- | ---------------------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes             |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs             |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path               |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units                |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name                |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts                |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports              |
| 1.3.6.1.2.1.25.4.2     | Running Processes Parameters |

### Enumeration Techniques

#### Port Scanning

```bash
# Basic scan
nmap -sU -p161 10.13.13.55

# Service version and script scan
sudo nmap -sU -p161 -sVC --script=snmp* 10.13.13.55
```

Example output:

```
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|   eth0
|     IP address: 10.13.13.55  Netmask: 255.255.255.0
|     MAC address: 00:0c:29:c4:42:38
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Status: up
| snmp-info: 
|   enterprise: net-snmp
|   engineID: 0x80001f888076c40b110c2978
|   engineBoots: 19
|   engineTime: 16h12m44s
|   authoritativeEngineID: 0x80001f888076c40b110c2978
|   enterpriseID: 8072
|_  engineIDFormat: 1
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:3306         0.0.0.0:0
|   TCP  127.0.0.1:25         0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  0.0.0.0:42971        *:*
| snmp-processes: 
|   1: 
|     Name: systemd
|     Path: /sbin/init
|   2: 
|     Name: kthreadd
|   3: 
|     Name: rcu_gp
...
```

#### Community String Brute Forcing

SNMP v1 and v2c use community strings for authentication, with "public" and "private" being common defaults.

**Using Nmap for Community String Brute Forcing**

```bash
sudo nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=wordlist.txt 10.13.13.55
```

Example output:

```
PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute: 
|   public - Valid credentials
|_  private - Valid credentials
```

**Using Onesixtyone**

```bash
# Single target
onesixtyone -c dict.txt 10.13.13.55

# Multiple targets
onesixtyone -c dict.txt -i hosts.txt
```

Example output:

```
Scanning 1 hosts, 51 communities
10.13.13.55 [public] Linux server 5.4.0-42-generic #46-Ubuntu SMP
10.13.13.55 [private] Linux server 5.4.0-42-generic #46-Ubuntu SMP
```

### Extracting Information with SNMP

#### Using snmpwalk

Once a valid community string is identified, `snmpwalk` can be used to extract information:

```bash
# Basic system information
snmpwalk -v2c -c public 10.13.13.55 system

# Hardware information
snmpwalk -v2c -c public 10.13.13.55 hrDevice

# Installed software
snmpwalk -v2c -c public 10.13.13.55 hrSWInstalledName

# Running processes
snmpwalk -v2c -c public 10.13.13.55 hrSWRunName

# Open TCP ports
snmpwalk -v2c -c public 10.13.13.55 tcpLocalPort

# Network interfaces
snmpwalk -v2c -c public 10.13.13.55 interfaces

# User accounts
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.4.1.77.1.2.25
```

Example output from system information:

```
SNMPv2-MIB::sysDescr.0 = STRING: Linux server 5.4.0-42-generic #46-Ubuntu SMP
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
SNMPv2-MIB::sysUpTime.0 = Timeticks: (584360) 1:37:23.60
SNMPv2-MIB::sysContact.0 = STRING: Admin <admin@example.com>
SNMPv2-MIB::sysName.0 = STRING: server.example.com
SNMPv2-MIB::sysLocation.0 = STRING: Server Room
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (0) 0:00:00.00
```

#### Targeted OID Queries

For more specific information, target individual OIDs:

```bash
# System processes
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.2.1.25.1.6.0

# Running software
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.2.1.25.4.2.1.2

# Process paths
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.2.1.25.4.2.1.4

# Storage information
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.2.1.25.2.3.1.4

# Memory information
snmpwalk -v2c -c public 10.13.13.55 hrMemorySize
```

### SNMPv3 Enumeration

SNMPv3 uses username-based security with authentication and privacy features:

```bash
# Enumerate SNMPv3 users
nmap -sU -p 161 --script=snmp-info 10.13.13.55

# Testing SNMPv3 with known credentials
snmpwalk -v3 -l authPriv -u username -a SHA -A authpassword -x DES -X privpassword 10.13.13.55 system
```

### Common SNMP Vulnerabilities

#### Weak Community Strings

Default or weak community strings (e.g., "public", "private") are common and easily guessed.

#### Information Disclosure

SNMP often reveals sensitive information about:

* Device configurations
* Network topology
* User accounts
* Running services
* Software versions

#### SNMP Write Access

If write access is enabled (using "private" or other community strings), attackers may be able to modify device configurations:

```bash
# Testing write access
snmpset -v2c -c private 10.13.13.55 SNMPv2-MIB::sysContact.0 s "Hacked"
```

#### Denial of Service

Some SNMP implementations are vulnerable to DoS attacks from malformed packets.

### SNMP Attack Scenarios

#### Network Reconnaissance

SNMP can provide comprehensive information about network infrastructure:

1. Scan the network for SNMP-enabled devices
2. Brute force community strings
3. Extract information about network interfaces, routing tables, and ARP caches
4. Map the network topology

#### Credential Harvesting

User account information may be exposed through SNMP:

```bash
# Extract usernames
snmpwalk -v2c -c public 10.13.13.55 1.3.6.1.4.1.77.1.2.25
```

#### Service Enumeration

Identify running services and open ports:

```bash
# List running processes
snmpwalk -v2c -c public 10.13.13.55 hrSWRunName

# Check listening TCP ports
snmpwalk -v2c -c public 10.13.13.55 tcpLocalPort
```

### Defensive Measures

When testing SNMP services, consider these security recommendations:

1. **Restrict SNMP Access**: Use firewall rules to limit access to SNMP ports
2. **Use Strong Community Strings**: Avoid defaults and use complex strings
3. **Migrate to SNMPv3**: Use authentication and encryption features
4. **Implement ACLs**: Restrict SNMP access to specific IP addresses
5. **Use Read-Only Community Strings**: Avoid write access where possible
6. **Regular Auditing**: Monitor SNMP access and configuration changes
7. **Update SNMP Software**: Keep SNMP implementations patched and updated

### SNMP Penetration Testing Methodology

When testing SNMP services, follow these steps:

1. **Discovery**: Identify systems with SNMP enabled
2. **Version Detection**: Determine SNMP version(s) in use
3. **Community String Testing**: Test for default and weak community strings
4. **Information Gathering**: Extract system, network, and configuration details
5. **Write Access Testing**: Test for modifiable OIDs
6. **SNMPv3 Testing**: Test authentication and encryption mechanisms
7. **Reporting**: Document findings and suggest security improvements

### Practical Testing Scripts

#### Automating SNMP Discovery

```bash
#!/bin/bash
# Simple SNMP discovery script
for ip in $(seq 1 254); do
    host="192.168.1.$ip"
    (snmpwalk -v2c -c public $host system 2>/dev/null | grep "Desc" && echo "SNMP found on $host") &
done
wait
```

#### Community String Tester

```bash
#!/bin/bash
# Test multiple community strings against a target
TARGET=$1
COMMUNITYLIST=$2

for community in $(cat $COMMUNITYLIST); do
    echo "Testing community string: $community"
    result=$(snmpwalk -v2c -c $community $TARGET system 2>&1)
    if ! echo "$result" | grep -q "Timeout\|cannot get"; then
        echo "[+] Valid community string found: $community"
        echo "$result"
    fi
done
```

### SNMP Command Reference

```bash
# Basic snmpwalk commands
snmpwalk -v2c -c public TARGET system
snmpwalk -v2c -c public TARGET interfaces
snmpwalk -v2c -c public TARGET ip
snmpwalk -v2c -c public TARGET tcp
snmpwalk -v2c -c public TARGET udp
snmpwalk -v2c -c public TARGET hrSWRunName
snmpwalk -v2c -c public TARGET hrSWInstalledName
snmpwalk -v2c -c public TARGET hrStorageDescr
snmpwalk -v2c -c public TARGET hrMemorySize

# snmpset (write) command
snmpset -v2c -c private TARGET OID s|i|a VALUE

# snmptrap command (sending trap)
snmptrap -v2c -c public TARGET '' NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 123456

# SNMPv3 commands
snmpwalk -v3 -l authPriv -u username -a SHA -A authpass -x AES -X privpass TARGET system
```

By understanding SNMP services and their security implications, penetration testers can effectively identify vulnerabilities and provide valuable recommendations for securing network management infrastructure.
