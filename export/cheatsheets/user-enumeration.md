# User Enumeration

## User Enumeration and Password Policy Assessment

User enumeration is a critical phase in penetration testing, allowing you to identify valid user accounts that could potentially be leveraged for authentication attacks. Combined with password policy assessment, this information helps you understand the restrictions placed on accounts and plan your attack strategy accordingly.

### Password Policy Assessment

Before attempting any authentication attacks, it's essential to understand the target's password policy to avoid account lockouts and ensure efficient testing.

#### Windows Domain Password Policies

**Using CrackMapExec**

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

This provides information about:

* Minimum password length
* Password complexity requirements
* Password history count
* Maximum password age
* Account lockout thresholds and duration

**Using enum4linux**

```bash
enum4linux -P 172.16.5.5
```

**Using LDAP Queries**

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

#### Understanding Policy Output

A typical Windows domain password policy includes:

* **Password history**: Number of unique passwords before reuse (e.g., 24 passwords)
* **Maximum password age**: Time before password expiration (e.g., 42 days)
* **Minimum password age**: Time before password can be changed again (e.g., 1 day)
* **Minimum password length**: Character requirement (e.g., 7 characters)
* **Password complexity**: Requirements for different character types
* **Account lockout threshold**: Failed attempts before lockout (e.g., 5 attempts)
* **Account lockout duration**: Time account remains locked (e.g., 30 minutes)
* **Account lockout observation window**: Time window for counting failed attempts

### User Enumeration Techniques

#### Windows Domain User Enumeration

**Using enum4linux**

```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

**Using rpcclient**

```bash
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers
```

**Using CrackMapExec**

```bash
# Anonymous authentication (if allowed)
crackmapexec smb 172.16.5.5 --users

# With valid credentials
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

**Using LDAP Queries**

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

**Using Kerbrute**

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

#### Linux System User Enumeration

**Local Users**

```bash
# View local users
cat /etc/passwd | cut -d: -f1

# Users with login shells
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1
```

**LDAP Users**

```bash
# Anonymous bind (if allowed)
ldapsearch -H ldap://10.10.10.10 -x -b "dc=example,dc=com" "(objectClass=posixAccount)" uid

# Authenticated bind
ldapsearch -H ldap://10.10.10.10 -x -D "cn=admin,dc=example,dc=com" -w password -b "dc=example,dc=com" "(objectClass=posixAccount)" uid
```

#### Web Application User Enumeration

**Common Enumeration Points**

* Login pages
* Registration forms
* Password reset functionality
* User profile pages
* Error messages

**Techniques**

```bash
# Testing login responses with FFUF
ffuf -w usernames.txt -X POST -d "username=FUZZ&password=invalid" -H "Content-Type: application/x-www-form-urlencoded" -u http://example.com/login -mr "User not found"

# Testing registration responses
ffuf -w usernames.txt -X POST -d "username=FUZZ&email=test@example.com&password=Test123!" -H "Content-Type: application/x-www-form-urlencoded" -u http://example.com/register -mr "Username already taken"
```

### Creating User Lists

#### From Organizational Information

1. **Company websites**: Extract names from "About Us" and "Team" pages
2. **LinkedIn/social media**: Find employees and their naming conventions
3. **Email leaks**: Extract usernames from leaked email addresses
4. **Press releases/news articles**: Identify executives and key personnel

#### Username Format Identification

Common username formats:

* first.last (john.smith)
* firstlast (johnsmith)
* first\_last (john\_smith)
* flast (jsmith)
* first.l (john.s)
* first\_initial\_last (jsmith)
* last\_initial\_first (smithj)

#### Generating Username Lists

```bash
# Using username-anarchy
./username-anarchy.pl -f first.last John Smith

# Manual name manipulation with Python
python3 -c "names=['John Smith', 'Jane Doe']; for name in names: first, last = name.lower().split(); print(f'{
```
