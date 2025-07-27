# Medusa

## Medusa

Medusa is a powerful, modular, parallel brute-forcing tool designed for testing authentication mechanisms across multiple protocols. It excels at high-speed password cracking with flexible configuration options.

### Basic Command Syntax

```bash
medusa [target_options] [credential_options] -M module [module_options]
```

### Target Options

| Parameter | Description                                | Example                     |
| --------- | ------------------------------------------ | --------------------------- |
| `-h HOST` | Specify a single target host               | `medusa -h 10.10.10.10 ...` |
| `-H FILE` | Specify a file containing multiple targets | `medusa -H targets.txt ...` |
| `-n PORT` | Specify a non-default port                 | `medusa -n 2222 ...`        |

### Credential Options

| Parameter     | Description                                            | Example                       |
| ------------- | ------------------------------------------------------ | ----------------------------- |
| `-u USERNAME` | Specify a single username                              | `medusa -u admin ...`         |
| `-U FILE`     | Specify a file containing usernames                    | `medusa -U users.txt ...`     |
| `-p PASSWORD` | Specify a single password                              | `medusa -p password123 ...`   |
| `-P FILE`     | Specify a file containing passwords                    | `medusa -P passwords.txt ...` |
| `-C FILE`     | Specify a combo file (username:password format)        | `medusa -C combos.txt ...`    |
| `-e ns`       | Additional checks: n=null password, s=same as username | `medusa -e ns ...`            |

### Performance Options

| Parameter  | Description                                      | Example            |
| ---------- | ------------------------------------------------ | ------------------ |
| `-t TASKS` | Number of parallel tasks                         | `medusa -t 10 ...` |
| `-T HOSTS` | Number of parallel target hosts                  | `medusa -T 5 ...`  |
| `-f`       | Stop after first valid credential found per host | `medusa -f ...`    |
| `-F`       | Stop after first valid credential found globally | `medusa -F ...`    |
| `-s`       | Enable SSL connect                               | `medusa -s ...`    |
| `-d`       | Debug mode                                       | `medusa -d ...`    |

### Output Options

| Parameter  | Description                                         | Example                     |
| ---------- | --------------------------------------------------- | --------------------------- |
| `-O FILE`  | Write output to file                                | `medusa -O results.txt ...` |
| `-v LEVEL` | Verbose level (0-6)                                 | `medusa -v 2 ...`           |
| `-w TIME`  | Wait time (seconds) between authentication attempts | `medusa -w 1 ...`           |

### Available Modules

| Module       | Protocol                     | Example                                                                                                        |
| ------------ | ---------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ftp`        | File Transfer Protocol       | `medusa -M ftp -h 10.10.10.10 -u admin -P passwords.txt`                                                       |
| `http`       | HTTP/Web Forms               | `medusa -M http -h 10.10.10.10 -u admin -P passwords.txt -m DIR:/login -m FORM:"user=&pass="`                  |
| `imap`       | IMAP Email                   | `medusa -M imap -h 10.10.10.10 -U users.txt -P passwords.txt`                                                  |
| `mssql`      | Microsoft SQL Server         | `medusa -M mssql -h 10.10.10.10 -U users.txt -P passwords.txt`                                                 |
| `mysql`      | MySQL Database               | `medusa -M mysql -h 10.10.10.10 -u root -P passwords.txt`                                                      |
| `pcanywhere` | PCAnywhere                   | `medusa -M pcanywhere -h 10.10.10.10 -U users.txt -P passwords.txt`                                            |
| `pop3`       | POP3 Email                   | `medusa -M pop3 -h 10.10.10.10 -U users.txt -P passwords.txt`                                                  |
| `postgres`   | PostgreSQL Database          | `medusa -M postgres -h 10.10.10.10 -U users.txt -P passwords.txt`                                              |
| `rdp`        | Remote Desktop               | `medusa -M rdp -h 10.10.10.10 -U users.txt -P passwords.txt`                                                   |
| `rexec`      | Remote Execution             | `medusa -M rexec -h 10.10.10.10 -U users.txt -P passwords.txt`                                                 |
| `rlogin`     | Remote Login                 | `medusa -M rlogin -h 10.10.10.10 -U users.txt -P passwords.txt`                                                |
| `rsh`        | Remote Shell                 | `medusa -M rsh -h 10.10.10.10 -U users.txt -P passwords.txt`                                                   |
| `smbnt`      | SMB (Windows)                | `medusa -M smbnt -h 10.10.10.10 -U users.txt -P passwords.txt`                                                 |
| `smtp`       | SMTP Email                   | `medusa -M smtp -h 10.10.10.10 -U users.txt -P passwords.txt`                                                  |
| `smtp-vrfy`  | SMTP Verification            | `medusa -M smtp-vrfy -h 10.10.10.10 -U users.txt`                                                              |
| `snmp`       | SNMP                         | `medusa -M snmp -h 10.10.10.10 -p public`                                                                      |
| `ssh`        | Secure Shell                 | `medusa -M ssh -h 10.10.10.10 -U users.txt -P passwords.txt`                                                   |
| `svn`        | Subversion                   | `medusa -M svn -h 10.10.10.10 -U users.txt -P passwords.txt`                                                   |
| `telnet`     | Telnet                       | `medusa -M telnet -h 10.10.10.10 -U users.txt -P passwords.txt`                                                |
| `vmauthd`    | VMware Authentication Daemon | `medusa -M vmauthd -h 10.10.10.10 -U users.txt -P passwords.txt`                                               |
| `vnc`        | VNC                          | `medusa -M vnc -h 10.10.10.10 -P passwords.txt`                                                                |
| `web-form`   | HTTP Web Form                | `medusa -M web-form -h 10.10.10.10 -U users.txt -P passwords.txt -m FORM:"user=&pass=" -m DENY:"Login failed"` |

### Common Use Cases

#### SSH Brute Force Attack

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

#### Web Authentication with Custom Form Fields

```bash
medusa -h example.com -U usernames.txt -P passwords.txt -M http -m DIR:/login -m FORM:"username=&password=" -m DENY:"Invalid credentials"
```

#### Testing for Empty and Default Passwords

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh
```

#### Parallel Brute Force Against Multiple Hosts

```bash
medusa -H hosts.txt -U usernames.txt -P passwords.txt -T 4 -t 8 -M ssh
```

#### Database Authentication Testing

```bash
medusa -h database.internal -u admin -P passwords.txt -M mysql
```

#### Stop After First Success (Fast Mode)

```bash
medusa -h 10.10.10.10 -U usernames.txt -P passwords.txt -f -M ssh
```

### Tips for Effective Use

1. **Start with limited parallelism** (`-t 4`) and increase based on network stability
2. **Use verbose mode** (`-v 1` or `-v 2`) to monitor progress
3. **Implement wait times** (`-w`) for services that may have rate limiting
4. **Prioritize known usernames** over extensive username lists
5. **Test null passwords and username-as-password** combinations first with `-e ns`
6. **Use combo lists** (`-C`) for more efficient testing with known credential pairs
