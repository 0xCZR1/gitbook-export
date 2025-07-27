# SMB Services

## SMB Services

Server Message Block (SMB) is a protocol used for file and resource sharing over a network. It is one of the most common protocols found in both enterprise and small business environments, making it a critical component to understand for penetration testing.

### Understanding SMB

SMB operates on TCP ports 139 and 445:

* **Port 139**: SMB originally ran on top of NetBIOS over TCP/IP
* **Port 445**: Direct SMB over TCP/IP (modern implementations)

SMB was invented by IBM in the mid-1980s. The UNIX/Linux equivalent is Samba, which implements the Common Internet File System (CIFS) protocol.

### SMB/Samba Architecture

Samba is a collection of applications that implements the SMB protocol for Unix and Linux systems. It allows for seamless integration between Windows and Linux/Unix environments.

The main configuration file for Samba resides in `/etc/samba/smb.conf`. This file controls all aspects of the Samba server's behavior, including:

* Share definitions
* Authentication methods
* Access controls
* Server settings

### Connecting to SMB Shares

#### Using smbclient

The primary tool for interacting with SMB shares from Linux is `smbclient`.

**Listing Available Shares**

```bash
smbclient -N -L //10.13.13.55/
```

Output:

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        files           Disk      Mark's Files
        tom_share       Disk      
        IPC$            IPC       IPC Service (ubuntu01 server (Samba, Ubuntu))
```

Parameters explained:

* `-N`: Suppresses password prompt (null session)
* `-L`: Lists shares available on the target

**Connecting to a Share**

```bash
smbclient -N //10.13.13.55/tom_share
```

This establishes a connection to the share, allowing for file operations if permissions allow.

#### Common SMB Commands

Once connected to a share, you can use these commands:

* `ls`: List files
* `get`: Download a file
* `put`: Upload a file
* `cd`: Change directory
* `mkdir`: Create directory
* `rmdir`: Remove directory
* `del`: Delete file
* `help`: Show available commands

### SMB Access Restrictions

Access to SMB shares depends on the permission settings in the server's configuration. Common scenarios include:

1. **Anonymous Access**: Server allows null sessions (no credentials required)
2. **Read-Only Access**: Users can view but not modify files
3. **Read-Write Access**: Users can view and modify files
4. **No Access**: Authentication required and/or specific permissions needed

Example of different behavior with different permissions:

```
# Successfully connected but can't list contents
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

# Successfully connected and can list contents
smb: \> ls
  .                                   D        0  Thu Aug 22 10:07:04 2024
  ..                                  D        0  Thu Aug 22 10:07:04 2024
  file.txt                            N        5  Thu Aug 22 10:07:04 2024
```

### Alternative Enumeration Tools

Several tools can be used to enumerate and interact with SMB services:

#### RPCClient

```bash
rpcclient -U "" -N 10.13.13.55
```

Common RPCClient queries:

* `srvinfo`: Server information
* `enumdomains`: Enumerate domains
* `querydominfo`: Domain information
* `netshareenumall`: List all shares
* `enumdomusers`: List domain users
* `queryuser RID`: User information

#### SMBMap

SMBMap allows for easier enumeration of SMB shares:

```bash
smbmap -H 10.13.13.55 -u anonymous
```

#### CrackMapExec

For more advanced enumeration:

```bash
crackmapexec smb 10.13.13.55 --shares -u "" -p ""
```

#### Enum4linux

A comprehensive tool for enumerating SMB servers:

```bash
enum4linux -a 10.13.13.55
```

### Common SMB Attacks

#### Information Disclosure

Even with limited access, SMB shares might expose sensitive information:

* Internal documentation
* Password files
* Configuration files
* Backup files

#### Password Attacks

SMB authentication mechanisms can be targeted with:

* Password guessing
* Pass-the-hash attacks
* Token impersonation

Example with CrackMapExec:

```bash
crackmapexec smb 10.13.13.55 -u users.txt -p passwords.txt
```

#### SMB Relay Attacks

When SMB signing is not enforced, relay attacks are possible:

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

#### Exploiting Vulnerabilities

Historical vulnerabilities like EternalBlue (MS17-010) targeted SMB. Newer implementations are generally more secure, but misconfigurations remain common.

### Defensive Best Practices

As a penetration tester, you should understand these defensive measures:

1. **Disable SMB v1**: Legacy versions are insecure
2. **Enable SMB Signing**: Prevents relay attacks
3. **Restrict Access**: Implement proper ACLs
4. **Regular Updates**: Keep Samba/Windows updated
5. **Logging and Monitoring**: Detect unusual access patterns

### Practical Assessment Approach

When assessing SMB services:

1. **Enumerate shares**: List all available shares
2. **Test access levels**: Check permissions on each share
3. **Review content**: Examine files for sensitive information
4. **Test authentication**: Attempt to authenticate with common credentials
5. **Check configurations**: Look for misconfigurations
6. **Test for known vulnerabilities**: Check for unpatched systems

By thoroughly understanding SMB services, you can effectively test and evaluate their security posture in target environments.
