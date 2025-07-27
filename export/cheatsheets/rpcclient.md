# RPCClient

## RPCClient Guide

RPCClient is a powerful command-line tool that's part of the Samba suite, designed for interacting with Microsoft RPC (Remote Procedure Call) services. It provides a versatile interface for enumerating and working with Windows-based systems, particularly Active Directory environments and SMB/CIFS services.

### Introduction to RPCClient

RPCClient leverages Microsoft's Remote Procedure Call (RPC) protocol to communicate with Windows services. The tool is particularly useful for:

* Enumerating domain users and groups
* Gathering information about servers and domains
* Querying user information
* Exploring available shares
* Testing authentication credentials
* Performing password resets (with appropriate privileges)

### Basic Connection Syntax

The basic syntax for connecting to a system with RPCClient is:

```bash
rpcclient -U [username] [target]
```

For a null session (anonymous) connection:

```bash
rpcclient -U "" -N [target]
```

Command options:

* `-U [username]`: Specify the username
* `-P [password]`: Specify the password (not recommended - insecure)
* `-N`: No password (for null sessions)
* `-W [domain]`: Specify the domain
* `-c [command]`: Run a single command and exit
* `-I [IP address]`: Connect to specific IP address
* `-p [port]`: Connect to specific port
* `-d [debug level]`: Set debug level

### Key RPC Commands

Once connected, these essential commands can help enumerate the target system:

#### Server Information

```
rpcclient $> srvinfo
```

Example output:

```
        INLANEFREIGHT   Wk Sv PrQ Unx NT SNT INLANEFREIGHT server
        platform_id     : 500
        os version      : 6.1
        server type     : 0x809a03
```

This output provides:

* Server name
* Operating system version
* Server platform information
* Server type flags

#### Domain Information

```
rpcclient $> enumdomains
```

Example output:

```
name:[INLANEFREIGHT] idx:[0x0] 
name:[Builtin] idx:[0x1]
```

For more detailed domain information:

```
rpcclient $> querydominfo
```

Example output:

```
Domain:         INLANEFREIGHT
Server:         DC01
Comment:        INLANEFREIGHT Domain Controller
Total Users:    2985
Total Groups:   116
Total Aliases:  26
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

#### Share Enumeration

List all available shares:

```
rpcclient $> netshareenumall
```

Example output:

```
netname: ADMIN$
        remark: Remote Admin
        path:   C:\Windows
        password:
netname: C$
        remark: Default share
        path:   C:\
        password:
netname: IPC$
        remark: Remote IPC
        path:
        password:
netname: NETLOGON
        remark: Logon server share
        path:   C:\Windows\SYSVOL\sysvol\inlanefreight.local\SCRIPTS
        password:
netname: SYSVOL
        remark: Logon server share
        path:   C:\Windows\SYSVOL\sysvol
        password:
```

For detailed information about a specific share:

```
rpcclient $> netsharegetinfo SYSVOL
```

#### User Enumeration

List all domain users:

```
rpcclient $> enumdomusers
```

Example output:

```
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[jsmith] rid:[0x44f]
user:[svc_backup] rid:[0x585]
```

#### User Information

Query detailed information about a specific user using their Relative ID (RID):

```
rpcclient $> queryuser 0x44f
```

Example output:

```
        User Name   :   jsmith
        Full Name   :   John Smith
        Home Drive  :   \\dc01\users\jsmith
        Dir Drive   :   
        Profile Path:   \\dc01\profiles\jsmith
        Logon Script:   logon.bat
        Description :   Marketing User
        Workstations:   
        Comment     :   
        Remote Dial :
        Logon Time               :      Wed, 27 Oct 2021 10:56:58 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Tue, 26 Oct 2021 09:32:26 EDT
        Password can change Time :      Wed, 27 Oct 2021 09:32:26 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x44f
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000001
        padding1[0..7]...
        logon_hrs[0..21]...
```

#### Group Enumeration

List all domain groups:

```
rpcclient $> enumdomgroups
```

Example output:

```
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
```

Query group members:

```
rpcclient $> querygroupmem 0x200
```

Example output:

```
        rid:[0x1f4] attr:[0x7]
        rid:[0x450] attr:[0x7]
```

Then resolve these RIDs to usernames:

```
rpcclient $> queryuser 0x1f4
```

#### Password Policy Information

Retrieve domain password policy:

```
rpcclient $> getdompwinfo
```

Example output:

```
min_password_length: 8
password_properties: 0x00000001
        DOMAIN_PASSWORD_COMPLEX
```

Query the password policy for a specific user:

```
rpcclient $> getusrdompwinfo 0x44f
```

### Advanced Usage

#### Running Commands in Batch Mode

Instead of entering an interactive session, you can execute commands directly from the command line:

```bash
rpcclient -U "username%password" -c "enumdomusers" 192.168.1.100
```

Using a script to run multiple commands:

```bash
echo -e "enumdomusers\nquerygroupmem 0x200" | rpcclient -U "username%password" 192.168.1.100
```

#### User Manipulation (with Admin Rights)

Create a new user (if you have appropriate privileges):

```
rpcclient $> createdomuser newuser
```

Set a user's password:

```
rpcclient $> setuserinfo2 newuser 23 'Password123!'
```

Add a user to a group:

```
rpcclient $> addgroupmem 0x200 0x456
```

#### Looking Up SIDs

Convert between names and SIDs:

```
rpcclient $> lookupnames administrator
```

Example output:

```
administrator S-1-5-21-1036416015-3025729302-1618636688-500
```

Convert SID back to name:

```
rpcclient $> lookupsids S-1-5-21-1036416015-3025729302-1618636688-500
```

#### Printer Information

If print services are available, you can enumerate printers:

```
rpcclient $> enumprinters
```

Get details about a specific printer:

```
rpcclient $> getprinter 0
```

### Automating RPCClient Tasks

#### Extracting All Domain Users

```bash
#!/bin/bash
# Script to extract domain users and save to file
target=$1
output_file="domain_users.txt"

# Connect and extract domain users
rpcclient -U "" -N $target -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "_" | tr -d '[]' > $output_file

echo "Extracted $(wc -l < $output_file) users to $output_file"
```

#### Enumerating Domain Information

```bash
#!/bin/bash
# Comprehensive domain enumeration script
target=$1
output_dir="domain_enum_$(date +%Y%m%d_%H%M%S)"

mkdir -p $output_dir
echo "Starting enumeration of $target"

# Run various enumeration commands
rpcclient -U "" -N $target -c "srvinfo" > $output_dir/server_info.txt
rpcclient -U "" -N $target -c "enumdomains" > $output_dir/domains.txt
rpcclient -U "" -N $target -c "querydominfo" > $output_dir/domain_info.txt
rpcclient -U "" -N $target -c "enumdomusers" > $output_dir/users.txt
rpcclient -U "" -N $target -c "enumdomgroups" > $output_dir/groups.txt
rpcclient -U "" -N $target -c "netshareenumall" > $output_dir/shares.txt
rpcclient -U "" -N $target -c "getdompwinfo" > $output_dir/password_policy.txt

echo "Enumeration complete. Results saved to $output_dir"
```

#### Mapping Group Membership

```bash
#!/bin/bash
# Script to map domain group membership
target=$1
group_rid=$2  # e.g., 0x200 for Domain Admins

# Get group members
members=$(rpcclient -U "" -N $target -c "querygroupmem $group_rid" | grep rid | awk '{print $1}' | cut -d '[' -f 2 | cut -d ']' -f 1)

echo "Group members:"
for rid in $members; do
    username=$(rpcclient -U "" -N $target -c "queryuser $rid" | grep "User Name" | cut -d ':' -f 2 | tr -d ' ')
    echo "$username ($rid)"
done
```

### Troubleshooting RPCClient

#### Common Issues and Solutions

**Connection Failures**

If you're having trouble connecting:

```
Error: NT_STATUS_CONNECTION_REFUSED
```

Possible solutions:

* Verify that SMB service is running on the target
* Check firewall settings
* Ensure the target allows the authentication method you're using

**Authentication Issues**

```
Error: NT_STATUS_LOGON_FAILURE
```

Possible solutions:

* Verify username and password
* Check domain name if using domain authentication
* Confirm account is not locked out or disabled

**Access Denied Errors**

```
Error: NT_STATUS_ACCESS_DENIED
```

Possible solutions:

* The authenticated user doesn't have sufficient privileges
* Remote registry access might be disabled
* Check local security policies on the target

**Missing RPC Endpoints**

```
Error: NT_STATUS_RPC_INTERFACE_NOT_FOUND
```

Possible solutions:

* The requested RPC service might not be running
* Firewall might be blocking specific RPC endpoints
* Service might have been disabled

### Security Considerations

When using RPCClient for penetration testing or security assessments:

1. **Log your activities**: Keep detailed records of all commands and output
2. **Minimize authentication attempts**: Avoid account lockouts
3. **Consider detection impact**: RPC enumeration may trigger security alerts
4. **Handle discovered credentials securely**: Protect any sensitive information
5. **Clean up**: If you create test accounts, ensure they are removed after testing

### Defensive Measures Against RPC Enumeration

As a penetration tester, it's valuable to understand defensive measures:

1. **Disable null sessions**: Prevent anonymous enumeration
2. **Restrict RPC access**: Use firewalls to limit RPC connections
3. **Implement least privilege**: Minimize what authenticated users can enumerate
4. **Enable detailed logging**: Monitor for suspicious RPC activity
5. **Use network segmentation**: Limit which systems can make RPC calls to sensitive servers

### Command Reference

| Command                              | Description                       |
| ------------------------------------ | --------------------------------- |
| `srvinfo`                            | Displays server information       |
| `enumdomains`                        | Lists all domains                 |
| `querydominfo`                       | Shows detailed domain information |
| `netshareenumall`                    | Lists all available shares        |
| `netsharegetinfo <share>`            | Shows detailed share information  |
| `enumdomusers`                       | Lists all domain users            |
| `queryuser <RID>`                    | Shows detailed user information   |
| `enumdomgroups`                      | Lists all domain groups           |
| `querygroupmem <RID>`                | Lists members of a group          |
| `getdompwinfo`                       | Shows domain password policy      |
| `lookupnames <name>`                 | Converts name to SID              |
| `lookupsids <SID>`                   | Converts SID to name              |
| `createdomuser <username>`           | Creates a new domain user         |
| `deletedomuser <username>`           | Deletes a domain user             |
| `setuserinfo2 <user> 23 <password>`  | Sets a user's password            |
| `addgroupmem <group_rid> <user_rid>` | Adds user to a group              |
| `enumprinters`                       | Lists available printers          |

By mastering RPCClient, penetration testers can effectively enumerate and interact with Windows systems, gathering valuable information for security assessments and vulnerability identification.
