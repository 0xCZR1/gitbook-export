---
description: Some tools...
---

# Tools

| Tool Category             | Tool Name            | Primary Purpose                       | Protocol Interaction    | Alternative Tools                   |
| ------------------------- | -------------------- | ------------------------------------- | ----------------------- | ----------------------------------- |
| **Reconnaissance**        | nmap                 | Port scanning & service discovery     | TCP/UDP                 | masscan, AutoRecon, RustScan        |
|                           | BloodHound           | AD relationship visualization         | LDAP, SMB               | PlumHound, ADExplorer               |
|                           | ADRecon              | AD information gathering              | LDAP, SMB               | PingCastle, ADCollector             |
|                           | CrackMapExec         | Network scanning & authentication     | SMB, WinRM, LDAP, MSSQL | Snaffler, PowerView                 |
|                           | ldapdomaindump       | LDAP enumeration                      | LDAP                    | windapsearch, ADExplorer            |
|                           | enum4linux-ng        | Windows/Samba enumeration             | SMB, RPC                | enum4linux, rpcclient               |
| **Credential Access**     | Mimikatz             | Credential theft & manipulation       | LSASS, Kerberos         | SharpKatz, SafetyKatz               |
|                           | Rubeus               | Kerberos ticket manipulation          | Kerberos                | Kekeo, Kerbrute                     |
|                           | LaZagne              | Credential harvesting                 | Local                   | SharpChrome, KeeThief               |
|                           | Hashcat              | Password cracking                     | Local                   | John the Ripper, BarsWF             |
|                           | KerbrDump            | Kerberos ticket extraction            | Kerberos                | mimikittenz, SessionGopher          |
|                           | SprayingToolkit      | Password spraying                     | LDAP, SMB               | DomainPasswordSpray, Ruler          |
| **Authentication Abuse**  | Certipy              | AD CS enumeration & exploitation      | LDAP, HTTP              | Certify, PSPKIAudit                 |
|                           | PKINITtools          | Certificate-based auth                | Kerberos                | gettgtpkinit, ticketer              |
|                           | pywhisker            | Shadow credentials attack             | LDAP                    | WhiskerPS, Whisker                  |
|                           | ntlmrelayx           | NTLM relay attacks                    | SMB, LDAP, HTTP         | MultiRelay, Responder               |
|                           | Responder            | LLMNR/NBT-NS poisoning                | LLMNR, NBT-NS           | Inveigh, InsecurePowerShell         |
|                           | SCMKit               | Service control abuse                 | SCMR                    | sc.exe, PetitPotam                  |
| **Lateral Movement**      | evil-winrm           | Enhanced WinRM shell                  | WinRM                   | SharpWMI, WSMan                     |
|                           | PassTheHash          | Pass-the-hash attacks                 | SMB, WMI                | Mimikatz, Impacket                  |
|                           | PowerLurk            | WMI event subscription                | WMI                     | WMImplant, WmiSploit                |
|                           | SharpRDP             | RDP hijacking                         | RDP                     | tscon, RDPWrap                      |
|                           | Chisel               | Tunneling & port forwarding           | TCP/HTTP                | ligolo-ng, sshuttle                 |
|                           | PsExec               | Remote execution                      | SMB                     | PAExec, PSExec.py                   |
| **Access Control**        | bloodyAD             | AD object manipulation                | LDAP                    | ADModule, PowerView                 |
|                           | impacket-dacledit    | DACL manipulation                     | LDAP, SMB               | PowerView, ADACLScanner             |
|                           | impacket-owneredit   | Object ownership changes              | LDAP                    | Set-ADObjectOwner, SetOwner.ps1     |
|                           | LAPSToolkit          | LAPS password retrieval               | LDAP                    | Get-LAPSPasswords, LAPSDumper       |
|                           | SharpGPOAbuse        | Group Policy abuse                    | LDAP, SMB               | PowerGPOAbuse, StandIn              |
| **Privilege Escalation**  | PowerUp              | Windows privilege escalation          | Local                   | SharpUp, JAWS                       |
|                           | BeRoot               | Privilege escalation scanner          | Local                   | PrivescCheck, WinPEAS               |
|                           | SharpHound           | AD attack path discovery              | LDAP, SMB               | AzureHound, ROADtools               |
|                           | Tokenvator           | Token manipulation                    | Local                   | incognito, juicy-potato             |
|                           | PrintSpoofer         | Service impersonation                 | Named Pipes             | RoguePotato, GodPotato              |
|                           | PPLBlade             | Protected Process bypass              | LSASS                   | PPLdump, PPLKiller                  |
| **Post-Exploitation**     | SharpC2              | Command & Control                     | Various                 | Covenant, Havoc                     |
|                           | ADCSPwn              | AD CS relay                           | LDAP, HTTP              | petitpotam, Certifried              |
|                           | SharpChisel          | Tunneling tool                        | TCP                     | SharpSocks, SocksOverRDP            |
|                           | Seatbelt             | System survey                         | Local                   | SysInternals, JAWS                  |
|                           | Nishang              | PowerShell post-exploitation          | Various                 | PowerSploit, Empire                 |
|                           | HiddenPowerShell     | PowerShell AMSI bypass                | .NET                    | PowerShell Empire, PsBypassCLM      |
| **Persistence**           | SharpStrike          | Scheduled task creation               | Task Scheduler          | AtExec, Schtasks.exe                |
|                           | SharPersist          | Multiple persistence methods          | WMI, Registry           | PowerLurk, WMImplant                |
|                           | SharpDPAPI           | DPAPI abuse                           | DPAPI                   | mimikatz, DpapiDump                 |
|                           | BetterSafetyKatz     | Obfuscated Mimikatz                   | LSASS                   | SharpKatz, SafetyKatz               |
|                           | BackdoorFactory      | Binary backdooring                    | PE/ELF                  | Shelter, Ebowla                     |
| **Domain Dominance**      | krbrelayx            | Kerberos relaying                     | Kerberos                | kekeo, Rubeus                       |
|                           | deathstar            | Automated domain takeover             | Various                 | RACE, ADReaper                      |
|                           | Powermad             | New machine accounts                  | LDAP                    | MachineAccountQuota, addcomputer.py |
|                           | aclpwn               | Automated ACL attacks                 | LDAP                    | SharpACL, ADACLScanner              |
|                           | lsassy               | Remote LSASS dumping                  | LSASS                   | procdump+mimikatz, nanodump         |
| **Forest/Domain Attacks** | ntlmrelayx           | NTLM relay                            | LDAP, SMB, HTTP         | Responder, MultiRelay               |
|                           | adidnsdump           | AD-integrated DNS                     | DNS, LDAP               | dirkjanm/krbrelayx, dnsteal         |
|                           | dementor             | Resource-based constrained delegation | Kerberos, LDAP          | SpoolSample, PetitPotam             |
|                           | targetedKerberoast   | Targeted Kerberoasting                | Kerberos                | GetUserSPNs.py, Rubeus              |
|                           | KrbRelayUp           | Kerberos relay privilege escalation   | Kerberos, LDAP          | GoldenGMSA, Silver                  |
| **Forest Trusts**         | PyWhisker            | Shadow credentials for trusts         | LDAP                    | Whisker, SharpSCCM                  |
|                           | SharpTrust           | Trust relationship enumeration        | LDAP, Kerberos          | Get-ADTrust, PowerView              |
|                           | ForgeCert            | Certificate forgery                   | AD CS                   | SharpDPAPI, Certi                   |
|                           | adconnectdump        | Azure AD Connect credential theft     | MSSQL                   | azuread\_decrypt\_msol, dploot      |
| **Evasion**               | Invoke-Obfuscation   | PowerShell obfuscation                | .NET                    | Chameleon, ISESteroids              |
|                           | AmsiScanBufferBypass | AMSI bypass                           | .NET                    | AmsiOps, PSBobfuscator              |
|                           | SharpBlock           | EDR evasion                           | ETW, AMSI               | SharpEvade, ProcessInjection        |
|                           | ScareCrow            | EDR evasion toolkit                   | Process Injection       | Mystikal, DonutCS                   |
|                           | NetLoader            | .NET assembly loader                  | .NET                    | GhostLoader, GadgetToJScript        |
| **DCSync & Replication**  | secretsdump.py       | DCSync attack                         | MS-DRSR                 | mimikatz DCSync, SharpSecDump       |
|                           | impacket-ntlmrelayx  | NTLM relay                            | LDAP, SMB, HTTP         | dirkjanm/krbrelayx, mitm6           |
|                           | SharpZeroLogon       | Zerologon exploit                     | MS-NRPC                 | CVE-2020-1472-exploit, zcrypto      |
|                           | PetitPotam           | NTLM coercion                         | MS-EFSRPC               | PrinterBug, ShadowCoerce            |
| **Exfiltration**          | SharpExfiltrate      | Data exfiltration                     | DNS, ICMP, HTTP         | DNSExfiltrator, Egress-Assess       |
|                           | ExfilDocs            | Document metadata scraping            | SMB                     | MetaExtractor, PowerMeta            |
|                           | SharpExfil           | Built-in protocol exfil               | DNS, HTTPS              | dnscat2, tunshell                   |
