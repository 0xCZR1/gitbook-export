# Active Directory Overview

As mentioned in the previous articles, Active Directory type of databases were already existing before Windows adopting it.

When did Microsoft decide to integrate Active Directory alongside proprietary functions to it in Windows? Year 2000.

## Composition:

Active Directory is composed out of:

### Objects:

Any component of AD (e.g. Users, Groups, Machines, OUs, etc...) are AD Objects.

### Attributes:

Any object has attributes, these are the name, location, privileges, etc...

### Schema:

Schema is an overview and a blueprint of what the AD can have.&#x20;

### Domain:

A domain is a logical segmentation which can be treated as a big group of computers, users, privileges, etc...

### Forest:

The forest is the topmost object in the hierarchy and it contains more domains.

### Tree:

A collection of more domains.

### Container:

Containers hold other objects.

### GUID or UUID:

A GUID is an unique 128-bit identifier that each object posses.

### Security Principals:

Are any objects that authenticate to Windows.

### Security Identifiers:

Are unique identifiers to Security Principals.&#x20;

### Distinguished Names:

Also known as DN is the full path of an object. (e.g.:  such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`).

### Relative Distinguished Name:

It's an unique component that identifies an object from the DN.

### samAccountName:

Security Account Manager Account Name is the unique id that is used by a component to log-in for example.

### userPrincipalName:

Not mandatory, another way of identification.

### Flexible Single Master Operations - FSMO&#x20;

Protect AD from critical unwanted changes.

There are 5 FSMOs:

#### Forest Wide FSMOs:

* Schema Master - gestionates the modifications brought to the AD Schema
* Domain Naming Master - gestionates addition or subtraction of domains from forests

#### Domain Wide FSMOs:

* Relative ID (RID) Master - allocates blocks of unique RIDs to other DCs
* Primary Domain Controller (PDC) Emulator - The highest authority DC in the domain. Gestionates changes like password change, account block.
* Infrastructure Master - Synchronizes in between domain modification.



### Global Catalog:

The GC is DC that stores copies of all the objects in the forest.

### Read-Only Domain Controller (RODC):

RODC has a read-only Active Directory database. No AD account passwords are cached on an RODC (other than the RODC computer account & RODC KRBTGT passwords.) No changes are pushed out via an RODC's AD database, SYSVOL, or DNS. RODCs also include a read-only DNS server, allow for administrator role separation, reduce replication traffic in the environment, and prevent SYSVOL modifications from being replicated to other DCs.

### Replication:

Replication happens when AD object gets update and gets transferred from a DC to the others.

### SPN:

Is an identifier for services that is used by Kerberos protocol in order to provide usernameless and passwordless authentication to a service.

### GPOs:

Collections of settings of privileges in the domain.

### ACLs:

Access Control Lists are a collection of ACEs.

### ACEs

Access Control Entries different set of settings that identifiy trust between services/users/components.

### DACLs:

Contain ACEs to define what security principals are allowed or not to access an object of the domain.

### System Access Control Lists SACLs:

Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

### Tombstone:

Is a db of removed items.

### AD Recycle Bin:

A recycle bin for AD.

### SYSVOL:

SYSVOL is a shared folder of all DCs that contain the actual GPOs on disk (.pol, etc...). This has to be the same on all DCs so that replication can be correct.

#### File Replication Service: &#x20;

Was used back in 2003. Now is deprecated

#### Distributed File System Replication:

Appeared in 2008 and is now the standard.

### AdminSDHolder:

* The AdminSDHolder Object: This is an object located in the "System" container of a domain. It has a specific Access Control List (ACL) that serves as a master template.
* The SDProp Process: A process called the Security Descriptor Propagator (SDProp) runs by default every 60 minutes on the Domain Controller holding the PDC Emulator FSMO role.

It does:

* It finds all users who are members of any "protected group."
* It compares the security permissions (the ACL) of each protected user account with the permissions on the AdminSDHolder template.
* If the permissions on the user account do not match the template, SDProp overwrites them with a copy of the permissions from AdminSDHolder.



