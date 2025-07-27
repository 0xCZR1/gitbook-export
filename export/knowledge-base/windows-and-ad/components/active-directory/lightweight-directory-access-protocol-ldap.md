# Lightweight Directory Access Protocol (LDAP)

## Understanding LDAP's purpose

Lightweight Directory Access Protocol, as the name states is a protocol used for Directory Access (Active \*Directory\*). In order to fully understand why the name "Lightweight" appends to the Directory Access Protocol part, we need to time-travel back in the '80s.

***

## History and Evolution

### Early X.500 DAP days:

In the '80s Active Directory type of databases/storing were starting to show up, one of the earliest was the UNIX /etc/passwd, but predominant, comprehensive, yet resource-intensive and slow was X.500's DAP (Directory Access Protocol).&#x20;

What was the deal with DAP and why was it slow?&#x20;

Well, it was using all the OSI stack, the practical one, not the conceptual OSI stack. Meaning that DAP required 7 layers to work and the Transport Layer was based of TP4 (Transport Protocol 4), equivalent to TCP for OSI. While the Network Layer was based on the ConnectionLess Network Protocol, equivalent of IP for TCP. The Session and Presentation Layer were using the Session OSI and the Presentation OSI protocols. This was making it comprehensive for the time and slow at the same time.

A need for change started to appear.

### It's 1993 and you are studying at the University of Michigan:

Year of 1993, the University of Michigan IT students, Tim Howes, Steve Kille and Wengyik Yeong (such a hard name) develop the RFC 1487 which defines the first version of LDAP. Using the TCP/IP stack. Making it "lightweight" and a better fit for the enterprise-scale environments yet to come.

### Microsoft adoption of LDAP for AD:

It's '96 and Microsoft develops Windows 2000 with AD and Kerberos integration. They need to find a way to communicate between Active Directory and also to support inter-system communication. LDAP was the best fit. LDAP was widely used at that time across different systems.&#x20;

Microsoft took LDAP and built proprietary functions upon it to handle AD specific operations.

### Summing it all up:

LDAP came out of a need to have a Directory Access Protocol that is using the TCP/IP stack, so that it is fast. Microsoft needed to adopt a Directory Access Protocol for their Active Directory Product and chose LDAP and built proprietary functions on top of it.

***

## Before the dive: LDAP Fun Fact: The "Magical" OIDs

Ever wonder why LDAP matching rules have those strange numbers like `1.2.840.113556.1.4.803`?

These aren't random! They're part of a global "OID tree" dating back to the 1980s telecommunications standards. Each organization gets their own branch to define objects without colliding with others.

The number `1.2.840.113556.1.4.803` tells a story:

* `1.2` = ISO
* `1.2.840` = US organizations
* `1.2.840.113556` = Microsoft's branch
* `1.2.840.113556.1.4` = Microsoft's LDAP extensions
* `1.2.840.113556.1.4.803` = The specific "bitwise AND" matching rule

Some Active Directory hackers keep these codes memorized! The bitwise AND (803) and recursive membership (1941) OIDs are particularly famous in security circles.

Incredibly, some LDAP implementations still use OIDs defined in the 1990s, making them older than many of the programmers using them today!

Next time you query LDAP with these magic numbers, remember you're using a piece of internet history that's survived multiple decades of technological evolution.

***

## LDAP Architecture, the DIT:

LDAP follows a hierarchal architecture that has a skeleton called Directory Informational Tree (DIT). From this tree the fruits (entities) hang for us to query.

### Entries:

Entries are the atomic unit of the DIT. Each entry gets assigned a DN.&#x20;

### Naming Contexts:

Naming Contexts are top-level divisions. There are a few types of naming contexts:

* Domain Naming Context, that reparents all the domain-related objects computers, users, etc..
* Configuration Naming Context, that represent the forest configurations.
* Schema Context, that represents data for all the objects.
* Application Partitions, that represent specific (optional) application configuration.

### Directory Schema:

The Directory Schema is not physical, it's a logical division that defines all the attributes that the objects can have, the syntax required to be used and the inheritance based on family-grade.

### Containers and Structural Elements:

Such as:

* Domain, represents the DC components.
* Organizational Units, a type of administrative container.
* Container Objects, like the BUILT-IN\USERS or COMPUTER containers.
* Application-Specific containers, example: Exchange.

### LDAP Architecture, technical implementation:

The DIT can be queried and found at %SYSTEMROOT%\NTDS\NTDS.dit on the DC. This file is an Extensible Storage Engine (ESE) that holds the database of AD:

* All directory objects and their attributes
* A hierarchy table mapping the tree structure
* Indices for efficient searching
* Replication metadata
* Deleted object tombstones

***

## LDAP Authentication and Binding

* Anonymous Bind
* Simple Bind (username and password)
* SASL Binding

### Active Directory Authentication through LDAP:

* NTLM Authentication (Windows Legacy Method)
* Kerberos Authentication (AD Based Method)
* Certificate-Based Authentication

***

## Core LDAP Operations

### Binding Operations:

* Anonymous Bound
* Not Bound
* Authenticated

```
ldapbind -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -W
```

### Search Operations:

Each search operation must contain the core parameters, so that the query is adhering to the RFC 4515 which defines the filters for search operations via LDAP. The core parameters are:

* The DN
* The OU and DC
* The Scope
* The Search Filters



Some of the below will make more sense when you reach the end and grasp the filters too!

Easiest way is to get a reflection of these from an ldap query through ldapsearch tool:

| Purpose                                   | Base DN             | Scope           | Filter                                                                                                                          | Attributes       |
| ----------------------------------------- | ------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| **Non-Expiring Passwords in Admin Group** | `dc=example,dc=com` | `sub` (subtree) | `(&(objectClass=user)(memberOf=cn=Domain Admins,cn=Users,dc=example,dc=com)(userAccountControl:1.2.840.113556.1.4.803:=65536))` | `sAMAccountName` |

#### Other Scope Options:

While all examples above use the `sub` (subtree) scope, here are examples of the other scope options:

base (meaning that will only search in that object base itself):

```
ldapsearch -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" -b "cn=John Smith,ou=IT,dc=example,dc=com" -s base "(objectClass=*)" *
```

one (meaning that will only search one object below in the tree):

```
ldapsearch -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" -b "ou=IT,dc=example,dc=com" -s one "(objectClass=person)" cn mail
```

### Add Operations:&#x20;

reates a new entry in the directory.

Example using ldapadd:

```
ldapadd -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" -f newuser.ldif
```

With newuser.ldif containing:

```ldif
ldifdn: cn=Jane Doe,ou=people,dc=example,dc=comobjectClass: inetOrgPersoncn: Jane Doesn: Doemail: jane.doe@example.comtitle: Software Engineer
```

### Modify Operation:

Changes attributes of an existing entry.

Example using ldapmodify:

```
ldapmodify -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" -f changes.ldif
```

With changes.ldif containing:

```ldif
ldifdn: cn=Jane Doe,ou=people,dc=example,dc=comchangetype: modifyreplace: titletitle: Senior Software Engineer-add: telephoneNumbertelephoneNumber: +1 555 123 4567-
```

### Delete Operation:

Removes an entry from the directory.

Example:

```
ldapdelete -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" "cn=Jane Doe,ou=people,dc=example,dc=com"
```

### Compare Operation:

Checks if an entry has a specific attribute value.

Example:

```
ldapcompare -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" "cn=Jane Doe,ou=people,dc=example,dc=com" "title:Senior Software Engineer"
```

### Modify DN Operation:

Renames an entry or moves it to a different location in the DIT.

Example:

```
ldapmodrdn -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" "cn=Jane Doe,ou=people,dc=example,dc=com" "cn=Jane Smith"
```

To move an entry to a different location:

```
ldapmodrdn -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" -r "cn=Jane Smith,ou=people,dc=example,dc=com" "cn=Jane Smith" "ou=engineering,dc=example,dc=com"
```

### Extended Operations:

LDAP allows for extension beyond the core operations. Common extended operations include:

*   **StartTLS**: Upgrade to encrypted connection

    ```
    ldapsearch -x -H ldap://ldapserver -ZZ -b "dc=example,dc=com" "(objectClass=person)"
    ```
*   **Password Modify**: Change user passwords

    ```
    ldappasswd -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password" "cn=Jane Smith,ou=people,dc=example,dc=com"
    ```
*   **Who Am I**: Determine authenticated identity

    ```
    ldapwhoami -x -H ldap://ldapserver -D "cn=admin,dc=example,dc=com" -w "password"
    ```

***

## LDAP Search Filters:

### Basic Bitwise Operations:

LDAP queries allow for search filters, these are based on the attributes of each object and the depth.&#x20;

Basic Syntax:

```
(attribute=value)
```

LDAP queries allow for bitwise operations like AND, OR, NOT, etc...

AND Bitwise Operation:

```
(&(attribute=value)(attribute=value))
```

OR Bitwise Operation:

```
(|(attribute=value)(attribute=value))
```

NOT Bitwise Operation:

```
(!(attribute=value))
```

Nested Bitwise Operations:

```
(&(objectClass=user)(|(department=IT)(department=Engineering))(!(status=disabled)))
```

### Extensible Search Operations:

LDAP also allows for extensible search operations, such as comparing accounts against a factor:

```
(attribute:rule:=value)
```

For example, in Active Directory, to find users with a specific bit flag in userAccountControl:

```
(userAccountControl:1.2.840.113556.1.4.803:=2)
```

This uses the "bitwise AND" matching rule to find disabled accounts. Why, you might ask?

So this OID 1.2.840.113556.1.4.803 stands for "LDAP\_MATCHING\_RULE\_BIT\_AND" matching rule.&#x20;

To break it down:

&#x20;`(userAccountControl:1.2.840.113556.1.4.803:=2)`:

* `userAccountControl` is the attribute being examined
* `1.2.840.113556.1.4.803` is the OID that represents the "LDAP\_MATCHING\_RULE\_BIT\_AND" matching rule
* `:=` is the operator for the extensible match
* `2` is the value to compare against, 2 means: ACCOUNTDISABLED.

