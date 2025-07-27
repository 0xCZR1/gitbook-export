# Windows Security Tokens

## Introduction

Microsoft started working at these concepts since the 80's , but released the first version in the 90's, '93 more precisely when they released Windows NT 3.1. This brought the Local Security Authority System with all the components we know of today.&#x20;

One of the most atomic security components are the Security Tokens. These are comprehensive data-structures, formed out of:

* Security Identifiers - SIDs - these are IDs attributed to each user.
* Group Security Identifiers - Group SIDs - these are IDs that are held by the group which the SID belongs to.
* Restricted SIDs - these are a new layer that even if the SID would allow access, this would deny it.
* Privilege - Dual-state nature meaning that you can have it, but it can be disabled!
* DACLs - Discretionary Access Control Lists, we will cover this broader here.
* Token Type - Permanent or Impersonation.
* Integrity Levels - These are another layer of resource security where Lower levels can't modify Higher levels resources, but Higher levels can modify Lower levels. (Low, Medium, High, System).
* Session ID - This marks your log-on session so that it isolates each session on a computer.
* Source - This marks the source of the token (which process generated it).

***

## Privileges

The privileges, as mentioned above can have a dual-nature, they can be assigned but enabled or disabled.&#x20;

Example of priviliges:

* **SeDebugPrivilege**: Allows debugging any process
* **SeBackupPrivilege**: Allows reading any file regardless of ACLs
* **SeRestorePrivilege**: Allows writing to any file regardless of ACLs
* **SeTcbPrivilege**: Allows acting as part of the operating system
* **SeImpersonatePrivilege**: Allows impersonating clients after authentication

***

## Token Types

### Primary Tokens:

* Generated at process creation or during log-on.

### Impersonation Tokens:

* Allow temporary access to a resource.
* Split in 4 levels:
  * Anonymous
  * Identification
  * Impersonation
  * Delegation

### Special Token Behavior:

Token behavior changes based on creation or inheritance, even perimeter connection or protocol initiation.

#### Types:

* Interactive Log-On will grant normal privileges
* WinRM session will come with pre-enabled administrative tokens if existing.
* Service tokens will come with the service defined tokens enabled.

#### When network boundaries are traversed additional token-level controls happen.

* If the process is a networked one, certain administrative privileges are disabled.
* If the process is a networked one, certain privileges are filtered.
* Impersonation needs delegation if it traverses networks.
* Some privileges can not be exercised across network connections.

Dilution is the term used when processes spawn child processes, especially across network boundaries, tokens often experience "dilution" where privileges become increasingly restricted with each new process creation.

***

## UAC and split-token

## Example of Special Token Behavior

