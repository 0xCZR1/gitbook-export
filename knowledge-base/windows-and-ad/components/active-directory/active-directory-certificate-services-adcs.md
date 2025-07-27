# Active Directory Certificate Services (ADCS)

Active Directory Certificate Services is Microsoft's PKI. Initially launched in 2000 as part of Windows, later on renamed and enhanced.

***

## What is a certificate?

In order to better understand certificates please check this [post](../../../digital-trust/from-couriers-to-certificates-the-remarkable-history-of-digital-trust.md#how-can-i-trust-this-key). Once you're caught up with what a certificate is. Let's get to the next point.

## What can a certificate do?

Certificates in Active Directory enable 4 distinct processes:

* Certificate-based Authentication.
* Secure (Encrypted) Protocol Communication.
* Smart Card Authentication.
* Signing Certificates (Code, E-mails, etc..).

## How are certificates working?

The main thing that attributes a certificate to an object is the Certificate SAN (Subject Alternative Name). If the SAN is set to X UPN, it will grant X access.

## ADCS Components

Primary components that are building ADCS are:

* Certificate Authority (CA).
* Web Enrollment Services.
* Certificate Templates
* Network Device Enrollment Services.
* Responder Services.
* Policy Definitions.

## From an Offensive Security Perspective

For security professionals, AD CS presents unique opportunities:

#### 1. Reconnaissance

* Certificate templates exposed via LDAP queries
* CA configurations accessible to authenticated users
* Web endpoints for certificate enrollment often available

```bash
# Using Certipy for AD CS reconnaissance
certipy find -u user@domain.com -p Password123 -dc-ip 10.10.10.10
```

#### 2. Common Vulnerabilities

* **ESC1**: Vulnerable template allowing SAN specification
* **ESC2**: Template permits domain authentication with user-supplied subject
* **ESC3**: Template allows enrollment by low-privileged users
* **ESC4**: CA allows SAN in web enrollment requests
* **ESC6**: Certificate templates with ENROLLEE\_SUPPLIES\_SUBJECT flag
* **ESC8**: NTLM relay to AD CS HTTP endpoints
* **ESC9**: Template with no security extension (as seen in "Certified")
* **ESC10**: Misconfigured template ACLs enabling privilege escalation

#### 3. Attack Techniques

* **Certificate Theft**: Stealing existing certificates from compromised hosts
* [**Shadow Credentials**](../../attacks/shadow-credential-attack.md): Technique to add certificate-based credentials
* **Certificate Request Forgery**: Requesting certificates with elevated privileges
* **NTLM Relay to AD CS**: Capturing and relaying authentication to certificate services
* **UPN Manipulation**: Changing a user's UPN before requesting certificates
* **Persistence**: Long-validity certificates provide stealthy persistence





