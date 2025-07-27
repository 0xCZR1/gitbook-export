# Shadow Credential Attack

## Introduction

This type of attack is relatively new compared to the other credential attacks out there. Disclosed by Elad Shamir in 2021 while he was researching for different ways of credential attacks it's taking advantage of the msDS-KeyCredentialLink attribute.

Before Shadow Credentials, attackers typically relied on:

* Kerberoasting (2014)
* AS-REP Roasting (2017)
* DCSync attacks (circa 2015)
* NTLM relay attacks
* Password spraying and brute forcing

These techniques either left significant event logs or became heavily monitored. The security community needed new, stealthier ways to obtain credentials.

## msDS-KeyCredentialLink attribute

What is it? This attribute has been added by Microsoft in order to save a public key on an object for Windows Hello purposes. Shadow Credential Attack is taking advantage of it by using GenericAll, WriteDACL, GenericWrite, WriteOwner to write a public key to an object and then using it's private key to request a TGT.&#x20;

### The Technical Mechanics

The attack works by:

1. Adding a new key credential to a target account's `msDS-KeyCredentialLink` attribute
2. Using the corresponding private key (which only the attacker knows) to request a Kerberos TGT via PKINIT
3. Extracting the NT hash from the encrypted parts of the TGT
4. Using the NT hash for subsequent authentication

This attack exploits the trust relationship between Kerberos and certificate-based authentication without needing to modify the account's actual password.

