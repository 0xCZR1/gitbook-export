# Kerberos

## Introduction

Kerberos is the main authentication protocol used by Active Directory. It makes ticketing based authentication possible through the generation of tickets and it has the following authentication methods in order to receive those tickets:&#x20;

* Username and Password;
* NT Hash;
* Certificate-based via X.509;

Understand the concept and the need of Kerberos to understand the three headed dog that guards the gates of the underworld.



## Let's go way back in time

### Early days:

It's 1983, at MIT the first revolutionary ticketing-based authentication system is birth as a result of the Athena Project which meant to create a computing system campus-wide, but there was a need to address:&#x20;

"How do users connect independently on the computers without sending passwords over the network"?

The Solution?

Meet Kerberos which comes from Ancient Greek, Cerberus, a 3-headed dog that guards the gates that serve as entrance to the underworld. A place where the dead can get in, but no one can get out.&#x20;

### Turning-point for Kerberos:

Although initial purpose of Kerberos was to serve for Athena, years have passed and it evolved. In 1988, Kerberos has reached version 3. Although certificate-based authentication was still not possible with Kerberos version 3, more years of development with scalability in mind made possible Kerberos v5.

### New horizons:

While version 1 to 3 were already break-throughs in authentication. There were some challenges that Kerberos had to satisfy in order to achieve it's glory. In the late 80's the group releases the version 4 of Kerberos which defined the Authentication Components and Flow that we still now today!

* Authentication Service (AS) - A client requests a Ticket Granting Ticket (TGT);
* Ticketing Granting Service (TGS)  - The TGT is used to request service tickets;
* Client/Service (CS) Exchange - The Clients use the TGS to authenticate to services;

Revolutionary for it's time, it still had some issues to address. Initially, TGT request used IP as an identifier, that caused some trouble. Even though traffic could not be intercepted and decrypted because of this, what could've easily happen was to request a TGT for an IP and then attempt to crack the password offline.&#x20;

Aside from that, there was a need for more features, like certificate authentication for example.

### Extended Features are now here!:

Kerberos v5 comes up in 1993 which had brought significant changes to the protocol. It added a lot of features, among these were:

* Delegation of authentication through forwardable tickets;
* Renewable tickets for longer sessions;
* Support for multiple encryption types;
* A generalized extensibility model for future features;

This is how PKINIT foundation had been laid off.

### Password Replicament:

Although revolutionary, still had issues. In the early days it used a password-derived key to encrypt the AS Request.&#x20;

Enterprise needed more than just this.

### PKI Idea:

Due to the fact DH laid off the basis of secure secret exchange in 76', afterwards in 77' Rivest, Shamir and Adleman laid of the first full fledged cryptographic system and 11 years later Certificates appearead and later on in the 90s became pretty mature, there were intentions to integrate such thing with Kerberos too.

### 2006:

It's 2006 and PKINIT appears! This opened new lands for Kerberos authentication. Instead of encrypting the timestamp with a password derived key, it used a X.509 Certificate, a Cryptographic Message Syntax (CMS) and a secure channel established through the DH method or RSA.



## Understanding how Kerberos Authentication Works

We first need to point out that authenticating can be split into two distinct categories:&#x20;

* Username Name and Password or HASH based
* Certificate Authentication through PKINIT extension.

These 2 categories follow different algorithms for authentication.

### Username and Password Auth:

When we do a username and password authentication, what happens is: PA-ENC-TIMESTAMP-AS-REQ.

#### First Phase (AS Exchange):

* First the client will build a Pre-Authentication Packet containing the encrypted timestamp encrypted with a password-derived key and his UPN.&#x20;
* Then it will  send an Authentication Service Request to the KDC.&#x20;
* The KDC will receive this, will validate the Pre-Auth message decrypting it with a password-derived key for the UPN and validate the timestamp not to be old and will send back an AS-REP if everything is successful.
* The AS-REP will contain a TGT encrypted with the KDC's secret key.
* The client decrypts the TGT with the key and stores it in the cache memory.

#### Second Phase (TGS Exchange):

* The client will use this TGT to request a TGS using the service SPN alongside an authenticator (username and timestamp) encrypted with the session key.
* The KDC receives, decrypts the TGT using its secret key, extracts the session key, decrypts the authenticator and validates the time.
* If successful, the KDC transmits a TGS-REP containing the TGS encrypted with the service's secret key and establish a new session key for the client encrypted with the TGT.
* Client receives, and stores the key and the TGS.

#### Third Phase (AP Exchange):

* The client connects to the service an Application Request (AP-REQ) containing the service ticket and a new authenticator encrypted with the service key.
* Service decrypts this with it's own key. Extracts the session key, uses it to decrypt the authenticator and validates the identity and timestamp.



### Certificate Based:

1. **Client Initiation**: When you log in with a certificate (e.g., smart card), your computer prepares an AS-REQ containing:
   * Your username (cleartext)
   * Your realm (domain name)
   * Pre-authentication data (PA-DATA) containing PA-PK-AS-REQ instead of PA-ENC-TIMESTAMP
   * The PA-PK-AS-REQ contains your X.509 certificate, a CMS structure signed with your private key, and key exchange data
2. **KDC Processing**: The domain controller (KDC) receives this request and:
   * Validates your certificate chain to a trusted Certificate Authority
   * Verifies your certificate hasn't expired or been revoked
   * Checks that your certificate has the Client Authentication extended key usage
   * Verifies the digital signature using your public key
   * Maps your certificate to a user account (typically via UPN in the Subject Alternative Name)
   * Completes the key exchange process (Diffie-Hellman or RSA)
3. **KDC Response**: If authentication succeeds, the KDC responds with an AS-REP containing:
   * A Ticket Granting Ticket (TGT) encrypted with the KDC's secret key
   * Key exchange data in PA-PK-AS-REP
   * Information needed to derive the session key
4. **Client Processing**: Your computer:
   * Uses your private key and the key exchange data to derive the session key
   * Stores the TGT and session key in its credential cache

#### Phases 2 and 3: Identical to Traditional Kerberos

After the initial authentication phase, the remainder of the process (TGS Exchange and AP Exchange) works exactly the same as in traditional Kerberos. This is one of the most elegant aspects of PKINIT—it only modifies the initial authentication mechanism while preserving the entire ticket-based infrastructure.









