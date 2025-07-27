# From Couriers to Certificates: The Remarkable History of Digital Trust

## Introduction

Have you ever wondered what is with all this Digital Trust?&#x20;

***

A single TLS handshake uses crypto standards from the 1970s, passes through validation chains touching 5+ global entities, and depends on billions of lines of crypto code that almost nobody fully understands!



Root certificates are so critical that their private keys are stored in actual physical safes, sometimes in underground bunkers with armed guards. Some signing ceremonies require multiple people to provide hardware keys, like launching nuclear weapons!



Meanwhile, your laptop casually trusts \~175 root certificates from dozens of countries, many operated by governments with... questionable intentions.

The X.509 certificate standard is so complex it takes 15+ RFC documents to describe. Version 3 added "extensions" that most developers don't comprehend but somehow keep the internet functioning.



The most impressive part? This Rube Goldberg machine of cryptographic trust somehow keeps trillions of dollars of global commerce functioning 24/7/365.

All while users just see a tiny lock icon in their browser and click "continue anyway" when certificate errors appear!

***

## History

### Diffie-Hellman Breakthrough (1976):

Before 1976, the world faced a fundamental paradox in cryptography: to communicate securely, two parties needed to share a secret key, but how could they exchange this key securely in the first place?

Government agencies and militaries relied on trusted couriers to physically transport keys. Businesses used armed guards to deliver encryption keys. This system was slow, expensive, and increasingly impractical as computer networks expanded globally.

The growing computerization of sensitive systems made finding a solution increasingly urgent...

Then in 1976, Whitfield Diffie and Martin Hellman published their groundbreaking paper ["New Directions in Cryptography"](https://ee.stanford.edu/~hellman/publications/24.pdf), which solved this seemingly impossible problem.

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Random Image from the publication.</p></figcaption></figure>

This has set foot to change the world! Through their achievement they made it possible for two persons that do not know each other and are far away to be able to communicate privately through setting-up the encrypted channel over a public channel by leveraging the discrete logarithm problem, which would take millions of year to solve with the current computational power. How does this work?

* First, both A and B agree on two numbers, a prime and a base.
* Each of them now sets 1 private number that only they know.
* They now do calculations between their private number and agreed number.
* They now exchange the results.
* They now do one more round of calculation using their private number and the result from before.
* They now arrived both at the same result.

Due to the nature of the discrete logarithm problem, an eavesdropper would not be able to reverse this result.

***

### Ron Rivest, Adi Shamir and Leonard Adleman (1977):

Was just a key-exchange process enough? Was it effective for each communication process? Was it feasible? Even though it has been ground-breaking, it was not enough for a full cryptographic process! That's when, a year later at the Massachusetts Institute of Technology (MIT) the first Public Key Cryptography appears: the RSA. (Rivest, Shamir, Adleman).

The RSA allowed for a public key and a private key and this made a huge leap, especially for the public services.

The Key Differencess between RSA and Diffie-Hellman:

* RSA is using the factoring problem (the difficulty of factoring the product of two large prime numbers).
* RSA provides a full cryptographic system to enable encryption/decryption, digital signatures and the key exchange.
* RSA is not only creating ephemeral keys used for a single session, but a persistent pair of keys that can be re-used.
* Enables asynchronous communcation.

The RSA Operates by 2 keys, one that is public and can be anywhere. And one that is private and will authenticate against the public key.

***

### How can I trust this key?:

Years to come and a new problem has raised. How can the key be trusted? How can we verify that the issuer of this key is the rightful issuer?

In 1988, certificates started to appear, but they were initially developed for the Directory Services of X.500's DAP. Later on, to address authentication methods they released the X.509 which over-the-course of years has been improved to be more reliable.

X.509 certificates function like digital ID cards that bind identity to a public key. Each certificate contains:

* The subject's identity (name, domain, organization)
* The subject's public key
* Validity period (issue and expiration dates)
* The issuer's information
* The issuer's digital signature



The hierarchical trust model works through a chain of signatures:

1. Root Certificate Authorities (CAs) are trusted implicitly
2. These Root CAs sign certificates for Intermediate CAs
3. Intermediate CAs sign certificates for websites and services



When you visit a secure website, your browser verifies its certificate by:

* Checking that it's signed by a trusted CA
* Verifying the digital signature using the CA's public key
* Confirming the certificate hasn't expired
* Ensuring the domain name matches



This model allowed trust to scale globally. Major browsers and operating systems come pre-installed with 100-175 trusted root certificates, creating a foundation of trust that supports trillions of secure connections without requiring users to manually verify each certificate.

***

### Plaintext internet?:

Even though RSA and Certificates appeared. The internet was still plaintext. That's when Netscape, in 1995 released the first version of Secure Socket Layer, SSL.&#x20;

SSL's purpose had been to encrypt the communication on the internet, e.g. HTTP became HTTP(S) using port 443.&#x20;

During the SSL Handshake Authentication:

* The server is presenting it's certificate.
* The client is using the trust chain to validate it.
* Now the client is sending a key encrypting it with the public key of the server
* The server decrypts this key and they both agree on using this symmetric key for ongoing communication
* Now the communication is encrypted with symmetric encryption (typically AES). This key is unique for each session.

Although SSL was not so secure at first so many enhancements have been done to it until late 90's when the Internet Engineering Task Force (IETF) in 1999 releases Transport Layer Security (TLS).

***

## How is this used in modern protocols?

Let's take this [box](../../write-ups/timelapse-write-up-htb.md#footholding) as an example, where I cracked a .pkx file's password and then extracted the key and certificate in order to connect via WinRM. Many services in Windows are configured to accept certificates. Even Kerberos does this through the PKINIT extension.

For more about certificates authentication and using them together with pentest tools you can check here.
