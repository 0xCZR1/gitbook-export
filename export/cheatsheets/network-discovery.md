# Network Discovery

## Network Discovery

Network discovery is a critical phase in penetration testing that involves identifying hosts, open ports, services, and operating systems within a target network.

### Host and Port Scanning

After determining that a host is online, we need to gather detailed information:

* Open ports and their services
* Service versions
* Operating system details

#### Port State Responses

When probing ports with Nmap, six possible response states can be identified:

| **State**          | **Description**                                                                                                                                     |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `open`             | Connection to the scanned port has been established. These can be TCP connections, UDP datagrams, or SCTP associations.                             |
| `closed`           | The TCP protocol indicates that the packet received contains an `RST` flag. This scanning method can also determine if a target is alive.           |
| `filtered`         | Nmap cannot identify whether the port is open or closed because either no response is returned or an error code is received from the target.        |
| `unfiltered`       | This state only occurs during TCP-ACK scans and means that the port is accessible, but it cannot be determined whether it is open or closed.        |
| `open\|filtered`   | No response for a specific port leads to this state. This indicates that a firewall or packet filter may protect the port.                          |
| `closed\|filtered` | This state only occurs in IP ID idle scans and indicates that it's impossible to determine if the scanned port is closed or filtered by a firewall. |

### Scan Types

Different scan types serve various purposes during network discovery:

| Scan Type | Description                                                                                                          |
| --------- | -------------------------------------------------------------------------------------------------------------------- |
| -sS       | SYN Scan: Sends only one SYN-flagged packet and does not complete the full TCP handshake. _Requires sudo privileges_ |
| -sT       | TCP Connect Scan: Completes the full three-way TCP handshake.                                                        |
| -sU       | UDP Scan: Tests UDP ports which often host important services like DNS, SNMP, and DHCP.                              |
| -sV       | Service Version Scan: Identifies the version of services running on open ports.                                      |
| -sA       | ACK Scan: Sends only ACK-flagged packets, useful for mapping firewall rules.                                         |

### Scan Parameters

Optimize your scans with these parameters:

| Parameter          | Description                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| --disable-arp-ping | Disables the default ARP ping, useful in complex networks.                                     |
| -n                 | Disables DNS resolution, speeding up scans.                                                    |
| --packet-trace     | Shows all packets sent and received, valuable for debugging.                                   |
| --reason           | Displays the reason why Nmap made a particular determination.                                  |
| -Pn                | Disables host discovery (ICMP Echo Requests), treating all hosts as online.                    |
| -p-                | Scans all 65535 ports.                                                                         |
| --stats-every=5s   | Checks and shows scan status every 5 seconds.                                                  |
| -v                 | Increases verbosity for more detailed output.                                                  |
| -A                 | Enables aggressive scanning: OS detection, version detection, script scanning, and traceroute. |

### Example Scans

#### Basic Port Scan with Service Detection

```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason -sV
```

Output:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-04 11:10 GMT
SENT (0.3426s) TCP 10.10.14.2:44641 > 10.129.2.28:445 S ttl=55 id=43401 iplen=44  seq=3589068008 win=1024 <mss 1460>
RCVD (0.3556s) TCP 10.129.2.28:445 > 10.10.14.2:44641 SA ttl=63 id=0 iplen=44  seq=2881527699 win=29200 <mss 1337>
NSOCK INFO [0.4980s] nsock_iod_new2(): nsock_iod_new (IOD #1)
NSOCK INFO [0.4980s] nsock_connect_tcp(): TCP connection requested to 10.129.2.28:445 (IOD #1) EID 8
NSOCK INFO [0.5130s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 8 [10.129.2.28:445]
Service scan sending probe NULL to 10.129.2.28:445 (tcp)
NSOCK INFO [0.5130s] nsock_read(): Read request from IOD #1 [10.129.2.28:445] (timeout: 6000ms) EID 18
NSOCK INFO [6.5190s] nsock_trace_handler_callback(): Callback: READ TIMEOUT for EID 18 [10.129.2.28:445]
Service scan sending probe SMBProgNeg to 10.129.2.28:445 (tcp)
NSOCK INFO [6.5190s] nsock_write(): Write request for 168 bytes to IOD #1 EID 27 [10.129.2.28:445]
NSOCK INFO [6.5190s] nsock_read(): Read request from IOD #1 [10.129.2.28:445] (timeout: 5000ms) EID 34
NSOCK INFO [6.5190s] nsock_trace_handler_callback(): Callback: WRITE SUCCESS for EID 27 [10.129.2.28:445]
NSOCK INFO [6.5320s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 34 [10.129.2.28:445] (135 bytes)
Service scan match (Probe SMBProgNeg matched with SMBProgNeg line 13836): 10.129.2.28:445 is netbios-ssn.  Version: |Samba smbd|3.X - 4.X|workgroup: WORKGROUP|
NSOCK INFO [6.5320s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up, received user-set (0.013s latency).

PORT    STATE SERVICE     REASON         VERSION
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: Ubuntu

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.55 seconds
```

### Recommended Scanning Strategy

1.  **Initial reconnaissance**: Broad scan to identify live hosts

    ```bash
    sudo nmap -sn 10.129.2.0/24 --disable-arp-ping
    ```
2.  **Quick service enumeration**: Scan common ports of discovered hosts

    ```bash
    sudo nmap -sV 10.129.2.28 --top-ports 100
    ```
3.  **Thorough enumeration**: Full port scan with service detection

    ```bash
    sudo nmap -sV -p- 10.129.2.28 -oA full_scan
    ```
4.  **Targeted scanning**: Focus on specific services with specialized scripts

    ```bash
    sudo nmap -sV -p 445 10.129.2.28 --script=smb-*
    ```
5.  **OS detection**: Identify operating systems

    ```bash
    sudo nmap -O 10.129.2.28
    ```

By following a structured approach to network discovery, you can efficiently map a target environment and identify potential entry points for further testing.
