# DNS Protocol

## DNS Protocol

The DNS (Domain Name System) is the backbone of the internet, functioning as the "phone book" of the web by resolving domain names to IP addresses.

### Common Ports

* 53 UDP - Standard DNS queries
* 53 TCP - Zone transfers and larger responses

### DNS Server Types

| **Server Type**                | **Description**                                                                                                        |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `DNS Root Server`              | Responsible for top-level domains (TLDs). There are 13 such root servers globally, coordinated by ICANN.               |
| `Authoritative Nameserver`     | Hold authority for particular zones and provide binding information for their areas of responsibility.                 |
| `Non-authoritative Nameserver` | Not responsible for particular DNS zones but collect information on DNS zones through recursive or iterative querying. |
| `Caching DNS Server`           | Cache information from other name servers for a specified period determined by the authoritative name server.          |
| `Forwarding Server`            | Simply forward DNS queries to another DNS server.                                                                      |
| `Resolver`                     | Perform name resolution locally in the computer or router.                                                             |

### DNS Configuration Examples

#### named.conf.options:

```
options {
        directory "/var/cache/bind";
        forwarders {
                8.8.8.8;
                8.8.4.4;
        };
        allow-query { any; };
        listen-on { any; };
};
```

#### named.conf.local

```
zone "czr.local" {
        type master;
        file "/etc/bind/czr.local";
};

zone "13.13.10.in-addr.arpa" {
        type master;
        file "/etc/bind/czr_reverse.local";
};
```

#### Zone File Example (czr.local):

```
$TTL    604800
@       IN      SOA     czr.local. root.czr.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.czr.local.
@       IN      A       10.13.13.11
@       IN      AAAA    ::1
ns      IN      A       10.13.13.11
www     IN      A       10.13.13.10
dev     IN      A       10.13.13.12
```

#### Reverse Zone Example (czr\_reverse.local):

```
$TTL    604800
@       IN      SOA     czr.local. root.czr.local. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.czr.local.
11      IN      PTR     ns.czr.local.
10      IN      PTR     www.czr.local.
12      IN      PTR     dev.czr.local.
```

### DNS Enumeration Tools

#### Dig Commands

```bash
# Query all DNS record types
dig any domain @IP

# Attempt zone transfer
dig axfr domain @IP

# Reverse DNS lookup
nslookup IP
```

### Attacking DNS

#### Zone Transfer

A DNS zone transfer is a type of DNS transaction used to replicate DNS databases across servers. If misconfigured, this can leak sensitive information.

```bash
# Attempt zone transfer with dig
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

# Using Fierce for zone transfer
fierce --domain zonetransfer.me
```

#### DNS Poisoning & MITM

DNS spoofing (cache poisoning) alters legitimate DNS records with false information to redirect traffic to malicious sites.

Using Ettercap for local DNS poisoning:

1.  Edit `/etc/ettercap/etter.dns`:

    ```
    inlanefreight.com      A   192.168.225.110*.inlanefreight.com    A   192.168.225.110
    ```
2. Activate `dns_spoof` plugin in Ettercap

#### Subdomain Enumeration

Before performing subdomain takeovers, enumerate existing subdomains:

```bash
# Using Subfinder
./subfinder -d inlanefreight.com -v

# Using Subbrute
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

#### Domain Takeover

When a CNAME record points to a service that's no longer active, an attacker can register that service and take control of the subdomain.

```bash
# Check for CNAME records
host support.inlanefreight.com
```

### Defending Against DNS Attacks

* Implement DNSSEC to verify DNS records
* Properly configure DNS servers to only allow zone transfers to authorized servers
* Regularly audit DNS configurations
* Use DNS monitoring to detect unusual patterns
* Keep DNS software updated to patch vulnerabilities
