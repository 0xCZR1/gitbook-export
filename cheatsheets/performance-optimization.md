# Performance Optimization

## Performance Optimization

Optimizing the performance of scanning and enumeration tools is crucial to efficiently conduct security assessments. Proper optimization reduces scan time, minimizes network impact, and can help evade detection. This guide focuses on best practices for performance optimization across common security tools.

### Scan Performance Considerations

When planning and executing scans, consider these key factors:

1. **Production Impact**: High-intensity scans can negatively affect production systems
2. **Network Load**: Excessive packets may congest network infrastructure
3. **Detection Risk**: Aggressive scanning increases the chance of triggering security controls
4. **Time Constraints**: Assessment windows may be limited and require efficiency
5. **Target Resilience**: Some targets may be unable to handle aggressive scanning

### Nmap Performance Optimization

Nmap offers several parameters to control scan speed and resource usage:

#### RTT Timeouts

Round-Trip Time (RTT) affects how long Nmap waits for responses:

```bash
# Default scan
sudo nmap 10.129.2.0/24 -F

# Optimized RTT
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

The optimized scan can be significantly faster (as seen in the example below), but may miss some hosts:

```
Default:    256 IP addresses (10 hosts up) scanned in 39.44 seconds
Optimized:  256 IP addresses (8 hosts up) scanned in 12.29 seconds
```

#### Retry Rates

Controlling packet retries can dramatically speed up scans:

```bash
# Default retry behavior
sudo nmap 10.129.2.0/24 -F

# No retries
sudo nmap 10.129.2.0/24 -F --max-retries 0
```

Reducing retries sacrifices reliability for speed:

```
Default: 23 open ports found
No retries: 21 open ports found
```

#### Packet Rates

Setting packet transmission rates is extremely effective for increasing scan speed:

```bash
# Default scan
sudo nmap 10.129.2.0/24 -F -oN tnet.default

# Rate-optimized scan
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```

Impact on performance:

```
Default:   256 IP addresses scanned in 29.83 seconds
Optimized: 256 IP addresses scanned in 8.67 seconds
```

In this case, both scans found the same number of open ports (23), making this an effective optimization.

#### Timing Templates

Nmap provides six timing templates to simplify scan optimization:

* `-T 0` / `-T paranoid`: Extremely slow, used for IDS evasion
* `-T 1` / `-T sneaky`: Slow, also for IDS evasion
* `-T 2` / `-T polite`: Slows down to consume less bandwidth
* `-T 3` / `-T normal`: Default timing
* `-T 4` / `-T aggressive`: Faster scan assuming reliable network
* `-T 5` / `-T insane`: Extremely fast scan assuming very high bandwidth

Example usage:

```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

Results:

```
Default: 256 IP addresses scanned in 32.44 seconds
T5:      256 IP addresses scanned in 18.07 seconds
```

### Optimizing Web Application Scanning Tools

#### Gobuster Performance

```bash
# Increase threads (default: 10)
gobuster dir -u http://target.com -w wordlist.txt -t 50

# Filter out common response lengths to reduce false positives
gobuster dir -u http://target.com -w wordlist.txt --exclude-length 400-600
```

#### FFUF Performance

```bash
# Increase threads (default: 40)
ffuf -w wordlist.txt -u https://target.com/FUZZ -t 100

# Add delay between requests to avoid overloading the server
ffuf -w wordlist.txt -u https://target.com/FUZZ -p 0.1

# Use multiple wordlists efficiently
ffuf -w domains.txt:DOMAIN -w paths.txt:PATH -u https://DOMAIN/PATH
```

### Resource Management for Multi-Tool Scanning

When running multiple tools simultaneously:

1.  **CPU allocation**: Use `nice` to set process priorities

    ```bash
    nice -n 19 nmap -sV 10.129.2.0/24 &
    ```
2. **Memory management**: Monitor with `htop` and adjust tool parameters accordingly
3.  **Process scheduling**: Use `at` or `cron` to schedule scans during off-peak hours

    ```bash
    echo "nmap -sV 10.129.2.0/24 -oN scan.txt" | at 2am
    ```
4.  **Distributed scanning**: Split large scans across multiple machines

    ```bash
    # Machine 1
    nmap -sV 10.129.2.1-50

    # Machine 2
    nmap -sV 10.129.2.51-100
    ```

### Network Considerations

#### Bandwidth Management

```bash
# Use trickle to limit bandwidth
trickle -d 100 -u 100 nmap -sV 10.129.2.0/24
```

#### Connection Management

```bash
# Limit open connections with ulimit
ulimit -n 1024
```

### Target-Specific Optimizations

#### Adapting to Target Response Times

For targets with slow response times:

```bash
# Increase timeout for slow targets
nmap --max-rtt-timeout 500ms 10.129.2.100
```

For highly responsive targets:

```bash
# Decrease timeout for fast targets
nmap --max-rtt-timeout 100ms --min-rate 300 10.129.2.100
```

#### Scan Phasing

Break scans into phases for better performance:

1.  **Discovery phase**: Quick scan to find live hosts

    ```bash
    nmap -sn 10.129.2.0/24 --max-retries 1
    ```
2.  **Service phase**: Targeted scan on discovered hosts

    ```bash
    nmap -sV -F 10.129.2.1,5,10
    ```
3.  **Deep inspection phase**: Focused scans on specific services

    ```bash
    nmap -p 80 --script http-enum 10.129.2.1
    ```

### Balancing Stealth and Speed

Different scenarios require different performance profiles:

#### Fast Enumeration (Internal Testing)

```bash
# Maximum performance
nmap -T5 --min-rate 1000 -F 10.129.2.0/24
```

#### Stealth Enumeration (External Testing)

```bash
# Low and slow approach
nmap -T1 --max-retries 1 --randomize-hosts 10.129.2.0/24
```

#### Balanced Approach

```bash
# Good balance of speed and stealth
nmap -T3 --min-rate 100 --max-retries 2 10.129.2.0/24
```

### Performance Testing Methodology

To find the optimal settings for a given environment:

1. Start with conservative settings
2. Run a baseline scan and record time and results
3. Gradually increase performance parameters
4. Compare results between runs
5. Find the point where increased performance doesn't cause missing results

### Best Practices Summary

1. **Test your settings**: Ensure optimizations don't compromise necessary data
2. **Start conservatively**: Begin with lower speeds and increase gradually
3. **Know your target**: Adapt settings to the specific environment
4. **Monitor impact**: Watch for signs of network or target system stress
5. **Document approach**: Record successful optimization parameters for future use
6. **Layer your scans**: Start broad and light, then focus on areas of interest

By carefully managing scan performance, you can achieve the optimal balance between speed, comprehensive results, and minimal impact on target systems.
