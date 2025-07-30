# 🧠 Network Packet Analysis Lab — Wireshark

This lab explores how to identify suspicious, malicious, or misconfigured behavior in packet captures using only **Wireshark** and **my brain**. Below are all the types of scenarios I look for and break down in this lab.

---

## 📦 SCENARIOS COVERED IN THIS LAB

---

### 🕵️‍♂️ 1. Command-and-Control (C2) Traffic
- Beaconing intervals (every X seconds)
- HTTP POSTs with encoded payloads
- Suspicious domains or subdomains (e.g. `logitech-update.xyz`)
- Fake TLS (non-browser JA3 fingerprints)

### 📤 2. Data Exfiltration
- Large outbound data with small inbound response
- DNS tunneling (`TXT`, long `A` records)
- HTTP POSTs with base64 or encrypted blobs
- FTP/SFTP uploads in cleartext or odd hours

### 🧪 3. Protocol Misuse / Tunneling
- ICMP tunnels (large `echo-request` payloads)
- DNS used for data transport
- HTTP GETs with long URIs containing hex, base64
- TLS being used on non-standard ports

### 💥 4. Exploits / Payload Delivery
- Drive-by download traffic
- HTTP response with PE headers (`MZ`, `.exe`)
- Malicious payloads embedded in SMB, RPC, or RDP
- Exploit kits: landing page + multiple redirects

### 🧑‍💻 5. Credential Theft / Info Stealers
- HTTP Basic Auth in cleartext
- Unencrypted login forms
- SMTP login brute force
- POSTs with parameter names like `user=`, `pass=`, `hwid=`

### 🧅 6. Man-in-the-Middle (MITM) Attacks
- TLS handshake anomalies (self-signed certs, unknown CAs)
- Downgrade from HTTPS to HTTP (SSL stripping)
- Duplicate ARP replies (ARP spoofing)
- Rogue DHCP servers

### 🌐 7. DNS Anomalies
- High volume of DNS queries to same domain
- Nonexistent TLDs (`.xyz`, `.top`, `.gq`)
- Repeated NXDOMAINs
- Fast-flux or DGA behavior

### 📈 8. Scanning & Recon
- SYN scans (`tcp.flags.syn == 1 && tcp.flags.ack == 0`)
- Null, XMAS, FIN scans
- DNS brute force / zone transfers
- SMB enumeration

### 🛜 9. Lateral Movement
- SMB traffic with admin share access
- WMI / RPC requests between endpoints
- RDP sessions not involving external IPs
- Internal DNS resolution for hostnames

### 📡 10. Suspicious Connections
- Connections to known threat IPs or TOR nodes
- High-volume outbound connections (C2 fanout)
- External connections on uncommon ports (e.g. TCP 2222)
- Obsolete or uncommon protocols (Telnet, TFTP, NetBIOS)

---

Each PCAP in this lab is documented with:
- Filters used  
- Key observations  
- Stream-by-stream breakdown  
- Indicators of compromise  
- Notes for detection logic or rule writing

---

**Tool used:** Wireshark  
**Mind used:** My brain  
**Source of PCAPs:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)

