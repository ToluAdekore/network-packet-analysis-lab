# 🧠 PCAP Review Checklist (Wireshark-Focused)

It’s designed to help you triage, analyze, and extract actionable insights from packet captures using **Wireshark + your brain**.

---

## 1️⃣ Define Objective Before Opening
- Clarify the **purpose** of the review (e.g., detect C2, check for exfil, hunt misconfigurations)
- Set a target: specific device, time window, IP range, or behavior to focus on

---

## 2️⃣ Initial Triage
- Open Wireshark → `Statistics ▸ Protocol Hierarchy`
- Use `Statistics ▸ Conversations` and `Endpoints` to:
  - Identify top talkers (IPs)
  - Spot high volume or long-duration flows
  - Note strange protocols or rare ports

---

## 3️⃣ Identify Suspicious Use Cases
Look for:
- Beaconing
- DNS tunneling
- C2 callbacks
- Data exfiltration
- Protocol abuse (ICMP, DNS, HTTP over weird ports)
- TLS downgrade or cert spoofing
- Port scanning / recon
- ARP spoofing

---

## 4️⃣ Layered Filtering Strategy
Start wide → get specific:
- General filter: `tcp || udp || icmp`
- Protocol filters: `dns`, `http`, `ftp`, `ssl`
- Behavioral filters:
  - Beaconing: `frame.time_delta_displayed > 30`
  - Long DNS: `dns.qry.name.len > 50`
  - TLS Certs: `ssl.handshake.type == 11`
  - POST data: `http.request.method == "POST"`
  - Obfuscation: `frame contains "base64"`

---

## 5️⃣ Follow Streams
- Right-click → "Follow TCP/UDP Stream"
- Look at payloads, headers, timing
- Document suspicious streams (frame #s, IPs, URIs, content)

---

## 6️⃣ Timing & Flow Analysis
- Use `frame.time_delta_displayed` to detect:
  - Repeated intervals (beacons)
  - Delays/latency outliers
- Use Wireshark's flow graph for visual inspection:
  - `Statistics ▸ Flow Graph`

---

## 7️⃣ Payload & Content Inspection
- HTTP:
  - Headers (Host, User-Agent, Referer)
  - URIs (long, encoded, strange paths)
  - POST bodies (login data, base64 blobs)
- DNS:
  - Suspicious subdomains or TXT records
- SMB/FTP:
  - File uploads, login attempts

---

## 8️⃣ TLS / Certificates
- Use filter: `ssl.handshake.type == 11`
- Check for:
  - Self-signed certs
  - Mismatched Common Name / SAN
  - Expired/invalid issuers

---

## 9️⃣ Recon & Scanning
- SYN scan: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
- NULL/FIN/XMAS scans: look for weird TCP flag combos
- High outbound fan-out to many IPs on similar ports
- DNS brute force (rapid queries to many subdomains)

---

## 🔟 Internal Traffic & Lateral Movement
- Look for:
  - RDP/SMB/FTP between internal IPs
  - Admin shares: `\\hostname\C$`
  - WMI/RPC traffic
  - ARP poisoning patterns (duplicate replies)

---

## 🔇 Suppress Noise
- Ignore:
  - Windows Update traffic
  - Legit DNS (common TLDs like `.com`, `.net`, etc.)
  - Common broadcast/multicast noise
- Focus on:
  - Rare domains
  - Non-browser user agents
  - Non-standard port usage

---

## 📌 Final Notes
For each analysis:
- Record filters used
- List IOCs: IPs, domains, URIs, certs
- Capture frame numbers of relevant packets
- Use screenshots if needed (Follow Stream, Payload view)

---

## 🧪 Quick Filter Reference

| Use Case               | Wireshark Filter                                |
|------------------------|--------------------------------------------------|
| C2 Beaconing           | `http.request.method == "POST"` + `frame.time_delta_displayed > 30` |
| DNS Exfiltration       | `dns && dns.qry.name.len > 50`                  |
| TLS Certificate Review | `ssl.handshake.type == 11`                      |
| SYN Scan               | `tcp.flags.syn == 1 && tcp.flags.ack == 0`      |
| Base64 Payloads        | `frame contains "base64"`                       |

---
**Used in:** [network-packet-analysis-lab](https://github.com/YOUR_USERNAME/network-packet-analysis-lab)
