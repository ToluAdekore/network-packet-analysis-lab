# 🕵️‍♂️ Network Traffic Analysis - Threat Scenario PCAP Index

This README provides a categorized index of PCAPs from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html) for hands-on practice in detecting various types of malicious network activity. These scenarios are ideal for SOC analyst training, malware traffic analysis, or home lab enrichment.

---

## 🔐 1. Command-and-Control (C2) Traffic

**Objective:** Identify beaconing, C2 POSTs, fake domains, and abnormal TLS usage.

- **2025-06-13 — It’s a Trap!**  
  *TLS handshake + fake Cloudflare decoy + suspicious domains*
- **2023-04 — Cold as Ice (IcedID)**  
  *C2 traffic using HTTPS with regular beaconing intervals*
- **2024-11-26 — Nemotodes**  
  *Likely contains malware beaconing with odd intervals*
- **2023-07 — RedLine Stealer (Wireshark Quiz)**  
  *RedLine C2 over HTTP/S + base64/hex-encoded blobs*

---

## 📤 2. Data Exfiltration

**Objective:** Detect data leaving the network via HTTP POST, DNS tunneling, or cleartext uploads.

- **2023-03 — Finding Gozi**  
  *Exfiltration using HTTP POSTs + potential DNS abuse*
- **2022-03-21 — Burnincandle**  
  *Massive POST body size indicating possible data dump*
- **2021-09-10 — Angry Poutine**  
  *DNS tunneling traffic pattern with encoded TXT records*

---

## 🧪 3. Protocol Misuse / Tunneling

**Objective:** Spot abuse of ICMP, DNS, HTTP, or TLS for covert channels.

- **2020-10-22 — Omegacast**  
  *Non-standard HTTP GETs with payloads*
- **2020-04-24 — Steelcoffee**  
  *DNS-based covert data channels*
- **2019-12-25 — Christmas Day**  
  *TLS on ports other than 443 = tunneling*

---

## 💥 4. Exploits / Payload Delivery

**Objective:** Detect drive-by attacks, malware downloads, and PE headers in HTTP.

- **2025-01-22 — Fake Software Site**  
  *Suspicious site delivering PE files (.exe)*
- **2020-05-28 — Catbomber**  
  *HTTP transfer of binaries + odd MIME types*
- **2019-11-12 — Okay-Boomer**  
  *Exploit kit-style traffic flow with redirects*

---

## 🧑‍💻 5. Credential Theft / Info Stealers

**Objective:** Identify cleartext credentials, form submissions, and suspicious POST parameters.

- **2023-02 — Unit 42 Wireshark Quiz**  
  *Cleartext basic auth seen in headers*
- **2022-02-23 — Sunnystation**  
  *Credentials passed via POST body (user/pass fields)*
- **2018-12-18 — Eggnog Soup**  
  *Formbook-style traffic pattern with credential theft*

---

## 🧅 6. Man-in-the-Middle (MITM) Attacks

**Objective:** Spot spoofing attempts, rogue devices, and downgraded encryption.

- **2020-08-04 — Pizza-Bender**  
  *Certificate anomalies + fake TLS fingerprinting*
- **2016-02-06 — Cupid's Arrow**  
  *ARP spoofing indicators with duplicate replies*
- **2015-07-11 — Pyndrine Industries**  
  *Rogue DHCP and fake certificates*

---

## 🌐 7. DNS Anomalies

**Objective:** Detect DGAs, DNS floods, and failed lookups.

- **2024-08-15 — WarmCookie**  
  *Fast-flux domain resolution and DGA signs*
- **2021-07-14 — Dualrunning**  
  *Randomized subdomain queries resembling DGA*
- **2018-09-27 — Blank Clipboard**  
  *Multiple NXDOMAINs from repeated failed lookups*

---

## 📈 8. Scanning & Reconnaissance

**Objective:** Spot recon attempts using common scanning tools.

- **2020-03-14 — Mondogreek**  
  *Masscan or Nmap-style SYN scans*
- **2019-06-22 — Phenomenoc**  
  *SMB enumeration traffic to internal shares*
- **2017-03-25 — March Madness**  
  *Multiple port scan types in sequence*

---

## 🛜 9. Lateral Movement

**Objective:** Identify unauthorized access within a local network.

- **2021-12-08 — ISC Contest**  
  *Lateral SMB + RPC/WMI activity between hosts*
- **2020-09-25 — Trouble Alert**  
  *RDP sessions to internal IPs*
- **2018-06-30 — Sorting Through the Alerts**  
  *SMB brute-force to admin shares*

---

## 📡 10. Suspicious Connections

**Objective:** Detect outbound connections to suspicious hosts or unusual protocols.

- **2024-07-30 — You Dirty Rat**  
  *Multiple C2 connections on strange ports*
- **2020-01-30 — Sol-Lightnet**  
  *Outbound Telnet + weird high-numbered ports*
- **2017-12-15 — Two pcaps, two emails**  
  *Old protocols + malware over SMTP/FTP*

---

## 📁 Usage

You can create folders such as:

- `Pcaps/` – Place the downloaded `.pcap` files here.
- `Checklist/` – Add YAML or markdown checklists to track what you've detected in each.
- `Reference/` – Include notes, extracted IOCs, or decoded payloads.

Use Wireshark, Zeek, or tshark to inspect each scenario and develop detection skills.

---

