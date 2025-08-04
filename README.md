
# 🧠 Curated PCAPs by Threat Type

This file organizes key PCAP exercises from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) according to specific threat detection categories in cybersecurity.

---

## 🕵️‍♂️ 1. Command-and-Control (C2) Traffic
Look for beaconing, POSTs with encoded payloads, suspicious subdomains:

- **2025-06-13 — It’s a Trap!**  
  *Focus: TLS + strange domains (fake Cloudflare decoy + C2 communication)*

- **2023-04 — Cold as Ice (IcedID)**  
  *Focus: IcedID uses HTTPS C2 with regular intervals*

- **2024-11-26 — Nemotodes**  
  *Likely includes malware families that beacon*

- **2023-07 — RedLine Stealer (Wireshark Quiz)**  
  *C2 over HTTP/HTTPS + encoded blobs*

---

## 📤 2. Data Exfiltration
Look for large outbound, DNS tunneling, POST blobs, FTP uploads:

- **2023-03 — Finding Gozi**  
  *Gozi often exfiltrates through POST + possible DNS*

- **2022-03-21 — Burnincandle**  
  *Features large HTTP POSTs and fake traffic volume*

- **2021-09-10 — Angry Poutine**  
  *DNS tunneling and custom exfiltration methods*

---

## 🧪 3. Protocol Misuse / Tunneling
DNS, ICMP tunnels, GET abuse, non-standard TLS:

- **2020-10-22 — Omegacast**  
  *Rare protocols and encoded HTTP GETs*

- **2020-04-24 — Steelcoffee**  
  *DNS used in odd ways*

- **2019-12-25 — Christmas Day**  
  *Known for exotic protocol use (check for TLS on port ≠ 443)*

---

## 💥 4. Exploits / Payload Delivery
Drive-by, PE headers in HTTP, exploit kits:

- **2025-01-22 — Fake Software Site**  
  *Likely includes PE file delivery*

- **2020-05-28 — Catbomber**  
  *Delivers executable via HTTP, suspicious response headers*

- **2019-11-12 — Okay-Boomer**  
  *Clear exploit chain and payload*

---

## 🧑‍💻 5. Credential Theft / Info Stealers
Cleartext logins, user/pass/hwid parameters:

- **2023-02 — Unit 42 Wireshark Quiz**  
  *Focus on basic auth and exposed creds*

- **2022-02-23 — Sunnystation**  
  *Login form POST parameters observed*

- **2018-12-18 — Eggnog Soup**  
  *Formbook-like credential theft traffic*

---

## 🧅 6. Man-in-the-Middle (MITM) Attacks
Self-signed certs, SSL stripping, ARP spoofing:

- **2020-08-04 — Pizza-Bender**  
  *TLS anomalies + possible MITM attempt*

- **2016-02-06 — Cupid's Arrow**  
  *Duplicate ARP traffic likely (classic MITM tell)*

- **2015-07-11 — Pyndrine Industries**  
  *Contains rogue DHCP + cert oddities*

---

## 🌐 7. DNS Anomalies
NXDOMAINs, fast-flux, DGA domains:

- **2024-08-15 — WarmCookie**  
  *Includes heavy DNS abuse*

- **2021-07-14 — Dualrunning**  
  *DGA-like DNS queries*

- **2018-09-27 — Blank Clipboard**  
  *NXDOMAIN floods*

---

## 📈 8. Scanning & Recon
SYN scans, XMAS/NULL, DNS brute force:

- **2020-03-14 — Mondogreek**  
  *Masscan/Nmap scan behavior*

- **2019-06-22 — Phenomenoc**  
  *SMB enumeration*

- **2017-03-25 — March Madness**  
  *Scan patterns observed*

---

## 🛜 9. Lateral Movement
SMB admin shares, RPC, WMI, RDP:

- **2021-12-08 — ISC Contest**  
  *Internal lateral movement patterns*

- **2020-09-25 — Trouble Alert**  
  *RDP between internal IPs*

- **2018-06-30 — Sorting Through the Alerts**  
  *SMB brute + internal recon*

---

## 📡 10. Suspicious Connections
TOR nodes, rare ports, obsolete protocols:

- **2024-07-30 — You Dirty Rat**  
  *Suspicious outbound to weird port + C2 fanout*

- **2020-01-30 — Sol-Lightnet**  
  *Telnet and weird port activity*

- **2017-12-15 — Two pcaps, two emails**  
  *Multiple threat types, including legacy protocols*
