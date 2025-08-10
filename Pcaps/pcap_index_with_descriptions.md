# 🕵️‍♂️ Network Traffic Analysis - Threat Scenario PCAP Index

Categorized PCAPs from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) with short descriptions for quick reference.


## 🔐 1. Command-and-Control (C2) Traffic
- [2025-06-13 — It’s a Trap!](https://www.malware-traffic-analysis.net/2025/06/13/index.html) — TLS handshake + fake Cloudflare decoy + suspicious domains
- [2023-04 — Cold as Ice (IcedID)](https://www.malware-traffic-analysis.net/2023/04/index.html) — C2 traffic using HTTPS with regular beaconing intervals
- [2024-11-26 — Nemotodes](https://www.malware-traffic-analysis.net/2024/11/26/index.html) — Likely contains malware beaconing with odd intervals
- [2023-07 — RedLine Stealer (Wireshark Quiz)](https://www.malware-traffic-analysis.net/2023/07/index.html) — RedLine C2 over HTTP/S + base64/hex-encoded blobs

## 📤 2. Data Exfiltration
- [2023-03 — Finding Gozi](https://www.malware-traffic-analysis.net/2023/03/index.html) — Exfiltration using HTTP POSTs + potential DNS abuse
- [2022-03-21 — Burnincandle](https://www.malware-traffic-analysis.net/2022/03/21/index.html) — Massive POST body size indicating possible data dump
- [2021-09-10 — Angry Poutine](https://www.malware-traffic-analysis.net/2021/09/10/index.html) — DNS tunneling traffic pattern with encoded TXT records

## 🧪 3. Protocol Misuse / Tunneling
- [2020-10-22 — Omegacast](https://www.malware-traffic-analysis.net/2020/10/22/index.html) — Non-standard HTTP GETs with payloads
- [2020-04-24 — Steelcoffee](https://www.malware-traffic-analysis.net/2020/04/24/index.html) — DNS-based covert data channels
- [2019-12-25 — Christmas Day](https://www.malware-traffic-analysis.net/2019/12/25/index.html) — TLS on ports other than 443 = tunneling

## 💥 4. Exploits / Payload Delivery
- [2025-01-22 — Fake Software Site](https://www.malware-traffic-analysis.net/2025/01/22/index.html) — Suspicious site delivering PE files (.exe)
- [2020-05-28 — Catbomber](https://www.malware-traffic-analysis.net/2020/05/28/index.html) — HTTP transfer of binaries + odd MIME types
- [2019-11-12 — Okay-Boomer](https://www.malware-traffic-analysis.net/2019/11/12/index.html) — Exploit kit-style traffic flow with redirects

## 🧑‍💻 5. Credential Theft / Info Stealers
- [2023-02 — Unit 42 Wireshark Quiz](https://www.malware-traffic-analysis.net/2023/02/index.html) — Cleartext basic auth seen in headers
- [2022-02-23 — Sunnystation](https://www.malware-traffic-analysis.net/2022/02/23/index.html) — Credentials passed via POST body (user/pass fields)
- [2018-12-18 — Eggnog Soup](https://www.malware-traffic-analysis.net/2018/12/18/index.html) — Formbook-style traffic pattern with credential theft

## 🧅 6. Man-in-the-Middle (MITM) Attacks
- [2020-08-04 — Pizza-Bender](https://www.malware-traffic-analysis.net/2020/08/04/index.html) — Certificate anomalies + fake TLS fingerprinting
- [2016-02-06 — Cupid's Arrow](https://www.malware-traffic-analysis.net/2016/02/06/index.html) — ARP spoofing indicators with duplicate replies
- [2015-07-11 — Pyndrine Industries](https://www.malware-traffic-analysis.net/2015/07/11/index.html) — Rogue DHCP and fake certificates

## 🌐 7. DNS Anomalies
- [2024-08-15 — WarmCookie](https://www.malware-traffic-analysis.net/2024/08/15/index.html) — Fast-flux domain resolution and DGA signs
- [2021-07-14 — Dualrunning](https://www.malware-traffic-analysis.net/2021/07/14/index.html) — Randomized subdomain queries resembling DGA
- [2018-09-27 — Blank Clipboard](https://www.malware-traffic-analysis.net/2018/09/27/index.html) — Multiple NXDOMAINs from repeated failed lookups

## 📈 8. Scanning & Reconnaissance
- [2020-03-14 — Mondogreek](https://www.malware-traffic-analysis.net/2020/03/14/index.html) — Masscan or Nmap-style SYN scans
- [2019-06-22 — Phenomenoc](https://www.malware-traffic-analysis.net/2019/06/22/index.html) — SMB enumeration traffic to internal shares
- [2017-03-25 — March Madness](https://www.malware-traffic-analysis.net/2017/03/25/index.html) — Multiple port scan types in sequence

## 🛜 9. Lateral Movement
- [2021-12-08 — ISC Contest](https://www.malware-traffic-analysis.net/2021/12/08/index.html) — Lateral SMB + RPC/WMI activity between hosts
- [2020-09-25 — Trouble Alert](https://www.malware-traffic-analysis.net/2020/09/25/index.html) — RDP sessions to internal IPs
- [2018-06-30 — Sorting Through the Alerts](https://www.malware-traffic-analysis.net/2018/06/30/index.html) — SMB brute-force to admin shares

## 📡 10. Suspicious Connections
- [2024-07-30 — You Dirty Rat](https://www.malware-traffic-analysis.net/2024/07/30/index.html) — Multiple C2 connections on strange ports
- [2020-01-30 — Sol-Lightnet](https://www.malware-traffic-analysis.net/2020/01/30/index.html) — Outbound Telnet + weird high-numbered ports
- [2017-12-15 — Two pcaps, two emails](https://www.malware-traffic-analysis.net/2017/12/15/index.html) — Old protocols + malware over SMTP/FTP
