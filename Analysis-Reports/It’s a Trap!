# Network Traffic Analysis Report  
**Date:** 2025-06-13  
**Scenario:** It’s a Trap!  
**Source:** malware-traffic-analysis.net  

---

## 1. Overview
This scenario contains malicious TLS-encrypted traffic that attempts to disguise itself as legitimate Cloudflare communication, along with suspicious domains acting as decoys. The objective is to identify beaconing patterns, domain infrastructure, and indicators of compromise (IOCs).

**Key Observations:**
- TLS handshake with fake Cloudflare domain.
- Suspicious domain names designed to appear legitimate.
- Possible C2 beaconing at regular intervals.

---

## 2. PCAP File
**Download:** [It’s a Trap! — PCAP](https://malware-traffic-analysis.net/2025/06/13/index.html)  
**File Type:** PCAP  
**Analysis Tool(s):** Wireshark, Zeek, tshark

---

## 3. Analysis Summary

### 3.1 Traffic Behavior
- **Protocol:** TLS over TCP
- **Destination IP(s):** _To be filled after analysis_
- **JA3/JA3S Fingerprint:** _To be filled after analysis_
- **Beaconing Pattern:** Regular interval handshake attempts (~X seconds apart).
- **Fake Domain Example:** `cf-secure-update[.]com` _(placeholder — replace with actual)_

### 3.2 TLS Certificate Details
- **Issuer CN:** _To be filled after analysis_
- **Subject CN:** Fake Cloudflare name.
- **Validity Period:** Short-lived (possible indicator of malicious use).

---

## 4. Indicators of Compromise (IOCs)
| Type | Value | Notes |
|------|-------|-------|
| Domain | _example.com_ | Fake Cloudflare decoy |
| IP Address | _X.X.X.X_ | Hosting suspicious TLS service |
| JA3 Fingerprint | _hash_ | Matches known malware family |

---

## 5. Detection & Mitigation
**Sigma/Snort/Suricata Rules:**
```text
alert tls any any -> any any (msg:"Suspicious TLS JA3 - Fake Cloudflare"; tls.sni; content:"cf-secure-update.com"; nocase; sid:100001;)
