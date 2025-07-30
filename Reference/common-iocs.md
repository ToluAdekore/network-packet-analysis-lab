# 🚩 Indicators of Compromise (IOCs) — Reference Guide

---

## 🧠 What Are IOCs?

Indicators of Compromise are **artifacts observed on a network or in an operating system** that strongly suggest a cyber threat has occurred. They provide security teams with actionable data to confirm or investigate a potential intrusion. :contentReference[oaicite:2]{index=2}

---

## 🔍 Why IOCs Matter

- Help detect if systems have been infiltrated  
- Enable security teams to build rules for detection and prevention  
---

## 🎯 Common Types of IOCs

Fortinet highlights these as the most frequent indicators:

### 🖧 Network-Based
- **Unusual outbound traffic**: unexpected destinations, bandwidth spikes  
- **Suspicious DNS queries**: odd domains, fast-flux TLDs, long TXT records

### 🧑‍💻 User/Account Behavior
- **Privileged account anomalies**: escalated privileges, unusual access patterns  
- **Login irregularities**: multiple failures, logins from unfamiliar geolocations 

### 🧩 File-Based & Host Artifacts
- **File hashes**, **malicious filenames**, **registry keys**, **malware signatures**  
- **C2 infrastructure DNS names** or **IPs associated with phishing** 

---

## ⚙️ Usage in Threat Hunting

- **Incident response teams** use IOCs post-intrusion to identify scope and impact  
- **Threat hunters** use IOCs proactively to scan historical logs and detect early compromise behaviors 

---

## 📊 IOC Examples Table

| IOC Type                       | Example Indicator                            | Detection Method                 |
|-------------------------------|----------------------------------------------|----------------------------------|
| Network-Based Traffic         | Unusual outbound traffic to C2 IP            | Traffic volume & destination logs |
| DNS Anomaly                   | Suspicious subdomain: `abcd1234.top`         | DNS queries length/entropy        |
| Privileged Account Use        | Admin login outside business hours           | Review login timestamps & locations |
| File/Hash Artifact            | `5d41402abc4b2a76b9719d911017c592` MD5 hash | Host-based intel/database lookup  |
| Credential Misuse             | Multiple failed logins for same user         | Security event logs               |

---

## 📌 Quick Reference Filters

If IOCs include domains or IPs, use summary display filters:
- `http.host contains "logitechupdate.com"`  
- `ip.dst == 185.XX.XX.XX`

---
