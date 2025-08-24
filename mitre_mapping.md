# 📊 MITRE ATT&CK Mapping

This document maps each lab scenario to relevant **MITRE ATT&CK techniques** to demonstrate adversary behaviors and defensive detections.

---

## ✅ Scenario 1 — Reverse Shell Delivery & Execution
- **Technique ID:** T1105
- **Name:** Ingress Tool Transfer
- **Description:** Adversaries deliver malicious files (payload.exe) to the victim over HTTP.
- **Detection:** Network monitoring for suspicious HTTP file downloads (e.g., `.exe` over cleartext).

---

## ✅ Scenario 2 — Data Exfiltration via HTTP
- **Technique ID:** T1041
- **Name:** Exfiltration Over C2 Channel
- **Description:** Sensitive data exfiltrated using standard web traffic (HTTP GET/POST).
- **Detection:** Large/suspicious outbound transfers, especially to attacker-controlled IPs.

---

## ✅ Scenario 3 — Credential Harvesting (Simulated)
- **Technique ID:** T1003
- **Name:** OS Credential Dumping
- **Description:** Credential data harvested and sent outbound via POST requests.
- **Detection:** Look for unusual authentication patterns, encoded strings in outbound requests.

---

## ✅ Scenario 4 — Beaconing Behavior (C2 Heartbeats)
- **Technique ID:** T1071.001
- **Name:** Application Layer Protocol: Web Protocols
- **Description:** Malware beaconing to attacker-controlled server at regular intervals.
- **Detection:** Network traffic with repetitive timing patterns and no user activity.

---

## ✅ Scenario 5 — File Transfer via FTP
- **Technique ID:** T1048
- **Name:** Exfiltration Over Alternative Protocol
- **Description:** Data transferred to attacker infrastructure using FTP.
- **Detection:** Monitor cleartext FTP traffic, unusual file uploads, and credential exposure.

---

# 📌 Summary Table
| Scenario | Technique ID | Name |
|----------|--------------|------|
| Reverse Shell Delivery | T1105 | Ingress Tool Transfer |
| Data Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Credential Harvesting | T1003 | OS Credential Dumping |
| Beaconing | T1071.001 | Application Layer Protocol: Web Protocols |
| FTP Exfiltration | T1048 | Exfiltration Over Alternative Protocol |

