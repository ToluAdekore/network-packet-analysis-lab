
# 🛠️ Scenario 7 — SMB Lateral Movement (File Transfer)

This scenario simulates an attacker moving laterally in a Windows environment using **SMB**. The Red Team used **smbclient** to connect to a shared folder on a remote host and transfer files, while the Blue Team monitored the activity in **Wireshark**.

---

## 🧪 Red Team Activity

### 1. Connect to SMB Share

The attacker used valid credentials (`MalwareLab:Tolu2121!`) to connect to the victim's custom share (`TestShare`).

```bash
smbclient //192.168.2.129/TestShare -U 'MalwareLab!%Tolu2121'
```

📷 **Connection Established:**
![SMB Connect](./screenshots/Screenshot%202025-09-01%20140346.png)

---

### 2. Navigate and Upload a File

Once connected, the attacker navigated into the `dropbox` directory and uploaded a test file (`test.txt`) to simulate **tool transfer**.

```bash
put test.txt
ls
```

📷 **File Uploaded:**
![File Uploaded](./screenshots/Screenshot%202025-09-01%20135703.png)

📷 **File Visible in SMB Client:**
![File Listing](./screenshots/Screenshot%202025-09-01%20135645.png)

📷 **File Confirmed in Windows Explorer:**
![Windows Explorer](./screenshots/Screenshot%202025-09-01%20135633.png)

📷 **File Opened (Contents: lateral test):**
![File Opened](./screenshots/Screenshot%202025-09-01%20140500.png)

---

## 🟦 Blue Team Detection (Wireshark)

The Blue Team monitored network traffic with the following Wireshark filter:

```wireshark
smb2
```

Captured events showed:

- NTLMSSP Authentication (`Session Setup`)
- Tree Connect to `TestShare`
- File `CREATE` and `WRITE` operations (corresponding to `put test.txt`)

📷 **Wireshark Capture:**
![Wireshark SMB2](./screenshots/Screenshot%202025-09-01%20135729.png)

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Simulation |
|--------------|----------------|------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral movement via SMB share connection |
| T1570 | Lateral Tool Transfer | Uploading `test.txt` to victim machine via SMB |

---

## ✅ Outcome

- Red Team successfully connected to a remote SMB share using valid credentials.  
- Simulated lateral movement by transferring a file (`test.txt`) to the target host.  
- Blue Team observed SMB2 authentication, share access, and file write activity in Wireshark.  

This scenario demonstrates how attackers can leverage SMB for lateral movement and tool transfer, and how defenders can monitor these actions in network traffic.

---

## 📂 Screenshots

Place these files in a `/screenshots/` folder in your repo:

| File Name | Description |
|-----------|-------------|
| `Screenshot 2025-09-01 140346.png` | SMB client connected |
| `Screenshot 2025-09-01 135703.png` | File uploaded via smbclient |
| `Screenshot 2025-09-01 135645.png` | File visible in SMB client |
| `Screenshot 2025-09-01 135633.png` | File visible in Windows Explorer |
| `Screenshot 2025-09-01 140500.png` | File opened (contents visible) |
| `Screenshot 2025-09-01 135729.png` | Wireshark SMB2 capture |
