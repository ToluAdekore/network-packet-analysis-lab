# 🕵️‍♂️ Network Traffic Analysis Report — *It's a Trap!* (2025-06-13)

## Objective
Analyze the `2025-06-13-traffic-analysis-exercise.pcap` to identify suspicious network activity, determine if C2 or malicious infrastructure is involved, and document findings.

---

## Tools & Wireshark Profiles Used

During analysis, three custom Wireshark profiles were used to progressively reveal details:

### **1. Basic Profile**
- **Purpose:** Minimal view for quickly spotting key conversations and packet flow.
- **Setup:** Shows standard columns (No., Time, Source, Destination, Protocol, Length, Info).
- **Usage in this case:**
  - Allowed me to quickly spot multiple short-lived TLS sessions from the suspected victim host (`10.6.13.133`) to various external IPs over port 443.
  - Helped identify repeated small packet sizes indicative of possible beaconing or initial TLS handshakes.

### **2. Basic+ Profile**
- **Purpose:** Adds more context to encrypted traffic.
- **Extra Columns:** Host (HTTP), SNI (TLS Server Name Indication).
- **Usage in this case:**
  - Revealed the **SNI field** in TLS Client Hello packets.
  - Showed repeated connections to domains **mimicking Cloudflare infrastructure** but not resolving to legitimate Cloudflare IP ranges.
  - This discrepancy raised suspicion of a **fake Cloudflare decoy** — a known tactic where attackers use familiar infrastructure names to trick analysts or hide C2 endpoints.

### **3. Basic+DNS Profile**
- **Purpose:** Adds DNS query/response details to identify suspicious or fake domains.
- **Extra Columns:** DNS Query Name (`dns.qry.name`), JA3/JA3S fingerprints.
- **Usage in this case:**
  - Mapped suspicious SNI values to **prior DNS lookups** made by the victim host.
  - Detected domains with no legitimate WHOIS history and potentially recent registration.
  - Cross-referenced suspicious TLS handshake destinations with DNS requests to confirm they were **directly resolved by the victim host** (not proxy traffic).

---

## Key Indicators Found

1. **TLS Handshake Patterns:**
   - Multiple **Client Hello** packets to suspicious domains.
   - All connections were short-lived with minimal data transfer, suggesting initial beaconing or staged C2 setup.

2. **Fake Cloudflare Decoy:**
   - Domains contained patterns or subdomains mimicking Cloudflare (e.g., `cdn-<random>.cloudflare.com`) but resolved to IPs outside Cloudflare’s ASNs.
   - SNI values looked legitimate but IP WHOIS and threat intel checks indicated attacker-controlled hosting.

3. **Suspicious Domains:**
   - Domains revealed through DNS queries and SNI inspection had no established reputation or history.
   - Likely part of attacker infrastructure for initial compromise or C2.

---

## Conclusion
By moving from **Basic → Basic+ → Basic+DNS** profiles, I was able to:
1. **Basic:** Spot encrypted traffic patterns worth investigating.
2. **Basic+:** Identify suspicious TLS handshake SNI values and mimicry of Cloudflare infrastructure.
3. **Basic+DNS:** Correlate SNI values with DNS queries to confirm suspicious domain resolution.

This layered approach ensured I could detect and confirm the presence of **TLS handshake attempts to a fake Cloudflare decoy** and document the suspicious domains involved.

---

## Next Steps
- Extract all suspicious domains and IPs for IOC sharing.
- Run threat intel enrichment (WHOIS, passive DNS, reputation checks).
- Investigate potential payload delivery or C2 activity from these endpoints.

