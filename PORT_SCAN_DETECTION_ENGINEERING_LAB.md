# Port Scan Detection Engineering Lab

## Objective
Simulate multiple Nmap reconnaissance techniques from a Kali host and engineer SIEM detections (Splunk and ELK) that:
1. Detect common scan behaviors.
2. Classify likely scan type.
3. Reduce false positives with practical tuning.

---

## Lab Topology

- **Attacker**: Kali Linux with `nmap`
- **Targets**: One or more Linux/Windows hosts in a lab subnet
- **Telemetry sources** (recommended):
  - Firewall logs (allow/deny + src/dst/port/proto)
  - Network sensor logs (Zeek/Suricata if available)
  - Host logs (Sysmon, auditd)
- **SIEM**: Splunk **or** ELK (queries for both provided)

Example subnet:
- Kali: `192.168.56.10`
- Targets: `192.168.56.0/24`

> Use only systems you own or are explicitly authorized to test.

---

## Phase 1: Generate Recon Traffic with Nmap

Run each scan separately first, then mix scans to emulate realistic attacker behavior.

### 1) Host discovery (ping sweep)
```bash
nmap -sn 192.168.56.0/24
```

### 2) TCP SYN scan (half-open)
```bash
nmap -sS -p 1-1024 192.168.56.20
```

### 3) TCP connect scan
```bash
nmap -sT -p 1-1024 192.168.56.20
```

### 4) UDP scan
```bash
nmap -sU -p 53,67,68,69,123,137,161,500 192.168.56.20
```

### 5) Service/version discovery
```bash
nmap -sV -p 22,80,443,3389 192.168.56.20
```

### 6) Aggressive timing (noisy)
```bash
nmap -sS -T4 -p- 192.168.56.20
```

### 7) Stealthy timing (slow)
```bash
nmap -sS -T1 -p 1-1024 192.168.56.20
```

### 8) FIN/NULL/XMAS scans (evasion-style)
```bash
nmap -sF 192.168.56.20
nmap -sN 192.168.56.20
nmap -sX 192.168.56.20
```

### 9) Decoy scan
```bash
nmap -sS -D RND:5 192.168.56.20
```

### 10) Fragmented packets
```bash
nmap -sS -f 192.168.56.20
```

---

## Phase 2: Data Normalization (Field Mapping)

Map your SIEM fields to this logical schema:
- `src_ip`
- `dest_ip`
- `dest_port`
- `proto`
- `action` (allow/deny/reset)
- `event_time`
- `tcp_flags` (if available)
- `sensor` or `log_source`

Detection quality depends on good normalization.

---

## Phase 3: Splunk Detection Queries

Assume index/sourcetype are already selected for network/firewall events.

### A. Horizontal scan (one source probing many hosts on same port)
```spl
index=network_logs action=allowed
| bin _time span=5m
| stats dc(dest_ip) as unique_hosts values(dest_ip) as host_list count by _time src_ip dest_port proto
| where unique_hosts >= 15 AND count >= 20
| eval detection="Horizontal Port Scan"
| sort - _time
```

### B. Vertical scan (one source probing many ports on one host)
```spl
index=network_logs action=allowed
| bin _time span=5m
| stats dc(dest_port) as unique_ports values(dest_port) as port_list count by _time src_ip dest_ip proto
| where unique_ports >= 20 AND count >= 25
| eval detection="Vertical Port Scan"
| sort - _time
```

### C. TCP SYN scan heuristic
```spl
index=network_logs proto=tcp
| bin _time span=5m
| stats count as total_events
        sum(eval(match(tcp_flags,"S") AND NOT match(tcp_flags,"A"))) as syn_only
        sum(eval(match(tcp_flags,"R"))) as resets
        by _time src_ip dest_ip
| eval syn_ratio=round((syn_only/total_events)*100,2)
| where total_events >= 40 AND syn_ratio >= 70
| eval detection="Likely SYN Scan"
| sort - _time
```

### D. UDP scan heuristic (many UDP ports, low response context)
```spl
index=network_logs proto=udp
| bin _time span=10m
| stats dc(dest_port) as unique_udp_ports count by _time src_ip dest_ip
| where unique_udp_ports >= 15 AND count >= 20
| eval detection="Likely UDP Scan"
| sort - _time
```

### E. Slow scan (low-and-slow over longer interval)
```spl
index=network_logs proto=tcp action=allowed
| bin _time span=1h
| stats dc(dest_port) as unique_ports count by _time src_ip dest_ip
| where unique_ports >= 30 AND count < 200
| eval detection="Potential Slow Port Scan"
| sort - _time
```

---

## Phase 4: ELK / Kibana KQL + ES|QL Detections

> Use your data view (e.g., `logs-network-*`) and mapped fields (`source.ip`, `destination.ip`, `destination.port`, `network.transport`, `event.action`, `tcp.flags`).

### A. KQL pre-filter for suspicious scan traffic
```kql
network.transport: tcp and event.action: (allow or allowed or accept)
```

### B. ES|QL - Horizontal scan
```esql
FROM logs-network-*
| WHERE @timestamp >= NOW() - 5 minutes
| STATS unique_hosts = COUNT_DISTINCT(destination.ip),
        attempts = COUNT(*)
  BY source.ip, destination.port, network.transport
| WHERE unique_hosts >= 15 AND attempts >= 20
| SORT attempts DESC
```

### C. ES|QL - Vertical scan
```esql
FROM logs-network-*
| WHERE @timestamp >= NOW() - 5 minutes
| STATS unique_ports = COUNT_DISTINCT(destination.port),
        attempts = COUNT(*)
  BY source.ip, destination.ip, network.transport
| WHERE unique_ports >= 20 AND attempts >= 25
| SORT unique_ports DESC
```

### D. ES|QL - UDP scan
```esql
FROM logs-network-*
| WHERE @timestamp >= NOW() - 10 minutes AND network.transport == "udp"
| STATS unique_udp_ports = COUNT_DISTINCT(destination.port),
        attempts = COUNT(*)
  BY source.ip, destination.ip
| WHERE unique_udp_ports >= 15 AND attempts >= 20
| SORT unique_udp_ports DESC
```

### E. ES|QL - Slow scan (hour bucket)
```esql
FROM logs-network-*
| WHERE @timestamp >= NOW() - 24 hours AND network.transport == "tcp"
| EVAL hour_bucket = DATE_TRUNC(1 hour, @timestamp)
| STATS unique_ports = COUNT_DISTINCT(destination.port),
        attempts = COUNT(*)
  BY hour_bucket, source.ip, destination.ip
| WHERE unique_ports >= 30 AND attempts < 200
| SORT hour_bucket DESC
```

---

## Phase 5: False Positive Reduction Strategy

Apply these controls to reduce noisy alerts:

1. **Asset allowlist**
   - Exclude known scanners and management tools (vulnerability scanners, monitoring servers, patch tools).
   - Keep allowlist in lookup/index and reference it in every detection.

2. **Role-aware thresholds**
   - Different thresholds for user VLANs vs server VLANs vs DMZ.
   - Example: scanning 10 hosts in user subnet may be suspicious; in scanner subnet may be normal.

3. **Time-of-day profiles**
   - Lower severity during approved maintenance windows.
   - Raise severity for after-hours scanning from workstations.

4. **Protocol-specific baselining**
   - DNS/NTP-heavy systems can look like scans if not profiled.
   - Build baseline counts of unique ports/hosts per source role.

5. **Multi-signal correlation**
   - Raise confidence when scan behavior + threat intel match + authentication anomalies occur.
   - Reduce severity when only one weak indicator appears.

6. **Deduplication / suppression**
   - Suppress repeat alerts for same `src_ip -> dest_scope` for a cooling period (e.g., 30 min).

7. **Confidence scoring**
   - Example scoring:
     - +30 if `unique_ports >= 50`
     - +20 if `unique_hosts >= 25`
     - +20 if SYN ratio > 80%
     - +30 if source is workstation segment
   - Alert only when score >= 60.

---

## Phase 6: Validation Plan

For each detection rule:
1. Run one Nmap technique.
2. Verify alert triggers within expected window.
3. Capture event sample and rule output.
4. Run benign admin/network activity (known good).
5. Confirm rule does not trigger or triggers lower-severity result.
6. Tune thresholds and repeat.

Track:
- True Positives (TP)
- False Positives (FP)
- False Negatives (FN)
- Mean time to detect (MTTD)

---


## Phase 7: Example Output (What You Should See)

Below are representative outputs to help you validate that your scans and detections are working.

### A) Nmap Host Discovery (`-sn`) sample
```text
Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-23 13:10 UTC
Nmap scan report for 192.168.56.1
Host is up (0.0012s latency).
Nmap scan report for 192.168.56.20
Host is up (0.00092s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 3.15 seconds
```

### B) Nmap SYN scan (`-sS`) sample
```text
Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-23 13:12 UTC
Nmap scan report for 192.168.56.20
Host is up (0.00074s latency).
Not shown: 1019 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 1.88 seconds
```

### C) Nmap UDP scan (`-sU`) sample
```text
Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-23 13:15 UTC
Nmap scan report for 192.168.56.20
Host is up (0.00099s latency).
PORT    STATE         SERVICE
53/udp  open          domain
67/udp  closed        dhcps
68/udp  closed        dhcpc
123/udp open|filtered ntp
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 12.40 seconds
```

### D) Splunk result table sample (Vertical scan query)
```text
_time                src_ip          dest_ip         proto  unique_ports  count  detection
2026-02-23 13:15:00  192.168.56.10   192.168.56.20   tcp    64            71     Vertical Port Scan
```

### E) ELK ES|QL result sample (Horizontal scan query)
```text
source.ip      destination.port  network.transport  unique_hosts  attempts
192.168.56.10  445               tcp                26            41
```

### F) Slow scan alert sample (low-and-slow)
```text
hour_bucket           source.ip       destination.ip    unique_ports  attempts  finding
2026-02-23T13:00:00Z  192.168.56.10   192.168.56.20     37            58        Potential Slow Port Scan
```

> If your output differs slightly (timings, number of closed ports, service labels), that is normal. Focus on pattern similarity and threshold crossing behavior.

---

## Deliverables Checklist

- [ ] Nmap command log with timestamps.
- [ ] SIEM query pack (Splunk and/or ELK).
- [ ] Threshold rationale per detection.
- [ ] False-positive tuning notes.
- [ ] Final detection runbook (triage steps + response actions).

---

## Optional Enhancements

- Add Zeek signatures for scan patterns.
- Detect decoy scans by identifying distributed low-volume probes with synchronized timing.
- Add MITRE ATT&CK mapping (`T1595 Active Scanning`).
- Build dashboard panels:
  - Top scanning sources
  - Ports most targeted
  - Scan activity trend by hour
  - Internal vs external scan origin

