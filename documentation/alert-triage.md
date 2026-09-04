# SOC Alert Triage Cases

This document demonstrates a SOC L1-style alert triage workflow using Suricata detections enriched in Splunk with severity, CVSS, MITRE ATT&CK mapping, threat category, and response recommendations.

## Triage Workflow

**Detect → Validate → Investigate → Classify → Map → Recommend → Document**

For each alert, the analyst validates the detection, reviews the source and destination context, assesses severity, maps the activity to MITRE ATT&CK, and records an appropriate next action.

---

## Case 1 — Drupal SQL Injection Attempt

**Detection:** `ET EXPLOIT Possible CVE-2014-3704 Drupal SQLi attempt URLENCODE 1`

| Field | Assessment |
|---|---|
| Severity | Critical |
| CVSS | 9.8 |
| CVE | CVE-2014-3704 |
| MITRE Tactic | Initial Access |
| MITRE Technique | Exploit Public-Facing Application |
| MITRE ID | T1190 |
| Threat Category | SQL Injection |
| Recommended Action | Investigate web server |

### Analyst Assessment

The alert indicates an attempted SQL injection against a Drupal application. The Critical severity and CVSS 9.8 rating warrant immediate investigation of the targeted web server and associated application logs.

### L1 Investigation

1. Validate the alert signature and timestamp.
2. Identify the source and destination IP addresses.
3. Confirm the destination service and port.
4. Review web-server and application logs around the event.
5. Determine whether the request resulted in successful exploitation.
6. Escalate if evidence of compromise is identified.

---

## Case 2 — Cisco ASA / Firepower Path Traversal

**Detection:** `ET EXPLOIT Cisco ASA and Firepower Path Traversal Vulnerability M1 (CVE-2020-3452)` and related CVE-2020-3452 detection activity.

| Field | Assessment |
|---|---|
| Severity | Critical |
| CVSS | 9.8 |
| CVE | CVE-2020-3452 |
| MITRE Tactic | Initial Access |
| MITRE Technique | Exploit Public-Facing Application |
| MITRE ID | T1190 |
| Threat Category | Exploit Attempt |
| Recommended Action | Investigate affected device |

### Analyst Assessment

The detection indicates an attempted path traversal / unauthenticated file-read attack against Cisco ASA or Firepower infrastructure. The Critical severity requires validation of the affected device and investigation for evidence of successful exploitation.

### L1 Investigation

1. Validate the affected source and destination.
2. Confirm that the destination is a Cisco ASA/Firepower device.
3. Review firewall and device logs around the alert timestamp.
4. Search for repeated attempts from the same source.
5. Determine whether sensitive files or configuration data were accessed.
6. Escalate confirmed or suspected compromise.

---

## Case 3 — Nmap Network Scanning

**Detection:** `ET SCAN Possible Nmap User-Agent Observed`

| Field | Assessment |
|---|---|
| Severity | Medium |
| CVSS | 5.3 |
| CVE | N/A |
| MITRE Tactic | Discovery |
| MITRE Technique | Network Service Discovery |
| MITRE ID | T1046 |
| Threat Category | Network Scan |
| Recommended Action | Investigate scanning activity |

### Analyst Assessment

The alert indicates activity associated with Nmap-based network service discovery. This may represent authorized security testing or reconnaissance preceding an attack, so the analyst should establish whether the source is expected or unauthorized.

### L1 Investigation

1. Identify the source IP and targeted systems.
2. Review the destination ports and services contacted.
3. Determine whether the source belongs to an authorized scanner or administrator.
4. Check for additional scanning signatures from the same source.
5. Correlate the activity with other alerts in Splunk.
6. Escalate suspicious or unauthorized reconnaissance.

---

## Case 4 — SSH Brute Force

**Detection:** `SOC DEMO - SSH Brute Force`

| Field | Assessment |
|---|---|
| Severity | Critical |
| CVSS | 8.1 |
| CVE | N/A |
| MITRE Tactic | Credential Access |
| MITRE Technique | Brute Force |
| MITRE ID | T1110 |
| Threat Category | Credential Attack |
| Recommended Action | Investigate authentication logs and block source if malicious |

### Observed Context

The investigated events show source `192.168.1.16` targeting `192.168.1.11` over destination port `22`. The events are enriched as Critical severity and mapped to MITRE ATT&CK T1110 (Brute Force).

### Analyst Assessment

The detection represents repeated SSH brute-force activity. The analyst should determine whether the source is authorized, review authentication failures and successful logins, and assess whether the target account or host was compromised.

### L1 Investigation

1. Identify the source and destination systems.
2. Review SSH authentication logs for failed and successful attempts.
3. Check whether a successful login followed the brute-force activity.
4. Identify the targeted username(s), where available.
5. Correlate the source IP with other security alerts.
6. Block or contain the source if malicious and authorized by the incident-response process.
7. Escalate if successful authentication or compromise is suspected.

---

## Evidence

Detailed investigation evidence is stored in the repository `screenshots/` directory, including Splunk dashboard views and alert-investigation results.

## SOC L1 Skills Demonstrated

- SIEM-based alert investigation
- Suricata alert validation
- Lookup-based alert enrichment
- Severity and CVSS assessment
- MITRE ATT&CK mapping
- Source/destination analysis
- Network reconnaissance analysis
- Exploit-attempt triage
- Credential-attack triage
- Incident escalation and response recommendations
