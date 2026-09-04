# Splunk Detection & Investigation Searches

This file contains the primary SPL searches used in the SOC Monitoring & Threat Detection lab. The searches are intended for alert triage, enrichment, investigation, correlation, and dashboarding.

## Base Search

```spl
index=main sourcetype=suricata
```

Use this as the starting point for Suricata telemetry in Splunk.

---

## 1. Total Suricata Events

```spl
index=main sourcetype=suricata
| stats count
```

**Purpose:** Measure the total volume of Suricata events in the selected time range.

---

## 2. Severity Distribution

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity IN ("Critical","High","Medium","Low")
| stats count by soc_severity
| sort - count
```

**Purpose:** Display the distribution of lookup-classified security alerts by SOC severity.

---

## 3. Critical Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="Critical"
| stats count
```

**Purpose:** Count Critical alerts for prioritization.

---

## 4. High Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="High"
| stats count
```

**Purpose:** Count High-severity alerts.

---

## 5. Medium Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="Medium"
| stats count
```

**Purpose:** Count Medium-severity alerts.

---

## 6. Low Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="Low"
| stats count
```

**Purpose:** Count Low-severity alerts.

---

## 7. Alert Category Distribution

```spl
index=main sourcetype=suricata
| eval category='alert.category'
| where isnotnull(category) AND category!=""
| stats count by category
| sort - count
```

**Purpose:** Show extracted Suricata alert categories while excluding events without a category.

---

## 8. Security Alert Timeline

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| timechart span=1h count by soc_severity
```

**Purpose:** Visualize classified security-alert activity over time.

---

## 9. Event Trend

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| timechart span=5m count
```

**Purpose:** Show short-interval changes in classified alert activity.

---

## 10. Top Attack Signatures

```spl
index=main sourcetype=suricata
| stats count by alert.signature
| sort - count
| head 10
```

**Purpose:** Identify the most frequently observed detection signatures.

---

## 11. Top Source Attackers

```spl
index=main sourcetype=suricata
| stats count by src_ip
| sort - count
| head 10
```

**Purpose:** Identify sources generating the most Suricata activity.

> High event volume does not by itself prove malicious activity. Validate the associated signatures and context before classifying a source as malicious.

---

## 12. Top Targeted Systems

```spl
index=main sourcetype=suricata
| stats count by dest_ip
| sort - count
| head 10
```

**Purpose:** Identify destination systems receiving the most observed activity.

---

## 13. Top Destination Ports

```spl
index=main sourcetype=suricata
| stats count by dest_port
| sort - count
| head 10
```

**Purpose:** Identify the destination services/ports most frequently associated with Suricata events.

---

## 14. Protocol Distribution

```spl
index=main sourcetype=suricata
| stats count by proto
| sort - count
```

**Purpose:** Summarize observed network protocols.

---

## 15. Events by Hour

```spl
index=main sourcetype=suricata
| bin _time span=1h
| stats count by _time
| sort _time
```

**Purpose:** Show event volume by hour.

---

## 16. Source / Destination Port Activity

```spl
index=main sourcetype=suricata
| stats count by src_ip dest_port
| sort - count
| head 20
```

**Purpose:** Highlight source-to-service activity and identify concentrated scanning or attack patterns.

---

## 17. Top Source / Destination Pairs

```spl
index=main sourcetype=suricata
| stats count by src_ip dest_ip
| sort - count
| head 20
```

**Purpose:** Identify frequently observed communication pairs for further investigation.

---

## 18. Latest Enriched Security Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| table _time alert.signature soc_severity cvss mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
| head 20
```

**Purpose:** Provide a concise analyst queue of the latest lookup-classified security alerts.

---

# Investigation Searches

## 19. Generic Enriched Alert Investigation

```spl
index=main sourcetype=suricata
| search alert.signature="<SIGNATURE>"
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| eval cvss=mvindex(cvss,0)
| eval cve=mvindex(cve,0)
| eval mitre_tactic=mvindex(mitre_tactic,0)
| eval mitre_technique=mvindex(mitre_technique,0)
| eval mitre_id=mvindex(mitre_id,0)
| eval threat_category=mvindex(threat_category,0)
| eval recommendation=mvindex(recommendation,0)
| eval src_ip=mvindex(src_ip,0)
| eval dest_ip=mvindex(dest_ip,0)
| eval dest_port=mvindex(dest_port,0)
| table _time alert.signature soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
```

**Purpose:** Standardize alert investigation and expose the enrichment needed for L1 triage.

## 20. Drupal SQL Injection — CVE-2014-3704

```spl
index=main sourcetype=suricata
| search alert.signature="*CVE-2014-3704*"
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| eval cvss=mvindex(cvss,0)
| eval cve=mvindex(cve,0)
| eval mitre_tactic=mvindex(mitre_tactic,0)
| eval mitre_technique=mvindex(mitre_technique,0)
| eval mitre_id=mvindex(mitre_id,0)
| eval threat_category=mvindex(threat_category,0)
| eval recommendation=mvindex(recommendation,0)
| eval src_ip=mvindex(src_ip,0)
| eval dest_ip=mvindex(dest_ip,0)
| eval dest_port=mvindex(dest_port,0)
| table _time alert.signature soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
```

**Expected classification:** Critical, CVSS 9.8, T1190, SQL Injection.

## 21. Cisco ASA / Firepower Path Traversal — CVE-2020-3452

```spl
index=main sourcetype=suricata
| search alert.signature="*CVE-2020-3452*"
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| eval cvss=mvindex(cvss,0)
| eval cve=mvindex(cve,0)
| eval mitre_tactic=mvindex(mitre_tactic,0)
| eval mitre_technique=mvindex(mitre_technique,0)
| eval mitre_id=mvindex(mitre_id,0)
| eval threat_category=mvindex(threat_category,0)
| eval recommendation=mvindex(recommendation,0)
| eval src_ip=mvindex(src_ip,0)
| eval dest_ip=mvindex(dest_ip,0)
| eval dest_port=mvindex(dest_port,0)
| table _time alert.signature soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
```

**Expected classification:** Critical, CVSS 9.8, T1190, Exploit Attempt.

## 22. Nmap Network Scanning

```spl
index=main sourcetype=suricata
| search alert.signature="*Nmap User-Agent Observed*"
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| eval cvss=mvindex(cvss,0)
| eval cve=mvindex(cve,0)
| eval mitre_tactic=mvindex(mitre_tactic,0)
| eval mitre_technique=mvindex(mitre_technique,0)
| eval mitre_id=mvindex(mitre_id,0)
| eval threat_category=mvindex(threat_category,0)
| eval recommendation=mvindex(recommendation,0)
| eval src_ip=mvindex(src_ip,0)
| eval dest_ip=mvindex(dest_ip,0)
| eval dest_port=mvindex(dest_port,0)
| table _time alert.signature soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
```

**Expected classification:** Medium, CVSS 5.3, T1046, Network Scan.

## 23. SSH Brute Force

```spl
index=main sourcetype=suricata
| search alert.signature="SOC DEMO - SSH Brute Force"
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| eval cvss=mvindex(cvss,0)
| eval cve=mvindex(cve,0)
| eval mitre_tactic=mvindex(mitre_tactic,0)
| eval mitre_technique=mvindex(mitre_technique,0)
| eval mitre_id=mvindex(mitre_id,0)
| eval threat_category=mvindex(threat_category,0)
| eval recommendation=mvindex(recommendation,0)
| eval src_ip=mvindex(src_ip,0)
| eval dest_ip=mvindex(dest_ip,0)
| eval dest_port=mvindex(dest_port,0)
| table _time alert.signature soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
```

**Expected classification:** Critical, CVSS 8.1, T1110, Credential Attack.

---

# Correlation Searches

## 24. Activity From a Source IP

```spl
index=main sourcetype=suricata
| search src_ip="<SOURCE_IP>"
| stats count by alert.signature dest_ip dest_port
| sort - count
```

**Purpose:** Determine what a source has targeted and whether multiple signatures are associated with it.

## 25. Activity Against a Destination IP

```spl
index=main sourcetype=suricata
| search dest_ip="<DESTINATION_IP>"
| stats count by alert.signature src_ip dest_port
| sort - count
```

**Purpose:** Determine whether a target is receiving activity from multiple sources or attack types.

---

## Time Range Guidance

For dashboard panels, use the Splunk dashboard **User time picker** so the panel follows the selected dashboard time range.

For historical investigation evidence, use a specific date range when the event occurred. For example, the SSH Brute Force lab events used for evidence occurred on **August 8, 2026**, so the investigation was run against that date.

## Analyst Notes

- A Suricata signature indicates detected network activity; it does not automatically prove successful compromise.
- Validate the source, destination, service, frequency, and surrounding events.
- Use lookup enrichment to prioritize and classify alerts.
- Correlate multiple events before escalating when possible.
- Treat response recommendations as triage guidance and follow the organization's authorization and incident-response procedures before containment actions.
