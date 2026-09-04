# Splunk SOC Dashboard

## Dashboard Purpose

The **SOC Monitoring & Threat Detection** dashboard provides a centralized view of Suricata security telemetry ingested into Splunk. It is designed to support SOC L1 monitoring, alert triage, threat classification, and investigation.

Primary data source:

```spl
index=main sourcetype=suricata
```

The dashboard uses the `suricata_threat_lookup.csv` lookup to enrich detected signatures with SOC severity, CVSS, CVE, MITRE ATT&CK information, threat category, and analyst recommendation.

---

## Dashboard Configuration

- **Dashboard name:** SOC Monitoring & Threat Detection
- **Data source:** Suricata EVE JSON
- **Splunk index:** `main`
- **Sourcetype:** `suricata`
- **Default time range:** Last 24 hours
- **Auto-refresh:** 30 seconds
- **Panel time range:** User time picker

### Time Picker Requirement

Dashboard panels must use the **User time picker** rather than a hard-coded time range. This allows the same dashboard to analyze recent activity or historical investigation windows without changing every panel individually.

Recommended workflow:

1. Open the dashboard.
2. Select the required time range from the global time picker.
3. Ensure each panel is configured to use the user-selected time range.
4. Refresh or wait for the configured auto-refresh interval.

---

## Dashboard Panels

### 1. Total Events

**SPL:**

```spl
index=main sourcetype=suricata
| stats count
```

**Visualization:** Single Value

**Purpose:** Displays the total number of Suricata events within the selected time range.

---

### 2. Critical Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="Critical"
| stats count
```

**Visualization:** Single Value

**Purpose:** Highlights alerts classified as Critical by the SOC threat lookup.

---

### 3. High Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="High"
| stats count
```

**Visualization:** Single Value

**Purpose:** Shows High-severity detections requiring analyst attention.

---

### 4. Medium Alerts

Uses the same lookup enrichment and filters for `soc_severity="Medium"`.

**Visualization:** Single Value

**Purpose:** Provides visibility into medium-priority security activity.

---

### 5. Low Alerts

Uses the same lookup enrichment and filters for `soc_severity="Low"`.

**Visualization:** Single Value

**Purpose:** Shows lower-priority detections that may require monitoring or contextual investigation.

---

## Severity & Threat Overview

### 6. Severity Distribution

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity IN ("Critical","High","Medium","Low")
| stats count by soc_severity
| sort - count
```

**Visualization:** Column/Bar Chart

**Purpose:** Compares the volume of alerts across SOC severity levels.

---

### 7. Alert Categories

```spl
index=main sourcetype=suricata
| eval category='alert.category'
| where isnotnull(category) AND category!=""
| stats count by category
| sort - count
```

**Visualization:** Bar Chart

**Purpose:** Identifies the major Suricata alert categories represented in the environment.

---

### 8. Alert Activity by Attack Type

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity threat_category mitre_tactic mitre_technique mitre_id
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| stats count by threat_category
| sort - count
```

**Visualization:** Bar Chart

**Purpose:** Groups enriched detections into investigation-oriented threat categories.

---

## Timeline & Activity Panels

### 9. Event Trend

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| timechart span=5m count
```

**Visualization:** Line Chart

**Purpose:** Shows the volume of classified security events over time and helps identify spikes in activity.

---

### 10. Security Alert Timeline

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| timechart span=1h count by soc_severity
```

**Visualization:** Line/Area Chart

**Purpose:** Tracks severity-specific alert activity over time.

---

### 11. Events by Hour

```spl
index=main sourcetype=suricata
| bin _time span=1h
| stats count by _time
| sort _time
```

**Visualization:** Column or Line Chart

**Purpose:** Shows hourly event volume and helps identify periods of increased network activity.

---

## Source, Destination & Network Analysis

### 12. Top Source Attackers

```spl
index=main sourcetype=suricata
| stats count by src_ip
| sort - count
| head 10
```

**Visualization:** Bar Chart

**Purpose:** Identifies source IP addresses generating the highest number of Suricata events.

---

### 13. Top Targeted Systems

```spl
index=main sourcetype=suricata
| stats count by dest_ip
| sort - count
| head 10
```

**Visualization:** Bar Chart

**Purpose:** Identifies destination systems receiving the highest volume of detected activity.

---

### 14. Top Destination Ports

```spl
index=main sourcetype=suricata
| stats count by dest_port
| sort - count
| head 10
```

**Visualization:** Bar Chart

**Purpose:** Highlights the destination services and ports most frequently associated with observed activity.

---

### 15. Protocol Distribution

```spl
index=main sourcetype=suricata
| stats count by proto
| sort - count
```

**Visualization:** Bar Chart

**Purpose:** Provides a high-level view of observed network protocols.

---

### 16. Source / Destination Port Activity

```spl
index=main sourcetype=suricata
| stats count by src_ip dest_port
| sort - count
| head 20
```

**Visualization:** Column Chart

**Purpose:** Highlights source IP and destination-port combinations generating significant activity.

---

### 17. Top Source / Destination Pairs

```spl
index=main sourcetype=suricata
| stats count by src_ip dest_ip
| sort - count
| head 20
```

**Visualization:** Table

**Purpose:** Helps analysts identify frequently observed communication or attack relationships between source and destination systems.

---

## Signature & Alert Investigation

### 18. Top Attack Signatures

```spl
index=main sourcetype=suricata
| stats count by alert.signature
| sort - count
| head 10
```

**Visualization:** Bar Chart

**Purpose:** Identifies the most frequently triggered Suricata signatures.

---

### 19. Latest Security Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| table _time alert.signature soc_severity cvss mitre_id threat_category src_ip dest_ip dest_port recommendation
| sort - _time
| head 20
```

**Visualization:** Table

**Purpose:** Provides an analyst-friendly queue of recent enriched security detections.

---

### 20. Critical Alert Investigation

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity="Critical"
| table _time alert.signature soc_severity cvss mitre_id src_ip dest_ip dest_port recommendation
| sort - _time
| head 20
```

**Visualization:** Table

**Purpose:** Focuses the analyst view on Critical detections and associated enrichment.

---

### 21. High / Critical Alerts

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| where soc_severity IN ("Critical","High")
| eval severity_order=if(soc_severity="Critical",1,2)
| sort severity_order - _time
| table _time alert.signature soc_severity cvss mitre_id src_ip dest_ip dest_port recommendation
| head 20
```

**Visualization:** Table

**Purpose:** Provides a prioritized view of the highest-severity detections for L1 triage.

---

## Analyst Workflow

The dashboard supports the following L1 workflow:

```text
Monitor Dashboard
       ↓
Identify Alert
       ↓
Validate Detection
       ↓
Review Source / Destination
       ↓
Enrich with Lookup
       ↓
Assess Severity / CVSS
       ↓
Map to MITRE ATT&CK
       ↓
Investigate Related Activity
       ↓
Document Findings
       ↓
Escalate When Required
```

### Analyst priorities

1. Review Critical alerts first.
2. Validate whether the source and destination are expected.
3. Review the alert signature and supporting network fields.
4. Use CVSS and SOC severity as prioritization inputs.
5. Review MITRE ATT&CK tactic/technique enrichment.
6. Check for repeated activity or related signatures.
7. Document evidence and recommended action.
8. Escalate when the activity suggests compromise, persistent malicious behavior, or requires higher-level response.

---

## Important Analyst Note

A Suricata alert demonstrates that traffic matched a detection rule. **It does not, by itself, prove that an attack succeeded or that the target was compromised.** The analyst should validate the event using surrounding network, endpoint, authentication, and application evidence when available.

---

## Project Skills Demonstrated

- Splunk SPL
- SIEM dashboard development
- Suricata alert analysis
- Lookup-based threat enrichment
- SOC severity classification
- CVSS interpretation
- MITRE ATT&CK mapping
- Network traffic analysis
- L1 alert triage
- Security event correlation
- Incident investigation workflow
- Analyst documentation
