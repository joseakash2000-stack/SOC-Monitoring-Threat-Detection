# Splunk Case Management & Alert Disposition

This document adds a lightweight case-management layer to the SOC Monitoring lab using Splunk lookup files. It is intentionally simple so the workflow can be demonstrated without claiming a production ITSM integration.

## 1. Case Register

Create a lookup named `soc_case_register.csv` with these columns:

```csv
case_id,alert_time,signature,src_ip,dest_ip,dest_port,initial_severity,disposition,status,mitre_id,escalation,analyst_notes,recommended_action
SOC-2026-001,2026-08-08T10:15:00,SOC DEMO - SSH Brute Force,192.168.1.16,192.168.1.11,22,Critical,True Positive,Closed,T1110,Yes,Repeated SSH attack pattern reviewed in controlled lab,Review authentication logs and escalate if compromise is suspected
SOC-2026-002,2026-08-08T10:30:00,ET SCAN Possible Nmap User-Agent Observed,192.168.1.16,192.168.1.11,80,Medium,Benign / Expected,Closed,T1046,No,Authorized lab scan confirmed,Document as expected activity
```

These are example lab records. Replace timestamps and addresses with the evidence from your own environment before presenting them as personal investigation results.

## 2. Enriched Alert Queue

```spl
index=main sourcetype=suricata
| lookup suricata_threat_lookup.csv signature as alert.signature OUTPUT soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category recommendation
| eval soc_severity=mvindex(soc_severity,0)
| where isnotnull(soc_severity)
| eval disposition=case(
    soc_severity="Critical", "Needs Investigation",
    soc_severity="High", "Needs Investigation",
    true(), "Review"
  )
| table _time alert.signature src_ip dest_ip dest_port soc_severity cvss cve mitre_tactic mitre_technique mitre_id threat_category disposition recommendation
| sort - _time
```

**Purpose:** Create an analyst queue where high-priority detections begin as `Needs Investigation` rather than being automatically labeled malicious.

## 3. True Positive / False Positive Review

Use the following pattern after validating the alert in context:

```spl
index=main sourcetype=suricata
| lookup soc_case_register.csv signature as alert.signature OUTPUT case_id disposition status escalation analyst_notes
| table _time case_id alert.signature src_ip dest_ip dest_port disposition status escalation analyst_notes
| sort - _time
```

**Purpose:** Bring investigation disposition and case status alongside the detection evidence.

## 4. Open Cases Requiring Investigation

```spl
| inputlookup soc_case_register.csv
| where status!="Closed"
| table case_id alert_time signature src_ip dest_ip dest_port initial_severity disposition status mitre_id escalation analyst_notes recommended_action
| sort - initial_severity
```

## 5. Escalated Cases

```spl
| inputlookup soc_case_register.csv
| where escalation="Yes"
| table case_id alert_time signature initial_severity disposition status mitre_id analyst_notes recommended_action
| sort - alert_time
```

## 6. Case Metrics

### Cases by disposition

```spl
| inputlookup soc_case_register.csv
| stats count by disposition
| sort - count
```

### Cases by status

```spl
| inputlookup soc_case_register.csv
| stats count by status
| sort - count
```

### Escalation rate

```spl
| inputlookup soc_case_register.csv
| eval escalated=if(escalation="Yes",1,0)
| stats count as total_cases sum(escalated) as escalated_cases
| eval escalation_rate=round((escalated_cases/total_cases)*100,2)
| table total_cases escalated_cases escalation_rate
```

## 7. Recommended L1 Status Model

```text
New
 ↓
Investigating
 ↓
 ├── False Positive → Closed
 ├── Benign / Expected → Closed
 ├── Needs More Context → Investigating
 └── True Positive
          ↓
       Escalate
          ↓
     Resolved / Closed
```

## 8. Important Limitation

Splunk lookup files provide a portfolio-friendly simulation of case tracking. They do not provide the controls, workflow automation, access management, audit requirements, or SLA handling of a production ITSM/case-management platform.
