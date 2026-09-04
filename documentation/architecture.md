# SOC Lab Architecture

This document describes the architecture actually used for the SOC Monitoring & Threat Detection lab.

## Components

| Component | Role |
|---|---|
| Kali Linux | Controlled traffic generation, reconnaissance, and security testing |
| Ubuntu | Linux host used in the lab and security telemetry workflow |
| Suricata | Network IDS and detection engine |
| Splunk Universal Forwarder | Forwards Suricata EVE JSON telemetry |
| Splunk Enterprise | SIEM, search, enrichment, correlation, and dashboarding |
| Wireshark | Packet-level network analysis |
| tcpdump | Command-line packet capture and validation |
| Nmap | Controlled network scanning for detection validation |
| VirtualBox | Virtual lab platform |

## Data Flow

```text
        Controlled Lab Traffic
                 |
        +--------+--------+
        |                 |
   Kali Linux         Ubuntu
        |                 |
        +--------+--------+
                 |
          [ Suricata IDS ]
                 |
          Suricata EVE JSON
                 |
          [ Splunk UF ]
                 |
          [ Splunk Enterprise ]
                 |
        +--------+--------+
        |                 |
   SPL Searches      SOC Dashboard
        |                 |
        +--------+--------+
                 |
           Alert Triage
                 |
        Threat Enrichment
                 |
        MITRE ATT&CK Mapping
                 |
       Recommendation / Escalation
```

## Suricata Detection Layer

Suricata inspects network traffic and generates structured EVE JSON events. The lab includes custom detection rules for controlled scenarios such as ICMP activity, HTTP activity, SSH access attempts, and SSH brute-force style activity.

The detection rules are maintained in:

```text
detection-rules/suricata/soc_demo.rules
```

## Splunk Ingestion

The Splunk Universal Forwarder monitors the Suricata EVE JSON output and forwards the telemetry to Splunk Enterprise.

Primary Splunk search scope:

```spl
index=main sourcetype=suricata
```

## SIEM Analysis Layer

Splunk Enterprise is used for:

- Event search and filtering
- Alert investigation
- Source/destination analysis
- Severity classification
- Lookup-based threat enrichment
- CVSS/CVE context
- MITRE ATT&CK mapping
- Event correlation
- SOC dashboarding

The threat lookup enriches selected Suricata signatures with:

- SOC severity
- CVSS
- CVE
- MITRE tactic
- MITRE technique
- MITRE ID
- Threat category
- Investigation recommendation

## Network Analysis

Wireshark and tcpdump are used for packet-level validation when required. Nmap is used only within the controlled lab to generate or validate network-scanning detections.

## Analyst Workflow

```text
Detection
   ↓
Validation
   ↓
Source / Destination Analysis
   ↓
Lookup Enrichment
   ↓
Severity Assessment
   ↓
MITRE ATT&CK Context
   ↓
Correlation
   ↓
Investigation
   ↓
Documentation
   ↓
Escalation When Required
```

## Scope and Limitations

This is a controlled defensive training environment. The architecture does not represent a production SOC deployment and does not include enterprise EDR, SOAR, ticketing, or endpoint telemetry integrations.

A Suricata alert indicates traffic matching a detection condition; it does not independently establish successful exploitation or system compromise.
