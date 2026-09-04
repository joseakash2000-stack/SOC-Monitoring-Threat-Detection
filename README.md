# SOC Monitoring & Threat Detection Lab

A hands-on SOC L1 home lab demonstrating network threat detection, SIEM monitoring, alert triage, log investigation, MITRE ATT&CK mapping, and security dashboard development.

> **Environment:** Controlled virtual lab for defensive security training and SOC analyst practice.

## Project Overview

This project simulates a small Security Operations Center (SOC) workflow using **Suricata IDS** and **Splunk SIEM**. Controlled network security events are detected by Suricata, written as EVE JSON telemetry, forwarded into Splunk, enriched with threat intelligence metadata, and investigated using SPL and dashboards.

The project focuses on the practical workflow expected from a **SOC L1 / Tier 1 Analyst**:

**Detect → Validate → Investigate → Classify → Map → Recommend → Document**

## Objectives

- Build a practical SOC monitoring environment
- Monitor network traffic for suspicious activity
- Configure and test Suricata detection rules
- Generate controlled security events for testing
- Forward Suricata EVE JSON logs into Splunk
- Investigate alerts using SPL
- Analyze source/destination IPs, ports, protocols, signatures, and severity
- Perform alert triage and distinguish relevant security events from noise
- Enrich detections with CVSS, CVE, MITRE ATT&CK, threat category, and recommendations
- Develop a SOC monitoring dashboard
- Practice repeatable L1 investigation and escalation workflows

## Architecture

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
   SPL Investigation   SOC Dashboard
        |                 |
        +--------+--------+
                 |
           Alert Triage
                 |
        MITRE ATT&CK Mapping
                 |
       Recommendation / Escalation
```

## Technologies & Tools

| Category | Tools |
|---|---|
| SIEM | Splunk Enterprise, Splunk Universal Forwarder |
| IDS / Detection | Suricata |
| Network Analysis | Wireshark, tcpdump |
| Network Scanning | Nmap |
| Operating Systems | Kali Linux, Ubuntu, Windows |
| Virtualization | VirtualBox |
| Threat Framework | MITRE ATT&CK |
| Query Language | Splunk SPL |
| Log Format | Suricata EVE JSON |

## Detection Coverage

The lab contains controlled detections and investigation scenarios including:

- ICMP ping activity
- HTTP traffic / suspicious HTTP activity
- SSH access attempts
- SSH brute-force style activity
- Network and port scanning
- Vulnerability and exploit-attempt signatures observed in Suricata telemetry

Detection rules are stored under:

```text
detection-rules/
└── suricata/
    └── soc_demo.rules
```

## Splunk Investigation

The project uses Splunk SPL to investigate and correlate Suricata security events.

Base search:

```spl
index=main sourcetype=suricata
```

Key fields include:

- `src_ip`
- `dest_ip`
- `src_port`
- `dest_port`
- `proto`
- `alert.signature`
- `alert.severity`
- `alert.category`
- Timestamp / event time

The repository contains reusable searches for event statistics, severity analysis, alert enrichment, correlation, and investigation.

See:

```text
splunk/searches.md
splunk/dashboard.md
```

## Alert Triage Workflow

A repeatable L1 triage process is documented in the project:

1. Review the alert and detection signature
2. Validate timestamp and affected host
3. Identify source and destination IP addresses
4. Review ports, protocol, and network context
5. Determine whether the activity is expected or suspicious
6. Check for repeated or related events
7. Assess severity and potential impact
8. Map the behavior to MITRE ATT&CK where applicable
9. Record findings and recommended action
10. Escalate confirmed or high-risk activity when required

Detailed workflow documentation:

```text
documentation/alert-triage.md
documentation/investigation-workflow.md
```

## MITRE ATT&CK Mapping

The project uses MITRE ATT&CK to provide behavioral context for selected Suricata detections.

Mapping documentation:

```text
mitre/attack-mapping.md
```

ATT&CK mappings are treated as analyst classifications for the lab and should be validated against the actual event context. A detection does not by itself prove that an attack succeeded.

## SOC Dashboard

The Splunk dashboard provides a high-level monitoring and investigation view including:

- Total security events
- Critical / High / Medium / Low alert counts
- Severity distribution
- Alert categories and threat categories
- Security event trends
- Source and destination activity
- Top signatures and destination ports
- Latest enriched security alerts
- Critical and High/Critical investigation tables

Dashboard documentation:

```text
splunk/dashboard.md
```

## Repository Structure

```text
SOC-Monitoring-Threat-Detection/
│
├── detection-rules/
│   └── suricata/
│       └── soc_demo.rules
│
├── documentation/
│   ├── alert-triage.md
│   ├── architecture.md
│   └── investigation-workflow.md
│
├── mitre/
│   └── attack-mapping.md
│
├── screenshots/
│   └── README.md
│
├── splunk/
│   ├── dashboard.md
│   └── searches.md
│
├── .gitignore
└── README.md
```

## Skills Demonstrated

### SOC / Blue Team

- L1 alert triage
- Security event analysis
- Log investigation
- Incident investigation workflow
- Detection engineering fundamentals
- Severity classification
- MITRE ATT&CK mapping
- Security monitoring

### SIEM

- Splunk data ingestion
- SPL searches
- Event filtering and aggregation
- Lookup-based threat enrichment
- Security dashboards
- Log-based investigation

### Network Security

- Suricata IDS
- Network traffic analysis
- TCP/IP and common protocols
- Port and service analysis
- Nmap scanning analysis
- Wireshark packet inspection

### Linux / Security Operations

- Kali Linux
- Ubuntu
- Linux security logs
- Command-line troubleshooting
- Virtual lab administration

## Evidence & Screenshots

The repository contains investigation evidence demonstrating:

- Splunk SOC dashboard
- Suricata alerts
- SPL investigations
- Network traffic analysis
- Alert triage examples

Place evidence under:

```text
screenshots/
```

## Setup Notes

This repository contains **configuration examples, Suricata rules, investigation queries, enrichment documentation, screenshots, and SOC workflow documentation**. The complete lab requires separately installed and configured instances of the listed tools.

The environment is intended for a controlled lab. Do not deploy detection rules or generate scanning traffic against systems you do not own or have explicit authorization to test.

## Future Enhancements

- Add sanitized sample logs
- Add additional Suricata detections
- Improve dashboard visualizations
- Add additional MITRE ATT&CK coverage
- Add a lightweight alert/ticket tracking workflow
- Add automated detection validation
- Add more Windows endpoint telemetry

## Author

**Akash Jose**

Cybersecurity / SOC Analyst Portfolio Project

GitHub: `joseakash2000-stack`

## Disclaimer

This project is created for **educational, defensive security, and SOC analyst portfolio purposes**. All testing should be performed only in systems and networks where the tester has explicit authorization to test.
