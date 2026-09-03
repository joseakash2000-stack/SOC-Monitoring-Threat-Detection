# SOC Monitoring & Threat Detection Lab

A hands-on SOC L1 home lab demonstrating network threat detection, SIEM monitoring, alert triage, log investigation, MITRE ATT&CK mapping, and security dashboard development.

> **Environment:** Controlled virtual lab for defensive security training and SOC analyst practice.

## Project Overview

This project simulates a small Security Operations Center (SOC) workflow using **Suricata IDS**, **Snort++**, and **Splunk SIEM**. Network and security events are generated in a controlled lab, detected by IDS rules, forwarded as structured logs, and investigated using Splunk searches and dashboards.

The project focuses on the practical workflow expected from a **SOC L1 / Tier 1 Analyst**:

**Detect → Validate → Investigate → Classify → Map → Recommend → Document**

## Objectives

- Build a practical SOC monitoring environment
- Monitor network traffic for suspicious activity
- Configure IDS detection rules using Suricata and Snort++
- Generate controlled security events for testing
- Forward Suricata EVE JSON logs into Splunk
- Investigate alerts using SPL
- Analyze source/destination IPs, ports, protocols, signatures, and severity
- Perform alert triage and distinguish relevant security events from noise
- Map detections to MITRE ATT&CK techniques
- Develop a SOC monitoring dashboard
- Practice repeatable L1 investigation and escalation workflows

## Architecture

```text
                         Network / Internet
                                |
                         [ pfSense / Lab Network ]
                                |
                    +-----------+-----------+
                    |                       |
               [ Kali Linux ]         [ Ubuntu ]
                    |                       |
                    +-----------+-----------+
                                |
                    +-----------+-----------+
                    |                       |
             [ Suricata IDS ]        [ Snort++ IDS ]
                    |                       |
              EVE JSON Logs          Detection Alerts
                    |                       |
                    +-----------+-----------+
                                |
                         [ Splunk UF ]
                                |
                                v
                       [ Splunk Enterprise ]
                                |
                    +-----------+-----------+
                    |                       |
              SPL Investigation       SOC Dashboard
                    |                       |
                    +-----------+-----------+
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
| IDS / Detection | Suricata, Snort++ |
| Network Analysis | Wireshark, tcpdump |
| Network Scanning | Nmap |
| Firewall / Network | pfSense |
| Operating Systems | Kali Linux, Ubuntu, Windows |
| Virtualization | VirtualBox |
| Threat Framework | MITRE ATT&CK |
| Query Language | Splunk SPL |
| Log Format | Suricata EVE JSON |

## Detection Coverage

The lab contains controlled detections for common SOC investigation scenarios, including:

- ICMP ping activity
- HTTP traffic / suspicious HTTP activity
- SSH access attempts
- SSH brute-force style activity
- Network and port scanning
- Port-based detection scenarios

Detection rules are stored under:

```text
detection-rules/
├── snort/
│   └── local.rules
└── suricata/
    └── soc_demo.rules
```

## Splunk Investigation

The project uses Splunk SPL to investigate and correlate security events.

Example investigation areas:

```text
index=main sourcetype=suricata
```

Key fields investigated include:

- `src_ip`
- `dest_ip`
- `src_port`
- `dest_port`
- `protocol`
- `alert.signature`
- `alert.severity`
- `alert.category`
- `sid`
- Timestamp / event time

The repository contains reusable searches for alert analysis, event statistics, severity analysis, and dashboard panels.

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

Detections are mapped to relevant MITRE ATT&CK tactics and techniques to practice threat-informed alert analysis.

Mapping documentation:

```text
mitre/attack-mapping.md
```

The goal is not simply to identify an alert, but to understand **what attacker behavior the alert may represent** and how it fits into a broader attack chain.

## SOC Dashboard

Splunk dashboard panels are designed to provide a high-level SOC monitoring view, including:

- Total security events
- Alert severity distribution
- Recent security alerts
- Detection signatures
- Source IP activity
- Destination IP activity
- Security event trends
- Investigation-focused alert details

Dashboard documentation:

```text
splunk/dashboard.md
```

## Repository Structure

```text
SOC-Monitoring-Threat-Detection/
│
├── detection-rules/
│   ├── snort/
│   │   └── local.rules
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

- Alert triage
- Security event analysis
- Log analysis
- Incident investigation workflow
- Detection engineering fundamentals
- Severity classification
- MITRE ATT&CK mapping
- Security monitoring

### SIEM

- Splunk data ingestion
- SPL searches
- Event filtering and aggregation
- Security dashboards
- Log-based investigation

### Network Security

- IDS rule creation
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

Screenshots will be added to document the working lab and investigation process, including:

- Splunk SOC dashboard
- Suricata alerts
- Snort detections
- SPL investigations
- Network traffic analysis
- Alert triage examples

Place evidence under:

```text
screenshots/
```

## Setup Notes

This repository primarily contains **configuration examples, detection rules, investigation queries, and documentation**. The complete lab requires separately installed and configured instances of the listed security tools.

The environment is intended for a controlled lab. Do not deploy detection rules or generate scanning traffic against systems you do not own or have explicit authorization to test.

## Future Enhancements

Planned improvements include:

- Add real investigation case studies
- Add sanitized sample logs
- Add additional MITRE ATT&CK detections
- Improve dashboard visualizations
- Add alert severity enrichment using lookup data
- Add a lightweight alert/ticket tracking workflow
- Add automated detection validation
- Add more Windows endpoint telemetry

## Author

**Akash Jose**

Cybersecurity / SOC Analyst Portfolio Project

GitHub: `joseakash2000-stack`

## Disclaimer

This project is created for **educational, defensive security, and SOC analyst portfolio purposes**. All testing should be performed only in systems and networks where the tester has explicit authorization.
