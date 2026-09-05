# SOC Monitoring & Threat Detection Lab

<p align="center">
  <strong>Suricata + Splunk SOC L1 Home Lab</strong><br>
  Network Detection • SIEM Monitoring • Alert Triage • Case Management • Endpoint Telemetry • MITRE ATT&CK
</p>

A controlled defensive SOC lab demonstrating the analyst workflow from network detection and SIEM ingestion through alert validation, true/false-positive disposition, investigation, threat enrichment, MITRE ATT&CK mapping, escalation, case documentation, and endpoint telemetry.

> **Environment:** Controlled virtual lab for defensive security training and SOC analyst portfolio practice.

## Architecture

```text
Controlled Lab Traffic
        ↓
    Suricata IDS
        ↓
   EVE JSON Logs
        ↓
 Splunk Universal Forwarder
        ↓
  Splunk Enterprise
        ↓
 SPL Investigation + Enrichment
        ↓
 SOC Dashboard
        ↓
 Alert Triage / Case / MITRE
        ↓
 Windows Sysmon Telemetry (Extension)
```

## SOC L1 Workflow

```text
Detect → Validate → Investigate →
Classify → Enrich → Map →
Create Case → Escalate When Required → Document → Close
```

The project explicitly models **true-positive / false-positive validation** rather than treating every IDS signature as proof of compromise.

## Key Capabilities

- Suricata network threat detection and EVE JSON telemetry
- Splunk Enterprise ingestion and SPL investigation
- Splunk dashboard development and correlation searches
- Alert validation and true-positive / false-positive disposition
- Severity classification and CVSS/CVE context
- MITRE ATT&CK mapping and threat enrichment
- Source/destination, port, protocol and timeline analysis
- Incident/case tracking using a lightweight Splunk lookup workflow
- Evidence-based escalation criteria and closure workflow
- Windows Sysmon endpoint telemetry extension for process, network, file, registry and DNS investigation
- Basic Python alert-processing automation
- Nmap, Wireshark and tcpdump for controlled network validation

## Detection Coverage

| Scenario | Purpose |
|---|---|
| ICMP / HTTP activity | Validate basic network visibility |
| SSH access | Detect inbound SSH activity |
| SSH brute force | Investigate repeated credential-attack behavior |
| Nmap scanning | Analyze reconnaissance / Network Service Discovery |
| Vulnerability / exploit signatures | Investigate vulnerability-related network activity |

Custom Suricata rules are maintained in `detection-rules/suricata/soc_demo.rules`.

## Splunk Investigation

Primary network telemetry:

```spl
index=main sourcetype=suricata
```

The repository contains reusable SPL for:

- Event volume and trends
- Severity distribution
- Top sources and targeted systems
- Ports and protocols
- Source/destination correlation
- Critical and High alert investigation
- Signature-specific investigation
- Lookup-based threat enrichment
- Alert disposition and case tracking
- Windows Sysmon endpoint investigation

See [`splunk/searches.md`](splunk/searches.md), [`splunk/case-management.md`](splunk/case-management.md), and [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md).

## Alert Triage & Case Management

The project uses a structured L1 decision model:

```text
Alert Intake
    ↓
Validate Detection
    ↓
True Positive / False Positive / Benign / Needs Investigation
    ↓
Investigate Context
    ↓
Assign Severity
    ↓
Enrich + MITRE ATT&CK
    ↓
Create / Update Case
    ↓
Escalate When Evidence Supports Incident
    ↓
Document Findings
    ↓
Resolve / Close
```

The case-management layer is deliberately described as a **simulation**. It does not claim ServiceNow, Jira, SOAR, or production ITSM integration.

See [`documentation/incident-case-management.md`](documentation/incident-case-management.md).

## Windows Endpoint Telemetry Extension

The endpoint extension adds Sysmon telemetry to the existing Splunk workflow:

```text
Windows Lab Endpoint → Sysmon → Windows Event Log
→ Splunk Universal Forwarder → Splunk Enterprise
→ Endpoint Investigation → MITRE / Case Workflow
```

Focused Sysmon events:

- Event ID 1 — Process Creation
- Event ID 3 — Network Connection
- Event ID 7 — Image/DLL Load
- Event ID 10 — Process Access
- Event ID 11 — File Creation
- Event ID 13 — Registry Value Set
- Event ID 22 — DNS Query

This is an **endpoint telemetry / EDR-style investigation extension**, not a commercial EDR integration. A specific EDR product should only be added to the resume after hands-on implementation.

See [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md).

## Python Automation

`scripts/ioc_log_processor.py` provides a small defensive automation exercise for exported alert CSV data. It:

1. Validates required alert fields.
2. Normalizes severity into review priority.
3. Marks Critical/High records as `Needs Investigation`.
4. Produces a case-ready CSV for analyst review.

This demonstrates basic security automation without claiming production SOAR capability.

## Example Investigations

Existing investigation scenarios include:

- Drupal SQL Injection — CVE-2014-3704
- Cisco ASA / Firepower Path Traversal — CVE-2020-3452
- Nmap Network Scanning
- SSH Brute Force

A Suricata signature indicates that traffic matched a detection condition; it does **not** independently prove successful exploitation or compromise.

## Evidence & Dashboard

The repository includes screenshots of the Splunk SOC dashboard and investigation views under `screenshots/`.

Dashboard coverage includes:

- Total events
- Critical / High / Medium / Low alerts
- Severity distribution
- Event trends
- Top source IPs
- Top targeted systems
- Destination ports
- Protocol distribution
- Attack signatures
- Latest enriched alerts
- Investigation tables

## Technologies

| Category | Tools / Concepts |
|---|---|
| SIEM | Splunk Enterprise, Splunk Universal Forwarder, SPL |
| Network Detection | Suricata IDS |
| Endpoint Telemetry | Sysmon / Windows Event Logs |
| Network Analysis | Wireshark, tcpdump, Nmap |
| Operating Systems | Windows, Kali Linux, Ubuntu |
| Virtualization | VirtualBox |
| Threat Framework | MITRE ATT&CK |
| Threat Context | CVE, CVSS, IOC analysis |
| Automation | Python |

## Repository Structure

```text
SOC-Monitoring-Threat-Detection/
├── detection-rules/
│   └── suricata/soc_demo.rules
├── documentation/
│   ├── alert-triage.md
│   ├── architecture.md
│   ├── investigation-workflow.md
│   └── incident-case-management.md
├── endpoint-telemetry/
│   └── README.md
├── mitre/
│   └── attack-mapping.md
├── screenshots/
├── scripts/
│   └── ioc_log_processor.py
├── splunk/
│   ├── dashboard.md
│   ├── searches.md
│   ├── case-management.md
│   └── endpoint-detections.md
├── .gitignore
└── README.md
```

## Skills Demonstrated

### SOC / Blue Team

- L1 alert triage
- True-positive / false-positive analysis
- Security event investigation
- Incident documentation
- Escalation decision-making
- Detection engineering fundamentals
- Threat enrichment
- MITRE ATT&CK mapping

### SIEM

- Splunk data ingestion
- SPL searches
- Correlation and filtering
- Lookup-based enrichment
- Dashboard development
- Alert investigation
- Case/disposition tracking

### Network Security

- Suricata IDS
- Network traffic analysis
- Nmap scanning analysis
- Wireshark packet inspection
- tcpdump
- TCP/IP and common protocols

### Endpoint Security

- Windows security telemetry
- Sysmon event analysis
- Process / network / file / registry / DNS investigation
- EDR/XDR investigation concepts

### Automation

- Python CSV processing
- Basic security alert normalization

## Scope & Limitations

This is a **controlled defensive training environment**, not a production SOC deployment.

The project does not claim enterprise EDR, SOAR, ServiceNow/Jira integration, or production incident-management controls. The case register is a lightweight portfolio simulation, and the endpoint extension requires a separately configured Windows/Sysmon lab endpoint.

All scanning and security testing must be performed only against systems and networks where explicit authorization exists.

## Documentation

| Document | Description |
|---|---|
| [`documentation/architecture.md`](documentation/architecture.md) | Lab architecture and data flow |
| [`documentation/alert-triage.md`](documentation/alert-triage.md) | L1 triage and investigation cases |
| [`documentation/investigation-workflow.md`](documentation/investigation-workflow.md) | Investigation methodology |
| [`documentation/incident-case-management.md`](documentation/incident-case-management.md) | Case, disposition and escalation workflow |
| [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md) | Windows/Sysmon endpoint extension |
| [`splunk/searches.md`](splunk/searches.md) | Network investigation SPL |
| [`splunk/case-management.md`](splunk/case-management.md) | Case/disposition SPL |
| [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md) | Sysmon investigation SPL |
| [`splunk/dashboard.md`](splunk/dashboard.md) | Dashboard documentation |
| [`mitre/attack-mapping.md`](mitre/attack-mapping.md) | ATT&CK mappings |

## Author

**Akash Jose**  
Cybersecurity / SOC Analyst Portfolio Project  
GitHub: `joseakash2000-stack`

## Disclaimer

This project is created for educational, defensive security, and SOC analyst portfolio purposes. Perform all testing only in systems and networks where explicit authorization exists.
