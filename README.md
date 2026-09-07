# SOC Monitoring & Threat Detection Lab

<p align="center">
  <strong>Suricata + Splunk SOC L1 Home Lab</strong><br>
  Network Detection • SIEM Monitoring • Alert Triage • Investigation • Endpoint Telemetry • MITRE ATT&CK
</p>

A controlled defensive SOC lab that demonstrates an L1 analyst workflow from network detection and SIEM ingestion through alert validation, investigation, threat enrichment, MITRE ATT&CK mapping, case handling, escalation decisions, and Windows endpoint process-creation detection.

> **Environment:** Controlled virtual lab for defensive security training and SOC analyst portfolio practice.

## What I Built

This project brings together two investigation paths:

```text
NETWORK DETECTION
Kali / Controlled Traffic
        ↓
   Suricata IDS
        ↓
    EVE JSON
        ↓
Splunk Universal Forwarder
        ↓
 Splunk Enterprise
        ↓
SPL + Threat Enrichment
        ↓
Alert Triage / Investigation
        ↓
MITRE ATT&CK + Case Workflow
```

```text
WINDOWS ENDPOINT
Windows Lab Endpoint
        ↓
Windows Security Auditing
        ↓
Event ID 4688 — Process Creation
        ↓
 Splunk Enterprise
        ↓
PowerShell → CMD Detection
        ↓
Scheduled Alert / Log Event
        ↓
L1 Triage + Case Workflow
```

The project is intentionally scoped as a **portfolio lab**, not a production SOC or enterprise security platform.

## SOC L1 Workflow

```text
Detect → Validate → Investigate → Classify
   ↓
Enrich → Map → Create / Update Case
   ↓
Escalate When Evidence Supports Incident
   ↓
Document → Resolve / Close
```

A detection is treated as an indicator for investigation, not automatic proof of compromise.

## Key Capabilities

- Suricata IDS network detection and EVE JSON telemetry
- Splunk Enterprise ingestion, SPL investigation, correlation and dashboarding
- Custom Suricata detection rules for controlled lab activity
- Alert validation and TP / FP / Benign / Needs Investigation disposition
- CVE / CVSS threat context and lookup-based enrichment
- MITRE ATT&CK tactic and technique mapping
- Source, destination, port, protocol and timeline correlation
- Lightweight Splunk lookup-based case tracking and escalation workflow
- Windows Security Event ID 4688 process-creation monitoring
- PowerShell spawning `cmd.exe` detection using parent/child process context
- Scheduled Splunk alert validation with Log Event output
- Basic Python CSV alert-processing automation
- Nmap, Wireshark and tcpdump for controlled validation and investigation

## Detection Coverage

| Scenario | Analyst Use |
|---|---|
| ICMP / HTTP activity | Validate network visibility and ingestion |
| SSH access | Detect and investigate inbound SSH activity |
| SSH brute force | Analyze repeated credential-attack behavior |
| Nmap scanning | Investigate network reconnaissance / service discovery |
| Vulnerability / exploit signatures | Investigate vulnerability-related activity |
| PowerShell → CMD process creation | Validate Windows process telemetry and parent/child process analysis |

Custom Suricata rules are maintained in `detection-rules/suricata/soc_demo.rules`.

## Splunk Investigation

Primary network telemetry:

```spl
index=main sourcetype=suricata
```

The repository contains reusable SPL for:

- Event volume and severity distribution
- Alert categories and trends
- Top sources, targets and destination ports
- Source/destination correlation
- Signature-specific investigation
- CVE/CVSS and MITRE enrichment
- Alert disposition and case tracking
- Windows Event ID 4688 endpoint investigation

See [`splunk/searches.md`](splunk/searches.md), [`splunk/case-management.md`](splunk/case-management.md), and [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md).

## Alert Triage & Case Management

The case workflow models a practical L1 process:

```text
Alert Intake
    ↓
Validate Detection
    ↓
TP / FP / Benign / Needs Investigation
    ↓
Investigate Source / Destination / Endpoint Context
    ↓
Assign Severity
    ↓
Enrich + MITRE ATT&CK
    ↓
Create / Update Case
    ↓
Escalate When Evidence Supports Incident
    ↓
Document Findings / Actions
    ↓
Resolve / Close
```

The repository documents three representative lab cases: SSH brute force, Nmap reconnaissance, and a controlled Windows PowerShell-to-CMD process-creation test. The case register is a **lightweight portfolio simulation** implemented with Splunk lookup data; it does not claim ServiceNow, Jira, SOAR, or production ITSM integration.

See [`documentation/incident-case-management.md`](documentation/incident-case-management.md).

## Windows Endpoint Detection

The verified endpoint implementation uses native Windows Security auditing and **Event ID 4688 (Process Creation)** rather than claiming a commercial EDR platform.

The demonstrated detection identifies **PowerShell spawning `cmd.exe`** and extracts the user, new process, creator process, and process IDs from Event ID 4688. The controlled test was classified as **Benign/Expected** because it was intentionally generated to validate the detection.

A Sysmon setup/investigation guide is retained as an **optional extension**. Sysmon events are not presented as successfully ingested portfolio telemetry unless they are actually observed in the lab.

See [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md) and [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md).

## Threat Enrichment & MITRE ATT&CK

Selected detections are enriched with CVE, CVSS, threat category, MITRE tactic, technique and ATT&CK ID where the mapping is supported by the observed behavior or detection context.

Examples include:

| Investigation | Context | ATT&CK |
|---|---|---|
| Drupal SQL Injection | CVE-2014-3704, Critical, CVSS 9.8 | T1190 |
| Cisco ASA / Firepower Path Traversal | CVE-2020-3452, Critical, CVSS 9.8 | T1190 |
| Nmap reconnaissance | Network Service Discovery | T1046 |
| SSH brute force | Credential attack | T1110 |
| PowerShell → CMD | Command and Scripting Interpreter | T1059 |

ATT&CK mapping is used for behavioral context and does not by itself establish successful exploitation or compromise.

See [`mitre/attack-mapping.md`](mitre/attack-mapping.md).

## Python Automation

`scripts/ioc_log_processor.py` provides a small defensive automation exercise for exported alert CSV data. It validates fields, normalizes severity into review priority, identifies Critical/High records for review, and produces a case-ready CSV.

This demonstrates basic security automation without claiming production SOAR capability.

## Investigation Examples

- **Drupal SQL Injection** — CVE-2014-3704
- **Cisco ASA / Firepower Path Traversal** — CVE-2020-3452
- **Nmap Network Scanning** — T1046
- **SSH Brute Force** — T1110
- **Windows PowerShell → CMD** — Event ID 4688 / T1059

A Suricata signature indicates that traffic matched a detection condition; it does **not** independently prove successful exploitation or compromise.

## Evidence & Dashboard

The repository includes a focused evidence set under `screenshots/`:

| Screenshot | Evidence |
|---|---|
| `01-suricata-alert-volume.png` | Suricata alert volume |
| `02-l1-alert-queue.png` | L1 prioritized alert queue |
| `03-ssh-bruteforce-investigation.png` | Enriched SSH brute-force investigation |
| `04-nmap-correlation-investigation.png` | Nmap/source correlation |
| `05-cisco-asa-firepower-exploit-investigation.png` | Cisco ASA/Firepower vulnerability investigation |
| `06-windows-endpoint-detection.png` | Windows 4688 PowerShell → CMD detection |
| `07-case-management-queue.png` | L1 case register and dispositions |
| `08-source-activity-timeline.png` | Source activity timeline |
| `09-final-soc-dashboard.png` | Final SOC dashboard |

Historical dashboard/investigation screenshots are also retained to show the progression of the Splunk dashboard and investigation work.

## Technologies

| Category | Tools / Concepts |
|---|---|
| SIEM | Splunk Enterprise, Splunk Universal Forwarder, SPL |
| Network Detection | Suricata IDS |
| Endpoint Telemetry | Windows Security Event Logs, Event ID 4688; Sysmon optional guide |
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
├── documentation/
├── endpoint-telemetry/
├── mitre/
├── screenshots/
├── scripts/
├── splunk/
├── .gitignore
└── README.md
```

## Skills Demonstrated

### SOC / Blue Team
- L1 alert triage
- True-positive / false-positive analysis
- Security event investigation
- Incident documentation
- Evidence-based escalation decisions
- Detection engineering fundamentals
- Threat enrichment
- MITRE ATT&CK mapping

### SIEM
- Splunk data ingestion
- SPL searches and filtering
- Correlation and investigation pivots
- Lookup-based enrichment
- Dashboard development
- Scheduled alert validation
- Case/disposition tracking

### Network Security
- Suricata IDS
- Network traffic analysis
- Nmap scanning analysis
- Wireshark packet inspection
- tcpdump
- TCP/IP and common protocols

### Endpoint Security
- Windows Security Event ID 4688
- Process creation analysis
- Parent/child process investigation
- PowerShell-to-CMD detection
- EDR-style investigation concepts without claiming commercial EDR deployment

### Automation
- Python CSV processing
- Security alert normalization and prioritization

## Scope & Limitations

This is a **controlled defensive training environment**, not a production SOC deployment.

The project does not claim enterprise EDR, SOAR, ServiceNow/Jira integration, or production incident-management controls. Case tracking is implemented as a lightweight Splunk lookup workflow. Sysmon is documented as an optional extension rather than verified portfolio telemetry.

All scanning and security testing must be performed only against systems and networks where explicit authorization exists.

## Documentation

| Document | Description |
|---|---|
| [`documentation/architecture.md`](documentation/architecture.md) | Lab architecture and data flow |
| [`documentation/alert-triage.md`](documentation/alert-triage.md) | L1 triage and investigation cases |
| [`documentation/investigation-workflow.md`](documentation/investigation-workflow.md) | Investigation methodology |
| [`documentation/incident-case-management.md`](documentation/incident-case-management.md) | Case, disposition and escalation workflow |
| [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md) | Windows 4688 endpoint and optional Sysmon guide |
| [`splunk/searches.md`](splunk/searches.md) | Network investigation SPL |
| [`splunk/case-management.md`](splunk/case-management.md) | Case/disposition SPL |
| [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md) | Windows 4688 endpoint detection SPL |
| [`splunk/dashboard.md`](splunk/dashboard.md) | Dashboard documentation |
| [`mitre/attack-mapping.md`](mitre/attack-mapping.md) | ATT&CK mappings |

## Author

**Akash Jose**  
Cybersecurity / SOC Analyst Portfolio Project  
GitHub: `joseakash2000-stack`

## Disclaimer

This project is created for educational, defensive security, and SOC analyst portfolio purposes. Perform all testing only in systems and networks where explicit authorization exists.

## Reproduce This Lab

1. **Environment:** Spin up three VirtualBox VMs on a host-only network - Kali Linux (attacker), a Windows endpoint (victim/telemetry source), and Ubuntu (Suricata sensor + Splunk).
2. **Suricata:** Install Suricata on the Ubuntu sensor, drop the custom rules from `detection-rules/suricata/` into `/etc/suricata/rules/`, and enable EVE JSON output in `suricata.yaml`.
3. **Splunk:** Install Splunk Enterprise on the same box (or a second VM), then install a Splunk Universal Forwarder pointed at Suricata's `eve.json` and, on the Windows VM, at the Security event log (Event ID 4688 auditing must be enabled via Group Policy first).
4. **Generate traffic:** From Kali, run the scans/attacks described in `mitre/attack-mapping.md` (Nmap reconnaissance, SSH brute-force, etc.) against the Windows/Ubuntu VMs.
5. **Investigate:** Use the SPL searches in `splunk/searches.md` to triage the resulting alerts, following the workflow in `documentation/investigation-workflow.md`.

Adjust IPs, interface names, and Splunk index names to match your own environment.
