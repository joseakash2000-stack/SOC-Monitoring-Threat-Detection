# SOC Monitoring & Threat Detection Lab

<p align="center">
  <strong>Suricata + Splunk SOC L1 Home Lab</strong><br>
  Network Detection • SIEM Monitoring • Alert Triage • Case Management • Endpoint Telemetry • MITRE ATT&CK
</p>

A controlled defensive SOC lab demonstrating the analyst workflow from network detection and SIEM ingestion through alert validation, true/false-positive disposition, investigation, threat enrichment, MITRE ATT&CK mapping, escalation, case documentation, and a Windows endpoint process-creation detection.

> **Environment:** Controlled virtual lab for defensive security training and SOC analyst portfolio practice.

## Architecture

```text
Controlled Lab Traffic → Suricata IDS → EVE JSON Logs
→ Splunk Universal Forwarder → Splunk Enterprise
→ SPL Investigation + Enrichment → SOC Dashboard
→ Alert Triage / Case / MITRE

Windows Lab Endpoint → Windows Security Audit
→ Event ID 4688 (Process Creation) → Splunk Enterprise
→ Endpoint Detection → Alert Action → L1 Triage / MITRE / Case
```

## SOC L1 Workflow

```text
Detect → Validate → Investigate → Classify → Enrich → Map
→ Create Case → Escalate When Required → Document → Close
```

The project explicitly models true-positive / false-positive validation rather than treating every IDS signature as proof of compromise.

## Key Capabilities

- Suricata network threat detection and EVE JSON telemetry
- Splunk Enterprise ingestion and SPL investigation
- Splunk dashboard development and correlation searches
- Alert validation and true-positive / false-positive disposition
- Severity classification and CVSS/CVE context
- MITRE ATT&CK mapping and threat enrichment
- Source/destination, port, protocol and timeline analysis
- Lightweight Splunk lookup case tracking and escalation workflow
- Windows Security Event ID 4688 process-creation monitoring
- PowerShell-to-CMD process relationship detection in a controlled Windows lab
- Scheduled Splunk alerting with Log Event output for alert-pipeline validation
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
| PowerShell → CMD process creation | Validate Windows endpoint process telemetry and L1 triage |

Custom Suricata rules are maintained in `detection-rules/suricata/soc_demo.rules`.

## Splunk Investigation

Primary network telemetry:

```spl
index=main sourcetype=suricata
```

Reusable SPL covers event volume, severity, sources, targets, ports, protocols, source/destination correlation, signature-specific investigation, lookup-based enrichment, alert disposition, case tracking, and Windows Event ID 4688 endpoint investigation.

See [`splunk/searches.md`](splunk/searches.md), [`splunk/case-management.md`](splunk/case-management.md), and [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md).

## Alert Triage & Case Management

```text
Alert Intake → Validate Detection
→ TP / FP / Benign / Needs Investigation
→ Investigate Context → Assign Severity
→ Enrich + MITRE → Create / Update Case
→ Escalate When Evidence Supports Incident
→ Document → Resolve / Close
```

The case-management layer is deliberately a **simulation**. It does not claim ServiceNow, Jira, SOAR, or production ITSM integration.

See [`documentation/incident-case-management.md`](documentation/incident-case-management.md).

## Windows Endpoint Detection

The verified endpoint implementation uses native Windows Security auditing and Event ID 4688 rather than claiming a commercial EDR integration.

The demonstrated detection identifies **PowerShell spawning `cmd.exe`** and extracts the user, new process, creator process, and process IDs from Event ID 4688.

The controlled test was classified as **Benign/Expected** because it was intentionally generated to validate the detection. The evidence does not establish a malicious command line or compromise.

The repository also contains a Sysmon setup/investigation guide as an optional extension. Sysmon event IDs are not presented as successfully ingested telemetry unless they are actually observed in the lab.

See [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md) and [`splunk/endpoint-detections.md`](splunk/endpoint-detections.md).

## Python Automation

`scripts/ioc_log_processor.py` provides a small defensive automation exercise for exported alert CSV data. It validates fields, normalizes severity into review priority, identifies Critical/High records for review, and produces a case-ready CSV. This demonstrates basic security automation without claiming production SOAR capability.

## Example Investigations

- Drupal SQL Injection — CVE-2014-3704
- Cisco ASA / Firepower Path Traversal — CVE-2020-3452
- Nmap Network Scanning
- SSH Brute Force
- Windows PowerShell → CMD process creation — Event ID 4688

A Suricata signature indicates that traffic matched a detection condition; it does **not** independently prove successful exploitation or compromise.

## Evidence & Dashboard

The repository includes a focused evidence set under `screenshots/`:

| Screenshot | Evidence |
|---|---|
| `01-suricata-alert-volume.png` | Suricata alert volume |
| `02-l1-alert-queue.png` | L1 prioritized alert queue |
| `03-ssh-bruteforce-investigation.png` | Enriched SSH brute-force investigation |
| `04-nmap-correlation-investigation.png` | Nmap/source correlation |
| `05-cisco-rv320-exploit-investigation.png` | Vulnerability/exploit alert investigation |
| `06-windows-endpoint-detection.png` | Windows 4688 PowerShell → CMD detection |
| `07-case-management-queue.png` | L1 case register and dispositions |
| `08-source-activity-timeline.png` | Source activity timeline |
| `09-final-soc-dashboard.png` | Final SOC dashboard |

Historical dashboard/investigation evidence is also retained to show the progression of the Splunk dashboard and alert-investigation work:

- `splunk-dashboard-overview.png`
- `splunk-dashboard-investigation.png`
- `splunk-dashboard-analysis.png`
- `splunk-alert-investigation.png`

## Technologies

| Category | Tools / Concepts |
|---|---|
| SIEM | Splunk Enterprise, Splunk Universal Forwarder, SPL |
| Network Detection | Suricata IDS |
| Endpoint Telemetry | Windows Security Event Logs, Event ID 4688; Sysmon guide/extension |
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
- Alert investigation and scheduled alerting
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
- EDR/XDR investigation concepts

### Automation
- Python CSV processing
- Basic security alert normalization

## Scope & Limitations

This is a **controlled defensive training environment**, not a production SOC deployment.

The project does not claim enterprise EDR, SOAR, ServiceNow/Jira integration, or production incident-management controls. The case register is a lightweight portfolio simulation. The verified endpoint detection uses Windows Security Event ID 4688; the Sysmon directory provides an optional setup/investigation guide and should not be interpreted as proof of successfully ingested Sysmon telemetry.

All scanning and security testing must be performed only against systems and networks where explicit authorization exists.

## Documentation

| Document | Description |
|---|---|
| [`documentation/architecture.md`](documentation/architecture.md) | Lab architecture and data flow |
| [`documentation/alert-triage.md`](documentation/alert-triage.md) | L1 triage and investigation cases |
| [`documentation/investigation-workflow.md`](documentation/investigation-workflow.md) | Investigation methodology |
| [`documentation/incident-case-management.md`](documentation/incident-case-management.md) | Case, disposition and escalation workflow |
| [`documentation/lab-build-and-investigation-journal.md`](documentation/lab-build-and-investigation-journal.md) | Practical lab build, validation, investigation, troubleshooting, and evidence journal |
| [`endpoint-telemetry/README.md`](endpoint-telemetry/README.md) | Windows endpoint/Sysmon setup and investigation guide |
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
