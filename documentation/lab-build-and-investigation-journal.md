# Lab Build & Investigation Journal

This document records the major implementation and validation steps completed in the controlled SOC lab. It is intentionally written as a practical work journal rather than as a generic SOC methodology.

> **Environment:** Controlled virtual lab for defensive security training. Network scanning and security testing were performed only against lab systems.

## 1. Lab Architecture

The final network detection path is:

```text
Kali Linux / Controlled Traffic
        ↓
     Suricata IDS
        ↓
     EVE JSON
        ↓
Splunk Universal Forwarder
        ↓
  Splunk Enterprise
        ↓
SPL + Lookup Enrichment
        ↓
SOC Dashboard / L1 Triage / Case Tracking
```

A separate Windows lab endpoint provides native Windows Security process-creation telemetry:

```text
Windows Endpoint
      ↓
Windows Security Auditing
      ↓
Event ID 4688
      ↓
Splunk Enterprise
      ↓
PowerShell → CMD Detection
      ↓
Scheduled Alert → Log Event
      ↓
L1 Triage / Case
```

## 2. Suricata Implementation

Suricata was deployed in the virtual lab and configured to generate EVE JSON telemetry. Custom SOC demonstration rules were created for controlled ICMP, HTTP, SSH access, and SSH brute-force activity.

The lab also generated and investigated Suricata signatures for reconnaissance and vulnerability-related traffic. Suricata alerts were treated as detection evidence, not as automatic proof of successful exploitation.

## 3. Splunk Integration

Suricata EVE JSON was forwarded into Splunk Enterprise using the Splunk Universal Forwarder.

Primary search:

```spl
index=main sourcetype=suricata
```

The dataset contains both alert and non-alert telemetry. For alert triage, the investigation scope was narrowed to:

```spl
index=main sourcetype=suricata event_type=alert
```

The lab data was also enriched with `suricata_threat_lookup.csv` for SOC severity, CVE/CVSS context, threat category, MITRE ATT&CK mapping, and analyst recommendations.

## 4. L1 Alert Queue

A reusable SPL query groups Suricata alerts into 15-minute windows and assigns portfolio triage priorities. Brute-force, SQL injection, path traversal, configuration disclosure, command injection, file-read, and similar exploit-oriented detections are prioritized above general scanning activity.

The queue was used to move from raw IDS volume to an analyst-oriented investigation list.

## 5. Investigation — SSH Brute Force

The investigation correlated activity from source `192.168.1.16` to destination `192.168.1.11` on TCP port `22`.

Observed evidence included:

- `SOC DEMO - SSH Brute Force`
- `SOC DEMO - SSH Access Attempt`
- Related flow and SSH telemetry
- Repeated activity across the investigation window

The activity was classified as simulated true-positive attack behavior. Available Suricata telemetry did **not** establish successful authentication or compromise; authentication and endpoint logs would be required for that conclusion.

MITRE ATT&CK mapping used for the demonstrated detection: `T1110` — Brute Force.

## 6. Investigation — Nmap Reconnaissance

The detection `ET SCAN Possible Nmap User-Agent Observed` was investigated by source, destination, port, time window, and related signatures.

Source correlation showed additional detections from the same source, including vulnerability/exploit and SSH brute-force signatures. Because authorization cannot be established from Suricata telemetry alone, the case was retained as **Needs Investigation** rather than being automatically classified as benign.

MITRE ATT&CK mapping: `T1046` — Network Service Discovery.

## 7. Investigation — Vulnerability Detection

Cisco RV320/RV325 configuration-disclosure activity was investigated using a signature-specific SPL query.

Observed evidence included the source, destination systems, destination port, severity, and first/last observed timestamps. The detection was treated as an exploit attempt; the alert alone was not used to claim successful exploitation.

The lookup associates the detection with `CVE-2019-1653` and MITRE `T1190` — Exploit Public-Facing Application.

## 8. Case Management

A lightweight case register was created to demonstrate the L1 operational workflow:

```text
Alert → Validate → Investigate → Classify → Enrich → MITRE
→ Case → Escalate when supported → Document → Close
```

The register contains three demonstrated cases:

| Case | Scenario | Disposition | MITRE |
|---|---|---|---|
| SOC-2026-001 | SSH brute force | True Positive | T1110 |
| SOC-2026-002 | Nmap reconnaissance | Needs Investigation | T1046 |
| SOC-2026-003 | PowerShell → CMD | Benign / Expected | T1059 |

The case register is a portfolio simulation implemented with a Splunk lookup; it is not a production ITSM integration.

## 9. Windows Event ID 4688 Implementation

Windows process-creation auditing was initially disabled in the lab.

Validation:

```powershell
auditpol /get /subcategory:"Process Creation"
```

The setting was enabled with:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

A controlled PowerShell-to-CMD process chain was then generated. Windows Security Event ID `4688` appeared in Splunk.

The verified detection extracts:

- User
- New process
- Creator/parent process
- New process ID
- Creator process ID

The demonstrated analytic identifies `powershell.exe` spawning `cmd.exe`.

Important limitation: the current 4688 telemetry used in this project does not establish the full command line for the controlled test, so the project does not claim command-line visibility beyond what the event actually provided.

## 10. Scheduled Splunk Alert Validation

A scheduled Splunk alert named `Windows - PowerShell Spawned CMD` was configured to run every five minutes and trigger when the detection returned results.

The alert was configured with a Log Event action that writes:

- Host: `Windows-Endpoint`
- Source: `SOC-Alert`
- Sourcetype: `soc_alert`
- Event: `PowerShell Spawned CMD detected`

Validation query:

```spl
index=main sourcetype=soc_alert
| sort - _time
| table _time host source sourcetype _raw
```

A resulting `soc_alert` event confirmed the alert-to-event pipeline in the lab.

## 11. Python Automation

`scripts/ioc_log_processor.py` was added as a basic defensive automation exercise. It processes exported alert CSV data, validates expected fields, normalizes severity into review priority, and produces case-ready output.

This is intentionally a small automation exercise and is not presented as a production SOAR implementation.

## 12. SOC Dashboard

The Splunk dashboard consolidates monitoring and investigation views including alert volume, severity, threat categories, source/destination activity, attack signatures, and analyst-oriented investigation results.

The final evidence set includes:

- Final SOC dashboard
- L1 alert queue
- SSH brute-force investigation
- Nmap/source correlation
- Cisco RV320 investigation
- Windows 4688 endpoint detection
- Case-management queue
- Source activity timeline

Historical dashboard screenshots are also retained in `screenshots/` to show the progression of dashboard development and investigation work.

## 13. Troubleshooting & Lessons Learned

### Windows 4688 auditing

**Problem:** Process Creation auditing was initially disabled.

**Fix:** Enabled successful Process Creation auditing with `auditpol`.

**Result:** Controlled process creation generated Event ID 4688 and became searchable in Splunk.

### Windows event parsing

**Problem:** Initial Windows event ingestion used XML rendering that made the raw events difficult to parse for the intended SPL.

**Fix:** The Windows Security input was changed to use non-XML rendering for the implemented detection.

**Result:** Event ID 4688 fields could be extracted reliably for the demonstrated analytic.

### Alert validation

**Problem:** A detection can show matching activity without proving compromise.

**Resolution:** Investigations were documented with explicit evidence limits and recommended validation steps rather than overstating the result.

## 14. Current Scope and Limitations

- Suricata is the verified network IDS used in the final project.
- Splunk Enterprise is the verified SIEM platform used for ingestion, investigation, dashboards, and alerting.
- The verified Windows endpoint analytic uses native Security Event ID 4688.
- Sysmon is documented as an optional extension; the project does not claim successful Sysmon Event ID 1 ingestion where it was not observed.
- The case-management layer is a lookup-based simulation, not ServiceNow/Jira.
- The project does not claim enterprise EDR/XDR, SOAR, automated containment, or production incident response.
- Suricata detections are treated as evidence requiring validation, not as proof of successful exploitation or compromise.

## 15. Evidence

See the repository `screenshots/` directory and the following documentation:

- `documentation/architecture.md`
- `documentation/alert-triage.md`
- `documentation/investigation-workflow.md`
- `documentation/incident-case-management.md`
- `splunk/searches.md`
- `splunk/dashboard.md`
- `splunk/case-management.md`
- `splunk/endpoint-detections.md`
- `endpoint-telemetry/README.md`
