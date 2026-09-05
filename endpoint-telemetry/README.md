# Windows Endpoint Telemetry Extension

This extension adds Windows endpoint telemetry to the existing Suricata + Splunk SOC lab. It is designed to practice the endpoint-investigation concepts commonly used by EDR/XDR platforms without claiming a commercial EDR integration.

## Architecture

```text
Windows Lab Endpoint
        ↓
      Sysmon
        ↓
Windows Event Log
        ↓
 Splunk Universal Forwarder
        ↓
  Splunk Enterprise
        ↓
Endpoint Investigation SPL
        ↓
MITRE ATT&CK / Case Workflow
```

## Telemetry Focus

The lab focuses on these Sysmon events:

| Event ID | Focus |
|---:|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image/DLL load |
| 10 | Process access |
| 11 | File creation |
| 13 | Registry value set |
| 22 | DNS query |

## L1 Investigation Examples

### Suspicious process creation

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| table _time Computer User Image CommandLine ParentImage ProcessId
| sort - _time
```

Review the process image, command line, parent process, user, and execution time. Map suspicious behavior to MITRE ATT&CK only after validating the context.

### Network connections from a process

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
| table _time Computer Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

Correlate unusual process/network combinations with other alerts and the destination service.

### Process access

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
| table _time Computer SourceImage TargetImage GrantedAccess CallTrace
| sort - _time
```

Use this as an investigation starting point for unusual process-access behavior. Do not classify activity as malicious from Event ID 10 alone.

### File creation

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11
| table _time Computer Image TargetFilename User
| sort - _time
```

### Registry modification

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13
| table _time Computer Image TargetObject Details User
| sort - _time
```

### DNS activity

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| table _time Computer Image QueryName QueryStatus User
| sort - _time
```

## Triage Workflow

```text
Endpoint Alert
    ↓
Validate Host + User + Timestamp
    ↓
Review Process / Network / File / Registry / DNS Context
    ↓
Check Related Events
    ↓
Determine True Positive / False Positive / Benign
    ↓
Map MITRE ATT&CK if Supported
    ↓
Create / Update Case
    ↓
Escalate if Evidence Supports Incident
    ↓
Document + Close
```

## Setup Notes

1. Install Sysmon on a Windows lab VM.
2. Configure Sysmon using an appropriate defensive configuration for a controlled environment.
3. Verify events in `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`.
4. Configure Splunk Universal Forwarder to collect the Sysmon Operational channel.
5. Confirm ingestion in Splunk before using the searches above.
6. Generate only authorized lab activity and document the resulting events.

## Important Portfolio Boundary

This directory demonstrates **endpoint telemetry and EDR-style investigation concepts**. It does not claim that the project uses CrowdStrike, Microsoft Defender for Endpoint, SentinelOne, or another commercial EDR product. Add a specific EDR product to the resume only after completing and documenting hands-on work with it.
