# Windows Endpoint Telemetry Extension

This directory documents the Windows endpoint investigation extension used with the SOC lab. The **verified portfolio implementation uses Windows Security Event ID 4688 (Process Creation)** and Splunk Enterprise. Sysmon is retained as an optional setup/investigation guide and is not claimed as successfully ingested telemetry unless events are actually observed.

## Verified Architecture

```text
Windows Lab Endpoint
        ↓
Windows Security Audit Policy
        ↓
Event ID 4688 — Process Creation
        ↓
Splunk Enterprise
        ↓
SPL Detection
        ↓
Scheduled Alert
        ↓
Alert Action / Log Event
        ↓
L1 Triage / MITRE / Case Workflow
```

## Verified Detection

The demonstrated detection identifies a **PowerShell process spawning `cmd.exe`** from Windows Security Event ID 4688.

The SPL extracts:

- User
- New process path
- Creator/parent process path
- New process ID
- Creator process ID

The detection was validated with controlled lab activity. The resulting activity was classified as **Benign/Expected** because it was intentionally generated for detection validation. The available event does not establish a malicious command line or compromise.

Example search pattern:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| rex field=Message "Account Name:\s+(?<user>[^\r\n]+)"
| rex field=Message "New Process Name:\s+(?<process_path>[^\r\n]+)"
| rex field=Message "Creator Process Name:\s+(?<parent_process>[^\r\n]+)"
| rex field=Message "New Process ID:\s+(?<process_id>0x[0-9a-fA-F]+)"
| rex field=Message "Creator Process ID:\s+(?<parent_process_id>0x[0-9a-fA-F]+)"
| eval process=lower(process_path)
| eval parent=lower(parent_process)
| where like(process,"%cmd.exe%") AND like(parent,"%powershell.exe%")
| eval detection_name="PowerShell Spawned CMD"
| eval severity="Medium"
| eval mitre_id="T1059"
| eval mitre_technique="Command and Scripting Interpreter"
| table _time user detection_name severity parent_process process_path process_id parent_process_id mitre_id mitre_technique
| sort - _time
```

## Alert Validation

The lab also validates the scheduled Splunk alert pipeline for this detection:

```text
Windows 4688
    ↓
SPL Detection
    ↓
Scheduled Alert
    ↓
Log Event Action
    ↓
SOC alert event
    ↓
Case / Triage workflow
```

This demonstrates alert generation and action handling without claiming SOAR or enterprise ITSM integration.

## Windows Event 4688 Setup

Process Creation auditing was enabled with Windows Audit Policy. Verify the setting with:

```powershell
auditpol /get /subcategory:"Process Creation"
```

The expected state for this lab is successful auditing enabled. Generate only controlled, authorized lab activity and verify Event ID 4688 in the Windows Security log before investigating it in Splunk.

## Sysmon Extension — Optional Guide

Sysmon was explored as an endpoint telemetry extension, but the portfolio evidence is **not based on claiming successful ingestion of a broad Sysmon event set**. The directory can be used as a guide for future lab expansion.

Potential Sysmon investigation areas include process creation, network connections, file creation, registry changes and DNS queries. These should only be documented as implemented after the corresponding events are actually observed and ingested.

## L1 Triage Workflow

```text
Endpoint Alert
    ↓
Validate Host + User + Timestamp
    ↓
Review Parent / Child Process Context
    ↓
Check Related Events
    ↓
Determine True Positive / False Positive / Benign / Needs Investigation
    ↓
Map MITRE ATT&CK if Supported
    ↓
Create / Update Case
    ↓
Escalate if Evidence Supports Incident
    ↓
Document + Close
```

## Portfolio Boundary

This project demonstrates Windows endpoint telemetry and EDR-style investigation concepts. It does **not** claim CrowdStrike, Microsoft Defender for Endpoint, SentinelOne, or another commercial EDR product, and it does not claim production SOAR or ITSM integration.
