# Splunk Windows Endpoint Detection Searches

This file documents the **verified Windows endpoint detection** used in the SOC lab. The implemented telemetry source is the native Windows Security log with **Event ID 4688 (Process Creation)**. Sysmon searches are intentionally not presented here as verified ingestion.

## Verified Detection

The demonstrated detection identifies **PowerShell spawning `cmd.exe`** from Windows Security Event ID 4688.

The SPL extracts:

- User
- New process path
- Creator/parent process path
- New process ID
- Creator process ID

The controlled test was intentionally generated to validate the detection and was classified as **Benign/Expected**. The available event does not establish a malicious command line or compromise.

## Base Search

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
```

## 1. PowerShell → CMD Process Creation

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

**Purpose:** Detect a suspicious parent/child process relationship for L1 review while requiring analyst validation of the user, command line, host, and surrounding activity.

## 2. Recent Windows 4688 Process Creation Events

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| table _time host user New_Process_Name Creator_Process_Name New_Process_ID Creator_Process_ID
| sort - _time
```

**Purpose:** Review recent process-creation telemetry before narrowing the investigation to a specific process relationship.

## 3. Endpoint Investigation Pivot

Start with the detected process relationship and review the surrounding Event ID 4688 activity:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search Message="*cmd.exe*"
| table _time host Message
| sort - _time
```

Then validate:

1. User account and host
2. Parent/child process relationship
3. Process creation timestamp
4. Command-line evidence, if available
5. Related authentication or endpoint events
6. Related network activity

## 4. Scheduled Alert Validation

The lab also validates the Splunk alert pipeline for the PowerShell-to-CMD detection:

```text
Windows Security Event 4688
        ↓
SPL Detection
        ↓
Scheduled Alert
        ↓
Log Event Action
        ↓
SOC Alert Event
        ↓
Case / Triage Workflow
```

This demonstrates alert generation and action handling without claiming SOAR or enterprise ITSM integration.

## 5. L1 Triage Decision

```text
Event ID 4688 Detection
        ↓
Validate Host + User + Timestamp
        ↓
Review Parent / Child Process
        ↓
Review Command Line + Related Events
        ↓
Benign / Expected / False Positive / Needs Investigation
        ↓
MITRE ATT&CK Context When Supported
        ↓
Case + Escalation Decision
```

The controlled PowerShell-to-CMD test is **Benign/Expected** because it was intentionally generated for validation. A real occurrence would require additional endpoint, user, command-line, authentication and network context before classification.

## Sysmon Boundary

The repository retains a Sysmon setup/investigation guide as an optional extension. Potential Sysmon searches may cover process creation, network connections, file creation, registry changes and DNS queries, but those events should only be described as implemented after they are actually observed and ingested.

See [`../endpoint-telemetry/README.md`](../endpoint-telemetry/README.md) for the verified Windows 4688 workflow and the optional Sysmon extension.
