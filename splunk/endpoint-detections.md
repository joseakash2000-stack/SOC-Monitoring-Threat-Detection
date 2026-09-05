# Splunk Windows Endpoint Detection Searches

These searches are for Sysmon telemetry collected from a Windows lab endpoint. They complement the network detections from Suricata and provide endpoint-side context for L1 investigation.

## Base Search

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

## 1. Process Creation — Sysmon Event ID 1

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| stats count by Image ParentImage User
| sort - count
```

**Use:** Identify frequently observed process/parent-process combinations and investigate unusual executions.

## 2. Network Connections — Event ID 3

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
| stats count by Image DestinationIp DestinationPort
| sort - count
```

**Use:** Pivot from an endpoint process to its network destinations.

## 3. Process Access — Event ID 10

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
| stats count by SourceImage TargetImage GrantedAccess
| sort - count
```

**Use:** Identify unusual process-access relationships for deeper validation.

## 4. File Creation — Event ID 11

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11
| stats count by Image TargetFilename User
| sort - count
```

## 5. Registry Changes — Event ID 13

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13
| stats count by Image TargetObject Details User
| sort - count
```

## 6. DNS Queries — Event ID 22

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| stats count by Image QueryName
| sort - count
```

## 7. Endpoint Investigation Pivot

Start with a suspicious process and pivot to related network activity:

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image="<IMAGE>"
| table _time Computer User Image CommandLine ParentImage ProcessId
| sort - _time
```

Then:

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3 Image="<IMAGE>"
| table _time Computer Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

## 8. Network-to-Endpoint Correlation Concept

The project now supports a two-sided investigation model:

```text
Suricata Network Alert
        ↓
Source / Destination / Port
        ↓
Identify Target Host
        ↓
Pivot to Windows Sysmon
        ↓
Process / Network / File / Registry / DNS Events
        ↓
Assess True Positive / False Positive
        ↓
MITRE ATT&CK Context
        ↓
Case + Escalation Decision
```

This is a lab workflow. Correlation should be based on timestamps, host identity, IP addresses, process context, and other available evidence rather than assuming that two events are related.
