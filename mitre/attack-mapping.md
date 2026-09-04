# MITRE ATT&CK Mapping

This document maps the project's Suricata detections to MITRE ATT&CK tactics and techniques used during SOC L1 triage.

## Detection Mapping

| Detection / Activity | Severity | Threat Category | Tactic | Technique | MITRE ID |
|---|---|---|---|---|---|
| ET SCAN Possible Nmap User-Agent Observed | Medium | Network Scan | Discovery | Network Service Discovery | T1046 |
| ET INFO Possible Kali Linux hostname in DHCP Request Packet | Low | Reconnaissance | Reconnaissance | Acquire Infrastructure | T1583 |
| Cisco ASA / Firepower Path Traversal — CVE-2020-3452 | Critical | Exploit Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| Cisco RV320/RV325 Config Disclosure — CVE-2019-1653 | High | Exploit Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| D-Link DSL-2750B OS Command Injection — CVE-2016-20017 | Critical | Command Injection | Execution | Command and Scripting Interpreter | T1059 |
| F5 TMUI RCE — CVE-2020-5902 | Critical | RCE Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| Drupal SQL Injection — CVE-2014-3704 | Critical | SQL Injection | Initial Access | Exploit Public-Facing Application | T1190 |
| HTTP POST contains `pass=` in cleartext | Medium | Cleartext Credential Exposure | Credential Access | Credentials from Password Stores | T1555 |
| SOC DEMO - SSH Brute Force | Critical | Credential Attack | Credential Access | Brute Force | T1110 |

## Tactic Overview

### Reconnaissance

**T1583 — Acquire Infrastructure**

Used in this project for the detection associated with a Kali Linux hostname observed in DHCP traffic. This classification is used as contextual reconnaissance evidence and should be correlated with additional activity before escalation.

### Initial Access

**T1190 — Exploit Public-Facing Application**

Used for detections representing exploitation attempts against exposed applications or network appliances, including the Drupal SQL injection and Cisco ASA/Firepower vulnerability detections.

### Execution

**T1059 — Command and Scripting Interpreter**

Used for the D-Link OS command-injection detection. The specific command-injection activity should be investigated for evidence of successful command execution or subsequent compromise.

### Credential Access

**T1110 — Brute Force**

Used for the custom SSH brute-force detection. Investigation should include authentication failures, successful logins, targeted accounts, and related activity from the source.

**T1555 — Credentials from Password Stores**

Used in this project for the HTTP cleartext password exposure detection as the lookup classification. Analysts should validate the actual protocol/application context and determine whether credentials were exposed.

### Discovery

**T1046 — Network Service Discovery**

Used for the Nmap User-Agent detection. The activity should be validated against authorized scanning and correlated with the systems and ports targeted.

## L1 Mapping Workflow

1. Identify the alert signature.
2. Determine the associated threat category.
3. Review the mapped MITRE ATT&CK tactic.
4. Identify the technique and ATT&CK ID.
5. Validate the network context and affected asset.
6. Correlate related alerts and events.
7. Document findings and escalation requirements.

## Analyst Guidance

MITRE ATT&CK mapping provides behavioral context; it does not by itself prove that an attack succeeded. A Suricata alert should be investigated using the source/destination context, timestamps, repeated activity, relevant endpoint or application logs, and evidence of successful exploitation or access.

## Project Coverage

The current project demonstrates coverage across:

- Reconnaissance
- Initial Access
- Execution
- Credential Access
- Discovery

The mapping is intended for controlled SOC lab telemetry and portfolio demonstration.
