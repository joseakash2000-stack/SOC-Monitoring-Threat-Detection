# MITRE ATT&CK Mapping

This document maps selected Suricata detections to MITRE ATT&CK techniques for SOC L1 behavioral analysis.

> ATT&CK mappings in this project are analyst classifications for controlled lab telemetry. A detection or mapping does not by itself prove successful compromise.

## Detection Mapping

| Detection / Activity | Severity | Threat Category | Tactic | Technique | MITRE ID |
|---|---|---|---|---|---|
| ET SCAN Possible Nmap User-Agent Observed | Medium | Network Scan | Discovery | Network Service Discovery | T1046 |
| Cisco ASA / Firepower Path Traversal — CVE-2020-3452 | Critical | Exploit Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| Cisco RV320/RV325 Config Disclosure — CVE-2019-1653 | High | Exploit Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| D-Link DSL-2750B OS Command Injection — CVE-2016-20017 | Critical | Command Injection | Execution | Command and Scripting Interpreter | T1059 |
| F5 TMUI RCE — CVE-2020-5902 | Critical | RCE Attempt | Initial Access | Exploit Public-Facing Application | T1190 |
| Drupal SQL Injection — CVE-2014-3704 | Critical | SQL Injection | Initial Access | Exploit Public-Facing Application | T1190 |
| HTTP POST contains `pass=` in cleartext | Medium | Cleartext Credential Exposure | Contextual Credential Exposure | No direct technique assigned | — |
| SOC DEMO - SSH Brute Force | Critical | Credential Attack | Credential Access | Brute Force | T1110 |
| Possible Kali Linux hostname in DHCP Request Packet | Low | Reconnaissance Context | Contextual | No direct technique assigned | — |

## Mapping Rationale

### T1046 — Network Service Discovery

Applied to the Nmap User-Agent detection because the observed activity can represent network service discovery. The analyst should establish whether the scanner is authorized and correlate the source with targeted systems and ports.

### T1190 — Exploit Public-Facing Application

Applied to detections representing exploitation attempts against exposed applications or network appliances, including Drupal SQL injection and Cisco ASA/Firepower vulnerability activity.

### T1059 — Command and Scripting Interpreter

Applied to the D-Link OS command-injection detection as a behavioral classification. Investigation should determine whether command execution actually occurred.

### T1110 — Brute Force

Applied to the custom SSH brute-force detection. Investigation should include authentication failures, successful logins, targeted accounts, and related activity from the source.

## Contextual Detections

Some network detections provide useful security context but do not provide enough evidence to assign a specific ATT&CK technique confidently.

A DHCP request containing a Kali Linux hostname may indicate the presence of a security-testing system, but the hostname alone does not establish attacker behavior. It is therefore retained as contextual evidence rather than mapped to an ATT&CK technique.

Likewise, an HTTP request containing `pass=` in cleartext indicates potential credential exposure, but the Suricata network event alone does not establish that an adversary captured or used the credential. It is therefore treated as contextual credential-exposure evidence rather than forcing an unsupported ATT&CK mapping.

## L1 Mapping Workflow

1. Identify the alert signature.
2. Determine the associated threat category.
3. Review the mapped ATT&CK tactic and technique, if applicable.
4. Validate the network context and affected asset.
5. Correlate related alerts and events.
6. Look for evidence of successful exploitation, authentication, or impact.
7. Document the classification and escalation requirements.

## Analyst Guidance

MITRE ATT&CK should provide behavioral context, not replace investigation. Analysts should correlate the Suricata event with timestamps, source/destination information, repeated activity, endpoint logs, authentication logs, application logs, and other available evidence.

## Project Coverage

The current project demonstrates coverage across:

- Initial Access
- Execution
- Credential Access
- Discovery
- Contextual reconnaissance analysis
