# Honeypot SIEM Lab

## Overview

This repository documents my hands-on honeypot and SIEM analysis lab using T-Pot, Elastic, Kibana, and Suricata. The purpose of this project is to collect real internet-facing honeypot telemetry, analyze suspicious activity, and write clear SOC-style reports based on observable evidence.

The lab focuses on defensive security skills such as alert review, traffic analysis, log filtering, service exposure analysis, and professional incident documentation.

## Lab Stack

| Tool / Platform | Purpose |
|---|---|
| T-Pot | Honeypot platform used to collect attacker/scanner activity |
| Elastic / Elasticsearch | Stores and indexes honeypot and network telemetry |
| Kibana | Used to search, filter, and analyze collected events |
| Suricata | Network detection engine used for alerting and protocol analysis |
| Contabo VPS | Cloud-hosted environment used to expose the honeypot to the internet |
| KQL | Kibana Query Language used to filter and investigate events |

## Skills Demonstrated

This project demonstrates practical blue-team skills, including:

- Honeypot deployment and monitoring
- SIEM investigation workflow
- Kibana Discover analysis
- KQL filtering
- Suricata alert review
- Network traffic analysis
- Service and port exposure analysis
- Evidence-based SOC reporting
- Distinguishing scanning/probing from confirmed exploitation
- Reviewing credential-guessing activity
- Identifying post-login reconnaissance commands
- Writing clear remediation recommendations

## Reports

| Report | Description |
|---|---|
| [001 - T-Pot Initial Analysis](reports/001-tpot-initial-analysis.md) | Initial review of external scanning and probing activity observed against the honeypot using Kibana, Elastic, and Suricata. |
| [002 - T-Pot 24-Hour Analysis](reports/002-tpot-24hr-analysis.md) | 24-hour review of Honeytrap and Cowrie activity, including broad port scanning, SSH credential guessing, and post-login reconnaissance commands. |
| [003 - T-Pot Multi-Day SIP/VoIP Analysis](reports/003-tpot-multiday-sip-analysis.md) | Multi-day review showing SentryPeer/SIP activity dominance, SIP port 5060 probing, INVITE/REGISTER activity, VoIP user-agent patterns, and possible toll-fraud reconnaissance indicators. |
| [004 - T-Pot Multi-Service Honeypot Overview](reports/004-tpot-multiservice-overview.md) | High-level review of approximately 2 million honeypot events, including SentryPeer, Honeytrap, Cowrie, Dionaea, Ciscoasa, top destination ports, activity spikes, and multi-service probing patterns. |
| [005 - Cowrie Credential and Payload Analysis](reports/005-cowrie-credential-and-payload-analysis.md) | Deep dive into Cowrie SSH/Telnet activity, including credential guessing, successful honeypot logins, command input, BusyBox checks, payload download attempts, file download events, and captured hashes. |

## Current Findings

The current reports focus on several types of external activity observed against the honeypot:

- SMBv1-related probing on TCP/445
- Telnet probing on TCP/23
- HTTP probing and header anomalies on TCP/80
- Broad scanning activity across exposed services
- Honeytrap-based port scanning and service discovery
- Cowrie SSH credential-guessing activity
- Captured post-login reconnaissance commands
- Source IP and country distribution analysis
- Suricata alert review and interpretation
- Multi-day SentryPeer/SIP activity dominance
- SIP/VoIP probing targeting port 5060
- INVITE and REGISTER traffic suggesting possible VoIP/toll-fraud reconnaissance
- SIP user-agent patterns tied to VoIP clients and scanner-like tools

The findings are based on observed honeypot telemetry and should be interpreted as source infrastructure activity, not confirmed attacker attribution.

## Methodology

The analysis process generally follows this workflow:

1. Confirm T-Pot and supporting services are running.
2. Review collected events in Kibana Discover.
3. Filter out management traffic and internal VPS-related noise.
4. Identify top source IPs, countries, destination ports, protocols, and alert signatures.
5. Investigate higher-value alerts, such as Major-severity Suricata findings.
6. Document evidence with screenshots and KQL filters.
7. Write SOC-style findings with analysis and remediation recommendations.

## Notes on Data Handling

This repository does not include raw log exports, malware samples, credentials, private keys, or sensitive system access information. Screenshots are redacted where needed to avoid exposing active infrastructure details.

IP addresses shown in reports should be treated as observed source infrastructure only. Geolocation does not prove the true origin of an attacker, especially when traffic may come from hosting providers, proxies, scanners, or compromised systems.

## Disclaimer

This project is for educational and portfolio purposes only. The honeypot was deployed in a controlled lab environment to observe unsolicited internet traffic and practice defensive security analysis. No offensive activity was performed against third-party systems.
