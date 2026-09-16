# SOC Traffic Analysis Labs

Packet capture analysis practice for SOC analyst work: real, publicly available malware traffic captures, each worked through in Wireshark and written up as a standalone incident report.

Each lab starts from a realistic trigger (an IDS alert, or just an environment reference sheet and a pcap), scopes the infected host, identifies who and what was affected, pulls indicators of compromise, and closes with scope limitations and recommendations, the same shape an analyst would hand to a response team or use to justify next steps.

## Labs

| Lab | Malware / Activity | Starting Point | Report |
|---|---|---|---|
| [FormBook C2 Activity](formbook-traffic-analysis/) | FormBook | Six IDS alerts (FormBook CnC Checkin) naming external IPs only | [README](formbook-traffic-analysis/README.md) |
| [Lumma Stealer C2 Activity](lumma-stealer-traffic-analysis/) | Lumma Stealer | Single IDS alert (victim fingerprinting) naming one external IP/port | [README](lumma-stealer-traffic-analysis/README.md) |
| [KongTuke ClickFix Infection](kongtuke-clickfix-traffic-analysis/) | KongTuke / ClickFix | No alert, only an environment reference sheet, scoped cold from DNS traffic | [README](kongtuke-clickfix-traffic-analysis/README.md) |

Every capture is a public training exercise from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/); each lab links to its specific source post.

## What each lab covers

The reports vary in starting point on purpose, an alert with one IP, an alert with several, and no alert at all, since a real SOC queue includes all three. From there, each one works through the same core questions:

- Which internal host is actually involved, and how is that scoped from the alert (or from raw traffic when there's no alert)
- The host's identity: IP, MAC address (from the Ethernet source field, tied to a segment, not the far end of the connection), and hostname
- The logged-on user: pulled from Kerberos AS-REQ traffic (the one exchange where identity isn't encrypted), then cross-checked through SAMR, the protocol Windows itself uses to resolve an account name to a full display name
- The malicious infrastructure involved: C2 domains/IPs, URI patterns, and any other indicators worth blocking or hunting on
- What the capture can't answer: none of these pcaps show the initial infection vector, so each report says so explicitly rather than guessing, and names what additional telemetry (EDR, mail gateway, proxy logs) would be needed to close that gap

Each README also documents mistakes worth flagging to a future self: mixing up Kerberos `cname` (the requester) with `sname` (almost always `krbtgt`, the TGT service, not a user), assuming a MAC address means anything beyond the local segment, or trusting an environment reference sheet without checking it against the traffic.

## Tools

- Wireshark / tshark for packet analysis
- Suricata/ET Open signature context, where an alert was part of the exercise

## Source material and scope

All packet captures analyzed here are publicly available training exercises from malware-traffic-analysis.net, used under that site's own access terms. Pcap files are not redistributed in this repository; each lab's README links back to the original source post. Every report is explicitly labeled as a training exercise, not a real-world incident, and any names, hostnames, or usernames referenced come from the exercise data itself, not real individuals.

This repository is a working practice log, not a finished portfolio piece: labs are added as new exercises are worked through, and earlier reports may be revisited as technique improves.
