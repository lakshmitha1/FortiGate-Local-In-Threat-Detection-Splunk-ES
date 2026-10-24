# FortiGate Local-In Threat Detection Using Splunk Enterprise Security

## 1. Project Overview

This project demonstrates a Security Operations Center (SOC) workflow for identifying repeated blocked local-in traffic targeting a FortiGate firewall using Splunk Enterprise Security (ES).

The project covers detection engineering, correlation search configuration, notable event verification, incident documentation in ServiceNow, severity classification, and remediation recommendations.

**Environment:** Security lab  
**SIEM:** Splunk Enterprise Security  
**Log source:** FortiGate firewall logs  
**Incident management:** ServiceNow

> **Disclaimer:** This is a lab investigation. Repeated blocked events do not independently prove a successful attack. Validate the log source and activity before classifying an event as a confirmed threat.

## 2. Objectives

- Analyze FortiGate firewall logs in Splunk.
- Identify repeated blocked local-in traffic.
- Create a Splunk ES correlation search.
- Configure a Notable response action.
- Verify alert generation in Incident Review.
- Document the investigation in ServiceNow.
- Recommend appropriate remediation.

## 3. Detection Logic

The correlation search identifies blocked FortiGate local-in events, groups them into five-minute intervals, and counts events by source IP, destination IP, and destination port.

**Detection threshold:** 20 or more blocked events in a five-minute bucket.

**Potential security concern:** Repeated attempts to access firewall-local services may indicate probing or unauthorized access attempts. Further investigation is required.

## 4. Splunk SPL

```spl
index=* vendor_product="Fortinet Firewall" action="blocked"
| search subtype="local"
| where in(policytype, "local-in-policy", "local-in-policy6")
| eval src_ip=coalesce(src_ip, srcip),
       dest_ip=coalesce(dest_ip, dstip),
       dest_port=coalesce(dest_port, dstport)
| bin _time span=5m
| stats count as blocked_count
    by _time src_ip dest_ip dest_port
| where blocked_count >= 20
| sort - blocked_count
```

**Note:** Field names depend on the FortiGate log format and field extractions in your environment. Validate the query against your actual events.

## 5. Investigation Workflow

1. Search FortiGate logs in Splunk.
2. Identify repeated blocked local-in events.
3. Configure and save the correlation search.
4. Verify whether a notable event is generated in Splunk ES Incident Review.
5. Create a ServiceNow incident to document the findings.
6. Record evidence, severity rationale, and recommended remediation.

## 6. Incident Management

**Incident title:** Repeated Blocked Local-In Attempts Against FortiGate

**ServiceNow incident:** INC0010004

**Initial severity assessment:** Low, pending investigation.

**Evidence to record:**
- Event timestamps
- Source and destination IP addresses
- Destination ports
- Blocked-event counts
- Correlation-search results
- Notable event status

## 7. Remediation Recommendations

- Review source IP addresses and their reputation.
- Validate local-in firewall policies and exposed management services.
- Check for related allowed connections or successful authentication.
- Restrict unauthorized access where appropriate.
- Escalate according to organizational incident response procedures if malicious activity is confirmed.
- Document the investigation outcome and update the incident status.

## 8. Project Evidence

Add sanitized screenshots showing:

- FortiGate log search results
- Correlation search configuration
- Detection results
- Incident Review results, if a notable was generated
- ServiceNow incident and investigation notes

## 9. Learning Outcomes

- SPL-based security detection
- Splunk ES correlation searches
- Notable event investigation
- Firewall log analysis
- Incident severity classification
- ServiceNow incident documentation
- SOC investigation and remediation workflow

## 10. Limitations

This project demonstrates a detection and incident documentation workflow. A correlation-search result does not prove a successful compromise, and a ServiceNow ticket does not itself establish that remediation was completed. All findings should be validated against the available evidence.
