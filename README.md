# Windows SOC & IT Labs

Hands-on Windows detection and troubleshooting labs with synthetic data and reproducible results.

## Lab 01 · Windows failed-logon triage

**Scenario.** You are reviewing failed Windows logons on a file server. Identify the burst, determine which accounts it targeted, and decide what evidence you need before escalating.

**Detection.** Flag five or more Windows Security Event ID 4625 records with Logon Type 3 (network) from the same source IP to the same computer in a fixed five-minute window. Exclude rows without a usable source address. Windows records Event 4625 when a logon fails and Event 4624 when a logon succeeds. The included CSV uses simplified field names and fictional users, hosts, and documentation-range IPs.

### Run in Splunk

1. Download [windows_failed_logon_events.csv](windows_failed_logon_events.csv).
2. In Splunk Web, go to **Settings → Lookups → Lookup table files → New**. Choose **Search & Reporting** as the destination app, upload the CSV, and set the destination filename to `windows_failed_logon_events.csv`.
3. Open **Search & Reporting** in the same app context and run this SPL. A Splunk index or forwarder is unnecessary for this exercise.

```spl
| inputlookup windows_failed_logon_events.csv
| eval event_id=tonumber(event_id), logon_type=tonumber(logon_type),
       source_ip=trim(source_ip), event_epoch=strptime(event_time,"%Y-%m-%dT%H:%M:%S%z")
| where event_id=4625 AND logon_type=3 AND isnotnull(event_epoch)
    AND isnotnull(source_ip) AND source_ip!="" AND source_ip!="-"
| bin event_epoch span=300
| stats count AS failures dc(target_user) AS distinct_users
        values(target_user) AS accounts BY event_epoch source_ip computer
| where failures>=5
| sort 0 event_epoch source_ip computer
| eval window_start=strftime(event_epoch,"%Y-%m-%d %H:%M:%S %z")
| table window_start source_ip computer failures distinct_users accounts
```

### Expected result

Exactly one result, shown here in UTC. Splunk may display the same window in your configured time zone.

| Window start (UTC) | Source IP | Target computer | Failures | Distinct users | Accounts |
|---|---|---|---|---:|---:|---|
| 2026-10-01 10:00:00 | 192.0.2.41 | FILE01 | 6 | 3 | svc_backup, user_amina, user_sami |

Four attempts from a different source stay below the threshold. A failure just after 10:05 belongs to the next bucket. Local interactive failures, rows missing an address, and successful logons are excluded from the detection.

### Triage checklist

1. Inspect the matching 4625 rows. Capture the source, destination, accounts, logon type, timestamps, and status codes.
2. Look for 4624 successes involving the same source, computer, and targeted accounts. The fixture includes a success for `user_amina` at 10:04:47 UTC. Verify the source asset and account activity before deciding whether it is related.
3. Check for a scheduled task, service, mapped drive, or stale stored credential. Look for activity from the source on other hosts and identify privileged or service accounts in the burst.
4. Write a short case note with the evidence, a plausible benign explanation, missing telemetry, and the next step. An example: “Six network failures from 192.0.2.41 targeted three FILE01 accounts. One targeted account later logged on successfully from the same source. Verify the source asset and whether the login was expected before escalating.”

### Verify without Splunk

With Python 3.8 or newer, run:

```bash
python verify_lab.py
```

The verifier applies the same filters, UTC bucket size, and grouping to the CSV and checks the expected alert. It checks the reference logic independently of Splunk.

### Limits

Fixed windows can split a burst across a bucket boundary. Grouping by destination can miss activity spread across several hosts. Shared source IPs and misconfigured services can create false positives. For real logs, map your collector's fields, validate audit coverage and source-address quality, and tune thresholds against your baseline.

### References

- [Microsoft Learn · Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Microsoft Learn · Event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Splunk · Define a CSV lookup](https://help.splunk.com/?resourceId=SplunkCloud_Knowledge_Usefieldlookupstoaddinformationtoyourevents)
- [Splunk · inputlookup](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.2/search-commands/inputlookup)
