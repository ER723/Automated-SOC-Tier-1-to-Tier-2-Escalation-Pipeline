# Wazuh Custom Rules → Sigma Mapping

Three of the pipeline's custom escalation rules, expressed in Sigma — the vendor-agnostic detection format. Each was validated with the real `sigma-cli` tool, including a working conversion to Splunk query syntax, confirming they're genuinely well-formed and portable, not just YAML that resembles a Sigma rule.

## Mapping table

| Sigma rule | MITRE technique | Wazuh source rule | Custom escalation rule | Rule type |
|---|---|---|---|---|
| `T1110-sudo-bruteforce.yml` | T1110 (Brute Force) | 5404 | 100100 | Native OS auth log |
| `T1014-rootcheck-anomaly.yml` | T1014 (Rootkit) | 510 | 100101 | Meta-detection (see note) |
| `T1571-new-listening-port.yml` | T1571 (Non-Standard Port) | 533 | 100102 | Meta-detection (see note) |

## Important honesty note: two different categories of Sigma rule here

**The sudo rule is a "clean" Sigma rule** — it matches directly against a native OS authentication log message. This is the textbook Sigma use case: a raw log line, translatable to any SIEM.

**The rootcheck and port-change rules are meta-detections** — they match against *Wazuh's own alert output*, not a raw OS or network log. Rootcheck's rootkit heuristics and Wazuh's netstat-diff polling are both internal Wazuh mechanisms with no equivalent structured log format outside Wazuh itself. This is a legitimate, recognized pattern in detection engineering (rules that fire on another tool's findings, sometimes called "correlation" or "alert-on-alert" rules) — but it's a meaningfully different, less portable category than a rule built on a raw log source, and worth being precise about rather than implying all three are equally portable.

## Verifying these rules yourself

```bash
pip install sigma-cli
sigma convert -t splunk --without-pipeline sigma-rules/T1110-sudo-bruteforce.yml
sigma convert -t splunk --without-pipeline sigma-rules/T1014-rootcheck-anomaly.yml
sigma convert -t splunk --without-pipeline sigma-rules/T1571-new-listening-port.yml
```

Each converts to a working Splunk search — confirmed during development. Other backends (Elastic, Sentinel/KQL, etc.) are also supported by `sigma-cli`, subject to that backend's own field-mapping requirements.
