# dmark

`dmark` is a local CLI for bulk DMARC aggregate report evaluation.

It handles:
- `.xml` and `.xml.gz` DMARC report files
- Optional extraction of DMARC attachments from a `.pst` export
- Local web UI for upload or folder-path analysis
- Domain-level pass/fail metrics and actionable recommendations

## Why this helps

For large mailboxes (thousands of DMARC report emails), this tool gives you:
- DMARC pass/fail rates
- Authentication vs alignment split (DKIM auth vs aligned, SPF auth vs aligned)
- DKIM/SPF alignment rates
- Policy/disposition summary
- Top failing source IPs
- Sender inventory (top senders, new since last run, optional approved-sender tagging)
- Historical Trend Score (all observed traffic) with factor-by-factor point deductions
- Severity-ranked issues with likely causes and a concrete action plan
- Policy impact simulator (estimated affected volume at `p=quarantine` / `p=reject`)
- Dual scoring: deliverability safety + anti-spoofing posture
- Four-pillar posture view: protection posture, deliverability safety, authentication coverage, and attack pressure
- Daily trend charts in the web UI (stacked source-category volume + split legitimate-vs-attack fail rates, UTC buckets)
- Receiver-side relay classification for known infrastructure patterns (e.g., `cloud-sec-av.com`)
- Auto sender classification for common M365 outbound and receiver-side relay patterns
- Dynamic M365-specific action plan output (DKIM enablement + selector CNAME guidance)
- Optional live DNS diagnostics (DMARC/SPF TXT + DKIM selector CNAME/TXT checks) to tailor remediation steps

## Install

From PyPI:

```powershell
python -m pip install dmark
```

From this repo (editable/dev):

```powershell
python -m pip install -e .
```

## Preferred Workflow for Outlook ("new Outlook")

This is the primary workflow for most users.

1. Export your DMARC-report folder from Outlook as a single `.pst` file.
2. Start the web UI:

```powershell
dmark serve --host 127.0.0.1 --port 8080
```

3. Open `http://127.0.0.1:8080`. If PST extraction is not ready yet, use the Web UI button to install the bundled `.NET PSTParse` helper.
4. Choose **Analyze PST upload**, select your `.pst`, then click **Upload PST and Analyze**.

## CLI Workflows (Optional / Advanced)

If you prefer command-line processing:

1. Extract report attachments:

```powershell
dmark extract-pst C:\path\to\dmarc-folder-export.pst --out-dir .\extracted-reports
```

2. Analyze extracted files:

```powershell
dmark analyze .\extracted-reports --json-out .\dmarc-summary.json
```

If you already have `.xml` / `.xml.gz` files:

```powershell
dmark analyze C:\path\to\reports
```

Enable DNS-informed guidance:

```powershell
dmark analyze C:\path\to\reports --resolve-dns
```

## Web UI

Start the local web app:

```powershell
dmark serve --host 127.0.0.1 --port 8080
```

Then open:

```text
http://127.0.0.1:8080
```

UI modes:
- Analyze local path: best for large sets (e.g., 4300 reports) without browser upload overhead.
- Analyze upload: good for small batches and spot checks.
- Analyze PST upload: upload one `.pst`, extract DMARC report attachments, and analyze in one step.
  - PST uploads now run as background jobs and show live stage updates in the UI (`queued`, `extracting`, `analyzing`, `complete/error`) including parsed file progress during analysis.
  - Web UI analysis includes DNS diagnostics to verify DMARC/SPF/DKIM record state and refine action plans.
  - Results now include a "First-Pass Interpretation" section that explains policy posture, legitimate-risk basis, attack pressure, and immediate next actions in plain language.
  - Advanced evidence remains available under expandable details for deeper investigation.
  - Results include per-domain daily trend charts below the summary table.

You can change upload size limit:

```powershell
dmark serve --max-upload-mb 500
```

Default web upload limit is `1024 MB`.
Parsing is multithreaded by default (`parse_workers=auto`).
On the first large run, the app auto-tunes worker count on a sample and caches the result in `.dmark_cache/parse_tuning.json`.
You can still override manually:

```powershell
dmark serve --parse-workers 16
dmark analyze C:\path\to\reports --parse-workers 16
```

Long-running web sessions can also tune PST job retention:

```powershell
dmark serve --job-ttl-seconds 86400 --max-jobs 1000
```

Summary computation now reports incremental progress during "Computing domain summaries" as reports are aggregated.

PST upload extraction still requires one backend:
- `pypff` available in Python, or
- `readpst` available in `PATH`, or
- bundled `.NET PSTParse` helper (use `pstparse-dotnet` engine; installable from the Web UI)

Optional CLI backend check/install:

```powershell
dmark setup-pst
dmark setup-pst --install-pstparse-dotnet
```

## PST extraction backends

`extract-pst` uses:
- `pypff` (if installed), otherwise
- `readpst` (if available in `PATH`), otherwise
- bundled `.NET PSTParse` helper

If extraction fails, install one of those backends and rerun.

## Example output

Human summary:

- Files scanned / parsed / parse errors
- Duplicate reports skipped
- Per-domain:
  - policy mode and consistency
  - historical trend score and enforcement readiness
  - trend score drivers (what cost points)
  - attack pressure on unauthorized/pending-review traffic (separate from legit delivery risk)
  - key issues (category, severity, confidence, evidence, likely cause)
  - prioritized action plan
  - policy impact simulation for `quarantine` / `reject`
  - readiness gate with explicit basis (all traffic vs approved senders)
  - messages, DMARC pass/fail rate
  - DKIM/SPF auth pass vs aligned pass rates
  - top sender inventory with "new since last run" indicator
  - disposition totals
  - top failing sources
  - per-source evidence details (header-from/envelope-from, DKIM selector/domain/result, SPF domain/result, dispositions/overrides)
  - recommendation summary

Machine-readable JSON:
- `--json-out path\to\summary.json`

## Notes

- Duplicate aggregate reports are deduped by `(org_name, report_id, begin, end, policy_domain)`.
- Relaxed alignment is approximated with subdomain checks to keep this dependency-free.
- For public-suffix-accurate alignment logic, add PSL-based domain normalization in a future iteration.
- Web UI uses Flask and runs locally on your machine.
- Evidence in reports is aggregate-record level (DMARC XML buckets), not individual message traces.
- Sender history is cached in `.dmark_cache/sender_history.json` to flag "new sender" sources between runs.
- Deliverability safety/readiness calculations automatically exclude sender traffic classified as receiver-side relay noise.
- Forwarding/indirect flow often breaks SPF while DKIM may still survive; override reasons are treated as confidence modifiers.
- Optional approved-sender config:
```json
{
  "domains": {
    "example.com": ["203.0.113.1", "198.51.100.9"]
  }
}
```
Save as `.dmark_cache/approved_senders.json` to drive readiness and impact analysis on approved sender volume.

## Dev test

```powershell
python -m unittest discover -s tests -v
```

## Dev quality checks

```powershell
python -m pip install ruff mypy
python -m ruff check src tests
python -m mypy --follow-imports=skip src/dmark/parser.py src/dmark/classification.py src/dmark/time_series.py
```
