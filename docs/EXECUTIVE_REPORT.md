# Executive environment report

The executive brief is intended for sharing a concise environment assessment with stakeholders. It complements the detailed host and fleet reports.

## Open or download

After running or importing a scan, or assembling a fleet in Scan Library, use the report actions:

- **Executive summary (PDF)** downloads a PDF of the current fleet evidence.
- **View executive summary** opens the printable HTML version.
- **Executive PDF — obfuscated** downloads a copy with generated host aliases, including aliases for failed targets.

When a fleet summary is generated, `00_executive_summary.pdf` and `00_executive_summary.html` are written in the scan output folder. Generated obfuscated summaries use the `00_OBFUSCATED_executive_summary` prefix. These artifacts are included when the existing scan packaging flow archives the folder.

## What the brief shows

The brief shows assessed hosts, failed targets, partial scans, CPU support, vSAN ESA readiness, and BMC security posture. These dimensions overlap; their counts are not an overall certification score. Targets that failed collection are outside the assessed-host readiness counts unless partial evidence exists. Recovered targets are removed from the failed roster. Central fleet managers are excluded from BMC security readiness.

The action list contains **up to ten distinct action groups**, with affected-host counts, suggested next steps, and at most three example hosts per group. It can include CPU blockers/exceptions, ESA storage/network blockers, failed collection, missing evidence, BMC control failures, recorded hardware faults, TPM/VMD configuration, BIOS baseline/mitigation gaps, and ESXi lifecycle issues. Missing evidence is explicitly unassessed; it is not a pass. Unused/down NIC ports alone do not become hardware-failure priorities.

Ranking is deterministic:

1. **P1:** detected blockers, recorded hardware faults, failed scan visibility, or explicitly high/critical security findings.
2. **P2:** remediation, overrides, missing evidence, and security findings without a known severity.
3. **P3:** explicitly low-severity security findings.

Within a priority, groups with more affected hosts appear first; titles break ties. A host may appear in multiple action groups. The report states how many groups were identified in total, so a top-ten cutoff is visible. It does not invent findings to fill ten slots. Security titles come from the existing control catalog; raw observed values, credentials, and failure messages are not printed in the brief.

Priorities use collected/enriched evidence and existing readiness evaluations. They are a review order, not an independent risk scoring engine or an automated certification decision. Confirm current Broadcom and OEM requirements in the detailed assessment before deployment.

## Icons and text output

Scanner and HTML report icons are enabled by default and bundled locally. The old emoji display controls have been retired, and imported presentation settings no longer suppress icons or strip Unicode from collected values. CSV and Excel remain data-first exports with original text preserved.

The new executive brief always uses a restrained, text-first presentation. The PDF is generated locally with Python's standard library, without an external conversion service or runtime package. It wraps long text and adds pages as needed. Its built-in PDF fonts support WinAnsi text; other characters are displayed as escaped Unicode rather than silently discarded. Use **View executive summary → Print / Save as PDF** for full browser-font Unicode rendering.

## Visual design

[Clarity labels](https://v13.clarity.design/documentation/labels) reserve status colors for state and advise against distracting color variety. [Clarity alerts](https://core.clarity.design/core-components/alert/) combine message content, icons, and urgency. The application uses these principles through its existing bundled CSS and local tokens: neutral text/backgrounds, narrow semantic accents, consistent typography, and explicit status words. It remains a Python-generated, offline UI rather than an Angular application.
