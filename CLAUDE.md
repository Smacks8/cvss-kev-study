# CIT 50700 project: Severity Metrics and Real-World Vulnerability Exploitation

Owner: Sai Smaran Manjunath. Course: CIT 50700, Prof. Noor, Purdue CIT department.

## The question
Do CVSS v3.1 severity scores (from NVD) predict confirmed exploitation (CISA's KEV catalog)
for CVEs published 2019-2023?

## Agreed design (replaces the original proposal)
- RQ1: logistic regression of `y_365` on CVSS score + vendor + CWE + year. Report odds ratio per point.
  Score and its 8 components go in SEPARATE models (score is a formula of the components).
- RQ2: out-of-sample test. Train on 2019-2021, test on 2022-2023. Compare 5 models
  (controls only, score, components, score+controls, components+controls) on ROC-AUC,
  PR-AUC, and recall/precision at top 1/5/10/20%. Paired bootstrap CIs.
- RQ3 (secondary): survival analysis of time to KEV listing by severity band.
  Kaplan-Meier + log-rank + Cox stratified by year. Right-censor unlisted CVEs.
  Primary cohort: CVEs published on/after 2021-11-03. Call it "time to listing", never "time to attack".
- The ANOVA from the proposal was dropped (it can't use censored CVEs; KEV launch backfill distorts lags).
- Use ALL records, no sampling.

## Data rules
- `clock_start` = max(publication date, 2021-11-03), the day KEV launched.
- Vendor comes from NVD CPE strings, never from KEV (KEV vendor exists only for listed CVEs = leakage).
- Window ends 2023: since April 2026 NIST scores new CVEs mainly if they are in KEV.
- Snapshot 2026-11-10: 99,031 CVEs, 784 in KEV, 664 with y_365 = 1.

## Files
- `01_build_dataset.py` builds `data/cve_analysis.csv` from raw KEV + NVD (see README.md).
- `data/cve_analysis.csv` is the frozen analysis table; later scripts read only this.
- Planned next: `02_models.py` (RQ1 + RQ2), `03_survival.py` (RQ3), robustness checks.

## How Sai wants help
- Explain every change twice: technically, and in plain words for someone new to the topic.
- Give every step needed to replicate, so he can answer questions in presentations.
- Build scripts one at a time and explain each before moving on.
