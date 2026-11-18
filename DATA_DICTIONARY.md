# Data dictionary: `data/cve_analysis.csv`

One row per software flaw (CVE): 99,031 rows, 25 columns. Snapshot of 2026-11-10.
Built by `01_build_dataset.py` from two sources:

- **NVD** (National Vulnerability Database): every published flaw, its score and affected products.
- **KEV** (CISA's Known Exploited Vulnerabilities catalog): flaws confirmed to have been attacked.

Columns are either taken straight from NVD, taken straight from KEV, or calculated by the script.
The worked example in each table is Log4Shell, CVE-2021-44228.

## 1. Identity and date

| Column | Meaning | Source | Log4Shell |
| --- | --- | --- | --- |
| `cve` | The flaw's public ID | NVD `id` | CVE-2021-44228 |
| `published` | Day NVD made the flaw public | NVD `published` (date part) | 2021-12-10 |
| `pub_year` | Year of `published` | Calculated | 2021 |

## 2. The danger score

| Column | Meaning | Source | Log4Shell |
| --- | --- | --- | --- |
| `cvss_score` | CVSS v3.1 base score, 0 to 10 | NVD `cvssMetricV31.baseScore` | 10.0 |
| `severity` | Score band: Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0 | NVD `baseSeverity` | Critical |
| `score_source` | `NVD` = scored by NIST analysts; `CNA` = scored by the organization that reported the flaw (often the vendor) | Calculated; NIST's score preferred when both exist | NVD |
| `score_conflict` | 1 if the two scorers disagree, else 0 | Calculated | 0 |

Scores range from 1.8 to 10 (median 7.5). Scorers disagree on 19.3% of flaws.

## 3. The eight ingredients of the score

The analyst answers eight questions; a fixed formula turns the answers into `cvss_score`.
Values keep NVD's capitals (`NONE`, not `None`, which would load as missing).

| Column | Question | Values |
| --- | --- | --- |
| `AV` Attack Vector | From where can it be attacked? | `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` |
| `AC` Attack Complexity | Does the attacker need special conditions? | `LOW`, `HIGH` |
| `PR` Privileges Required | Does the attacker need an account first? | `NONE`, `LOW`, `HIGH` |
| `UI` User Interaction | Must a victim do something? | `NONE`, `REQUIRED` |
| `S` Scope | Can damage spread beyond the flawed part? | `UNCHANGED`, `CHANGED` |
| `CI` Confidentiality Impact | Can private data be read? | `NONE`, `LOW`, `HIGH` |
| `II` Integrity Impact | Can data be changed? | `NONE`, `LOW`, `HIGH` |
| `AI` Availability Impact | Can the system be knocked offline? | `NONE`, `LOW`, `HIGH` |

Log4Shell: `NETWORK`, `LOW`, `NONE`, `NONE`, `CHANGED`, `HIGH`, `HIGH`, `HIGH`.

Because the score is a formula of these eight, the score and the ingredients never go in the same
model. NVD's own short names for the last three are C, I and A; they are renamed here because a
column named `C` clashes with the `C()` function in the statsmodels formula language.

## 4. Controls

| Column | Meaning | Source | Log4Shell |
| --- | --- | --- | --- |
| `cwe` | Type of programming mistake (Common Weakness Enumeration); `none` if NVD gave only a vague label | NVD `weaknesses`, NIST's label preferred | CWE-917 |
| `vendor` | Company named most often in the affected-product list | NVD `configurations` (CPE strings) | cisco |

Most common `cwe` values: CWE-79 cross-site scripting (13,268), CWE-787 out-of-bounds write (7,285),
CWE-89 SQL injection (4,955). 13,040 flaws have `none`.

- Vendor is never taken from KEV: KEV names a vendor only for attacked flaws, which would leak the answer.
- The most-often-named rule can mislabel. Log4Shell is an Apache flaw but shows as `cisco`, because
  Cisco products dominate its affected-product list.

## 5. The attacked list

| Column | Meaning | Source | Log4Shell |
| --- | --- | --- | --- |
| `kev_date` | Day CISA added the flaw to KEV; blank if never | KEV `dateAdded`, joined on `cve` | 2021-12-10 |
| `kev` | 1 if on KEV, else 0 | Calculated | 1 |

784 flaws (0.8%) have `kev` = 1. NVD's own copy of the KEV date matched the KEV file for all 784.

## 6. Outcomes

| Column | Meaning | Calculation | Log4Shell |
| --- | --- | --- | --- |
| `clock_start` | Start of the one-year window | Later of `published` and 2021-11-03 (KEV launch) | 2021-12-10 |
| `y_365` | **Main outcome:** listed within 365 days of `clock_start` | `kev_date - clock_start <= 365` | 1 |
| `y_ever` | **Sensitivity outcome:** listed at any time | Same as `kev` | 1 |

KEV did not exist before November 2021, so older flaws start their clock on its first day. This
gives every flaw the same one-year window in which listing was possible.
664 flaws have `y_365` = 1; the other 120 listed flaws were added more than a year after `clock_start`.

## 7. Timing (survival analysis)

| Column | Meaning | Calculation | Log4Shell |
| --- | --- | --- | --- |
| `lag_days` | Days from publication to listing; blank if never listed | `kev_date - published` | 0 |
| `lag_nonpositive` | 1 if listed on or before publication day | `lag_days <= 0` | 1 |
| `followup_days` | Days observed: to listing, or to the snapshot date if never listed | `(kev_date or snapshot) - published` | 0 |

Among listed flaws the median lag is 272 days (range -290 to 2,599).
A negative lag means attackers used the flaw before NVD published it; these 90 flaws are reported
separately rather than dropped. `followup_days` lets the survival analysis treat unlisted flaws as
"not listed yet after N days" (right-censored) instead of discarding them.

## Source summary

- **From NVD:** `cve`, `published`, `cvss_score`, `severity`, `AV`-`AI`, `cwe`, `vendor`
- **From KEV:** `kev_date`
- **Calculated:** `pub_year`, `score_source`, `score_conflict`, `kev`, `clock_start`, `y_365`,
  `y_ever`, `lag_days`, `lag_nonpositive`, `followup_days`
