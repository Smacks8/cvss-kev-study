# Does severity predict exploitation? (CIT 50700 project)

Compares CVSS v3.1 severity scores (from NVD) with confirmed exploitation
(CISA's KEV list) for flaws published 2019-2023.

## Step 1: build the dataset

```bash
pip install pandas

# 1. Get the two raw sources
mkdir -p data/raw && cd data/raw
curl -o kev.csv https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv
git clone --depth 1 --filter=blob:none --sparse https://github.com/fkie-cad/nvd-json-data-feeds nvd
cd nvd && git sparse-checkout set CVE-2017 CVE-2018 CVE-2019 CVE-2020 CVE-2021 CVE-2022 CVE-2023
git rev-parse HEAD        # note this commit id
cd ../../..

# 2. Build the table
python3 01_build_dataset.py --kev data/raw/kev.csv --nvd data/raw/nvd \
    --out data/cve_analysis.csv --nvd-commit <commit id from above>
```

Output: `data/cve_analysis.csv` (one row per flaw) and `data/snapshot.json`
(which data, from when). The raw NVD folder is about 1.5 GB and is not stored
in this repository; `cve_analysis.csv` is, so later steps run without it.

## Columns in cve_analysis.csv

| Column | Meaning |
| --- | --- |
| cve | The flaw's ID |
| published, pub_year | When NVD published it |
| cvss_score, severity | CVSS v3.1 base score (0-10) and its band |
| AV, AC, PR, UI, S, CI, II, AI | The eight ingredients of the score |
| score_source | NVD = scored by NIST analysts, CNA = by the vendor |
| score_conflict | 1 if two sources gave different scores |
| cwe | Weakness type, e.g. CWE-79 |
| vendor | Vendor named most often in the affected-product list |
| kev, kev_date | On the KEV list (1/0) and the date it was added |
| clock_start | Later of publication date and KEV launch (2021-11-03) |
| y_365 | Main outcome: listed within 365 days of clock_start |
| y_ever | Listed at all by the snapshot date |
| lag_days | Days from publication to listing (KEV flaws only) |
| lag_nonpositive | 1 if listed on or before publication day |
| followup_days | Days observed: to listing, or to the snapshot date |

Snapshot of 2026-11-10: 99,031 flaws, 784 in KEV, 664 with y_365 = 1.
