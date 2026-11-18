"""
01_build_dataset.py  --  Turn two raw sources into ONE analysis table.

INPUT
  --kev   the CISA KEV file (CSV). One row per flaw that was really attacked.
  --nvd   a folder of NVD records (JSON). One file per flaw (CVE), holding
          its publication date, CVSS score, weakness type and products.
OUTPUT
  --out   cve_analysis.csv: one row per flaw, ready for statistics.
          snapshot.json is written next to it (what data, from when).

Run:
  python3 01_build_dataset.py --kev data/raw/kev.csv --nvd data/raw/nvd \
      --out data/cve_analysis.csv --nvd-commit <git commit of the NVD mirror>

The script has five parts. Each part is marked PART 1 ... PART 5 below.
"""
import argparse
import collections
import glob
import hashlib
import json
import os

import pandas as pd

# ---- Fixed study settings (change here, nowhere else) ----------------------
FIRST_YEAR, LAST_YEAR = 2019, 2023          # publication years we study
KEV_LAUNCH = pd.Timestamp("2021-11-03")     # the day the KEV list first existed
WINDOW_DAYS = 365                           # "attacked within one year"

# CVSS v3.1 pieces we keep. Long NVD name -> short column name.
COMPONENTS = {
    "attackVector": "AV",            # from where can it be attacked? (network, local...)
    "attackComplexity": "AC",        # does the attacker need luck / special conditions?
    "privilegesRequired": "PR",      # does the attacker need an account first?
    "userInteraction": "UI",         # must a victim click something?
    "scope": "S",                    # can the damage spread beyond the flawed part?
    "confidentialityImpact": "CI",   # can data be read?
    "integrityImpact": "II",         # can data be changed?
    "availabilityImpact": "AI",      # can the system be knocked offline?
}


# =============================================================================
# PART 1 -- Read ONE NVD record and pull out the few facts we need
# =============================================================================
def pick_cvss(record):
    """Return (chosen v3.1 entry, did sources disagree?).

    NVD can hold several v3.1 scores for one flaw: one from NIST's own
    analysts ("Primary") and one from the vendor ("Secondary"). We prefer
    NIST's, so every flaw is scored by the same referee where possible.
    """
    entries = record.get("metrics", {}).get("cvssMetricV31", [])
    if not entries:
        return None, False
    primary = [e for e in entries if e.get("type") == "Primary"]
    chosen = primary[0] if primary else entries[0]
    scores = {e["cvssData"]["baseScore"] for e in entries}
    return chosen, len(scores) > 1


def pick_cwe(record):
    """Return the weakness type, e.g. 'CWE-79' (cross-site scripting)."""
    blocks = record.get("weaknesses", [])
    # Prefer NIST's own label, then any other source.
    blocks = sorted(blocks, key=lambda b: b.get("source") != "nvd@nist.gov")
    for block in blocks:
        for d in block.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-"):      # skips 'NVD-CWE-noinfo' / 'NVD-CWE-Other'
                return value
    return "none"


def pick_vendor(record):
    """Return the vendor named most often in the list of affected products.

    Products are written as 'cpe:2.3:a:VENDOR:PRODUCT:...'. We take the
    vendor from NVD, NEVER from KEV: KEV only names vendors for attacked
    flaws, so using it would hand the model the answer.
    """
    counts = collections.Counter()
    for config in record.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) > 3:
                        counts[parts[3]] += 1
    return counts.most_common(1)[0][0] if counts else "unknown"


def read_record(path):
    """One JSON file -> one small dictionary (or None if we must skip it)."""
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    if record.get("vulnStatus") == "Rejected":       # withdrawn IDs
        return None
    published = pd.Timestamp(record["published"]).normalize()
    if not FIRST_YEAR <= published.year <= LAST_YEAR:
        return None
    row = {"cve": record["id"], "published": published, "has_v31": False}
    chosen, conflict = pick_cvss(record)
    if chosen is not None:
        data = chosen["cvssData"]
        row.update(
            has_v31=True,
            cvss_score=data["baseScore"],
            severity=data["baseSeverity"].title(),          # Low / Medium / High / Critical
            score_source="NVD" if chosen.get("type") == "Primary" else "CNA",
            score_conflict=int(conflict),
            cwe=pick_cwe(record),
            vendor=pick_vendor(record),
            nvd_kev_date=record.get("cisaExploitAdd"),      # NVD's own copy, used as a cross-check
        )
        for long_name, short_name in COMPONENTS.items():
            # Kept in capitals (NETWORK, NONE, LOW...). The word "None" would be
            # misread as "missing" when the CSV is loaded again; "NONE" is not.
            row[short_name] = data[long_name]
    return row


# =============================================================================
# PART 2 -- Read ALL NVD records (about 120,000 small files)
# =============================================================================
def read_nvd(folder):
    rows = []
    # A flaw's ID year can be earlier than its publication year, so we also
    # look in the two ID-year folders before the study window.
    for id_year in range(FIRST_YEAR - 2, LAST_YEAR + 1):
        for path in glob.iglob(os.path.join(folder, f"CVE-{id_year}", "*", "*.json")):
            row = read_record(path)
            if row is not None:
                rows.append(row)
    return pd.DataFrame(rows)


# =============================================================================
# PART 3 -- Join NVD with KEV on the CVE ID
# =============================================================================
def join_kev(nvd, kev_path):
    kev = pd.read_csv(kev_path, usecols=["cveID", "dateAdded"])
    kev = kev.rename(columns={"cveID": "cve", "dateAdded": "kev_date"})
    kev["kev_date"] = pd.to_datetime(kev["kev_date"])
    # how="left": keep every NVD flaw; attach a KEV date only where one exists.
    # validate: crash loudly if any CVE ID appears twice on either side.
    return nvd.merge(kev, on="cve", how="left", validate="one_to_one")


# =============================================================================
# PART 4 -- Build the outcome columns (what we try to explain)
# =============================================================================
def add_outcomes(df, snapshot_date):
    df["pub_year"] = df["published"].dt.year
    df["kev"] = df["kev_date"].notna().astype(int)

    # The one-year clock cannot start before the list existed.
    df["clock_start"] = df["published"].clip(lower=KEV_LAUNCH)
    days_from_clock = (df["kev_date"] - df["clock_start"]).dt.days

    # y_365: on the attacked list within one year of the clock start.
    df["y_365"] = ((df["kev"] == 1) & (days_from_clock <= WINDOW_DAYS)).astype(int)
    # y_ever: on the attacked list at all, as of the snapshot.
    df["y_ever"] = df["kev"]

    # For the survival analysis: days from publication to listing, and for
    # unlisted flaws, days we have watched them so far.
    df["lag_days"] = (df["kev_date"] - df["published"]).dt.days
    df["lag_nonpositive"] = (df["lag_days"] <= 0).astype(int)     # listed on/before publication day
    df["followup_days"] = (df["kev_date"].fillna(snapshot_date) - df["published"]).dt.days
    return df


# =============================================================================
# PART 5 -- Run everything, check it, save it
# =============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", required=True)
    ap.add_argument("--nvd", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--nvd-commit", default="unknown")
    args = ap.parse_args()

    nvd = read_nvd(args.nvd)
    print(f"NVD records published {FIRST_YEAR}-{LAST_YEAR}: {len(nvd):,}")

    df = join_kev(nvd, args.kev)
    kev_all = pd.read_csv(args.kev)
    snapshot_date = pd.to_datetime(kev_all["dateAdded"]).max()

    # Filter check: how many attacked flaws do we lose by requiring a v3.1 score?
    in_window_kev = df["kev_date"].notna()
    print(f"KEV flaws published in window: {in_window_kev.sum():,} "
          f"(without a v3.1 score: {(in_window_kev & ~df['has_v31']).sum()})")

    df = df[df["has_v31"]].drop(columns="has_v31").copy()
    df = add_outcomes(df, snapshot_date)

    # Cross-check: NVD's own copy of the KEV date must agree with the KEV file.
    both = df[df["kev"] == 1]
    agree = (pd.to_datetime(both["nvd_kev_date"]) == both["kev_date"]).mean()
    print(f"NVD copy of KEV date agrees with KEV file: {agree:.1%}")
    df = df.drop(columns="nvd_kev_date")

    df = df.sort_values("cve").reset_index(drop=True)
    df.to_csv(args.out, index=False)

    with open(args.kev, "rb") as f:
        kev_hash = hashlib.sha256(f.read()).hexdigest()
    snapshot = {
        "kev_file_sha256": kev_hash,
        "kev_rows_total": int(len(kev_all)),
        "kev_latest_dateAdded": str(snapshot_date.date()),
        "nvd_mirror": "https://github.com/fkie-cad/nvd-json-data-feeds",
        "nvd_mirror_commit": args.nvd_commit,
        "rows": int(len(df)),
        "kev_in_rows": int(df["kev"].sum()),
        "y_365_positives": int(df["y_365"].sum()),
    }
    with open(os.path.join(os.path.dirname(args.out), "snapshot.json"), "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"\nFinal table: {len(df):,} flaws, {df['kev'].sum():,} in KEV, "
          f"{df['y_365'].sum():,} with y_365 = 1")
    print("\nBy publication year:")
    print(df.groupby("pub_year").agg(flaws=("cve", "size"), kev=("kev", "sum"),
                                     y_365=("y_365", "sum")).to_string())
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
