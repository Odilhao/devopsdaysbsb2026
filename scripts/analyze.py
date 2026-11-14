"""Turn data/raw/* into the CSVs in data/processed/ (the only numbers used on slides).

Run after the fetch_* scripts. 2026 is partial, so year-over-year tables also
include a same-period column (Jan 1 -> cutoff day of each year) for fair comparison.
"""
import datetime
import json

import pandas as pd

from common import PROCESSED, RAW, TODAY

CUTOFF = datetime.date.fromisoformat(TODAY)
CUT_MD = CUTOFF.strftime("%m-%d")
YEARS = list(range(2018, CUTOFF.year + 1))


def save(df, name, source, index=False):
    path = PROCESSED / name
    with open(path, "w") as f:
        f.write(f"# source: {source}\n# computed: {TODAY} (data cutoff {CUTOFF})\n# script: scripts/analyze.py\n")
        df.to_csv(f, index=index)
    print(f"wrote data/processed/{name} ({len(df)} rows)")


def same_period(dates):
    """Boolean mask: date falls between Jan 1 and the cutoff month-day of its own year."""
    return dates.dt.strftime("%m-%d") <= CUT_MD


def growth_table(df, date_col, group=None):
    """Per-year full count + same-period (YTD) count."""
    d = df[df[date_col].dt.year.isin(YEARS)].copy()
    d["year"] = d[date_col].dt.year
    d["ytd"] = same_period(d[date_col])
    keys = ["year"] + ([group] if group else [])
    full = d.groupby(keys).size().rename("full_year")
    ytd = d[d.ytd].groupby(keys).size().rename(f"jan1_to_{CUT_MD}")
    return pd.concat([full, ytd], axis=1).fillna(0).astype(int).reset_index()


# ---------------------------------------------------------------- CVE.org
def cvelist():
    df = pd.read_csv(RAW / "cvelist_index.csv", dtype=str)
    df = df[df.state == "PUBLISHED"].copy()
    df["date"] = pd.to_datetime(df.date_published, errors="coerce")
    df = df[df.date.notna()]
    df["cvss"] = pd.to_numeric(df.cvss_base, errors="coerce")
    src = "CVE.org cvelistV5 bulk export https://github.com/CVEProject/cvelistV5"

    save(growth_table(df, "date"), "cve_yearly.csv", src)

    bands = pd.cut(df.cvss, [-0.1, 3.95, 6.95, 8.95, 10], labels=["low", "medium", "high", "critical"])
    df["band"] = bands.astype(str).replace("nan", "no_cna_score")

    # Critical (CNA CVSS >= 9.0) per month since Jul 2023, with CNA-score coverage.
    # Before 2017 almost no CVE.org record carries a CNA score, so "all of history"
    # comparisons below use CNA-scored records only (see the coverage column).
    mm = df[df.date >= "2023-07-01"]
    mon = mm.groupby(mm.date.dt.strftime("%Y-%m")).agg(
        published=("cve_id", "size"), cna_scored=("cvss", lambda s: int(s.notna().sum())),
        critical=("band", lambda s: int((s == "critical").sum())))
    save(mon.reset_index().rename(columns={"date": "month"}), "cve_monthly_critical.csv",
         src + " (critical = CNA CVSS base >= 9.0, any version)")
    crit = df[df.band == "critical"]
    yr = crit.groupby(crit.date.dt.year).size()
    so = crit[(crit.date >= "2026-09-01") & (crit.date < "2026-11-01")]
    ao = crit[(crit.date >= "2026-08-01") & (crit.date < "2026-11-01")]
    rows = [
        ("critical_sep_oct_2026", len(so)),
        ("critical_aug_oct_2026", len(ao)),
        ("critical_all_before_2026", int((crit.date < "2026-01-01").sum())),
        ("critical_all_before_sep_2026", int((crit.date < "2026-09-01").sum())),
        ("critical_2018_to_2022_sum", int(yr.loc[2018:2022].sum())),
        ("critical_2025_full_year", int(yr.loc[2025])),
        ("critical_2023_full_year", int(yr.loc[2023])),
        ("critical_ytd_current_year", int(yr.loc[CUTOFF.year])),
    ]
    save(pd.DataFrame(rows, columns=["metric", "value"]), "cve_critical_checks.csv",
         src + " (fact-check: Sep+Oct 2026 Critical vs history; CNA scores only)")

    return df


# ---------------------------------------------------------------- KEV + EPSS
def kev(cve_df):
    data = json.loads((RAW / "kev.json").read_text())
    k = pd.DataFrame(data["vulnerabilities"])
    k["added"] = pd.to_datetime(k.dateAdded)
    src = "CISA KEV https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    save(growth_table(k, "added"), "kev_yearly.csv", src)

    pub = cve_df.set_index("cve_id").date
    k["published"] = k.cveID.map(pub)
    k["days_to_kev"] = (k.added - k.published).dt.days
    k["cve_year"] = k.published.dt.year
    t = k[k.cve_year.isin(YEARS)].groupby("cve_year").days_to_kev.agg(
        kev_entries="count", median_days="median",
        within_7_days=lambda s: int((s <= 7).sum()),
        on_or_before_publish=lambda s: int((s <= 0).sum()))
    t["pct_within_7_days"] = (100 * t.within_7_days / t.kev_entries).round(1)
    save(t.reset_index(), "kev_time_to_exploit.csv",
         src + " + CVE.org datePublished (days from CVE publication to KEV listing, by CVE year)")


# ---------------------------------------------------------------- Scanners
def scanners():
    """Per image: how many findings each scanner reports, by severity, and how many have a fix."""
    rows = []
    for f in sorted((RAW / "scanners").glob("*.json")):
        if f.stat().st_size == 0:
            continue
        tool, image = f.stem.split("__", 1)
        data = json.loads(f.read_text())
        vulns = []
        if tool == "trivy":
            for r in data.get("Results", []) or []:
                for v in r.get("Vulnerabilities", []) or []:
                    vulns.append((v["VulnerabilityID"], v.get("Severity", "UNKNOWN").lower(),
                                  bool(v.get("FixedVersion"))))
        else:
            for m in data.get("matches", []) or []:
                v = m["vulnerability"]
                vulns.append((v["id"], v.get("severity", "Unknown").lower(),
                              v.get("fix", {}).get("state") == "fixed"))
        ids = {}
        for vid, sev, fixed in vulns:  # one row per unique vuln id (worst severity, fixed if any)
            prev = ids.get(vid)
            ids[vid] = (sev if prev is None else prev[0], fixed or (prev[1] if prev else False))
        sev_counts = pd.Series([s for s, _ in ids.values()]).value_counts()
        rows.append({
            "image": image, "tool": tool, "findings": len(vulns), "unique_ids": len(ids),
            "critical": int(sev_counts.get("critical", 0)), "high": int(sev_counts.get("high", 0)),
            "medium": int(sev_counts.get("medium", 0)), "low": int(sev_counts.get("low", 0) + sev_counts.get("negligible", 0)),
            "unknown": int(sev_counts.get("unknown", 0)),
            "with_fix": sum(1 for _, fx in ids.values() if fx),
        })
    if rows:
        save(pd.DataFrame(rows), "scanner_comparison.csv",
             "Trivy 0.58.1 + Grype 0.86.1 run by scripts/scan_images.sh (unique vulnerability IDs per image)")


def headlines():
    """Derived numbers quoted on slides (ratios across the other tables)."""
    rd = lambda n: pd.read_csv(PROCESSED / n, comment="#")  # noqa: E731
    ytd = f"jan1_to_{CUT_MD}"
    cve = rd("cve_yearly.csv").set_index("year")
    kev = rd("kev_yearly.csv").set_index("year")
    y, p = CUTOFF.year, CUTOFF.year - 1
    rows = [
        ("cve_ytd_ratio_vs_prev_year", round(cve.loc[y, ytd] / cve.loc[p, ytd], 2)),
        ("kev_ytd_growth_pct", round(100 * (kev.loc[y, ytd] / kev.loc[p, ytd] - 1))),
        ("cve_ytd_growth_pct", round(100 * (cve.loc[y, ytd] / cve.loc[p, ytd] - 1))),
    ]
    save(pd.DataFrame(rows, columns=["metric", "value"]), "headline_numbers.csv", "derived from the other data/processed tables")


if __name__ == "__main__":
    cve_df = cvelist()
    kev(cve_df)
    scanners()
    headlines()
