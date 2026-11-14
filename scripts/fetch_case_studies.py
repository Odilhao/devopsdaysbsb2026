"""Signals for the CVEs used as case studies on slides, plus NVD Critical totals.

Fetch (skipped with --offline; cached per CVE in data/raw/case_studies/):
  - GitHub Advisory Database API (GitHub is also a CNA, assigner "GitHub_M"):
    GHSA id, review type, severity, CVSS, affected package range, first patched version
  - NVD API: total CVEs with a CVSS v3 Critical score (all time vs a window)
Join with the local KEV (data/raw/kev.json), EPSS (data/raw/epss.csv.gz)
and CVE.org index (data/raw/cvelist_index.csv).

Writes data/processed/case_study_signals.csv and data/processed/nvd_critical_totals.csv.
Add a CVE to CASES to put it on a slide.
"""
import csv
import gzip
import json
import sys
import time
import urllib.parse

from common import PROCESSED, RAW, get_json, write_csv

CASES = {
    "CVE-2026-98432": "Linux kernel TCP/MPTCP UAF",
    "CVE-2026-111497": "Brotli (Node2Shell)",
    "CVE-2026-123158": "OpenSSH password bypass on musl (sshole)",
    "CVE-2026-115731": "OpenVox/Puppet Server report deserialization RCE",
    "CVE-2026-102895": "GPUStack improper authentication",
}
NVD_WINDOWS = [("all_time", None, None), ("2026-09_to_10", "2026-09-01", "2026-10-31")]
CACHE = RAW / "case_studies"
OFFLINE = "--offline" in sys.argv


def github(cve):
    path = CACHE / f"{cve}.github.json"
    if not OFFLINE:
        path.write_text(json.dumps(get_json(f"https://api.github.com/advisories?cve_id={cve}")))
        time.sleep(1)
    return json.loads(path.read_text()) if path.exists() else []


def gh_cols(advs):
    if not advs:
        return ["", "", "", "", ""]
    a = advs[0]
    cv = a.get("cvss_severities") or {}
    score = (cv.get("cvss_v4") or {}).get("score") or (cv.get("cvss_v3") or {}).get("score") or ""
    pk = "; ".join(f"{v['package']['ecosystem']}:{v['package']['name']} {v.get('vulnerable_version_range') or ''}"
                   f" -> {v.get('first_patched_version') or 'no fix'}" for v in a.get("vulnerabilities") or [])
    return [" ".join(x["ghsa_id"] for x in advs), a.get("type", ""), a.get("severity", ""), score, pk]


def nvd_total(start, end):
    q = {"cvssV3Severity": "CRITICAL", "resultsPerPage": "1"}
    if start:
        q |= {"pubStartDate": f"{start}T00:00:00.000Z", "pubEndDate": f"{end}T23:59:59.999Z"}
        q2 = {k: v for k, v in q.items() if k != "cvssV3Severity"}
    d = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(q))
    time.sleep(7)  # NVD public rate limit
    total = None
    if start:
        total = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(q2))["totalResults"]
        time.sleep(7)
    return d["totalResults"], total


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    kev = {v["cveID"]: v for v in json.load(open(RAW / "kev.json"))["vulnerabilities"]}
    epss, epss_date = {}, ""
    with gzip.open(RAW / "epss.csv.gz", "rt") as f:
        epss_date = f.readline().strip().split("score_date:")[-1][:10]
        for r in csv.DictReader(f):
            if r["cve"] in CASES:
                epss[r["cve"]] = r
    cna = {}
    with open(RAW / "cvelist_index.csv") as f:
        for r in csv.DictReader(f):
            if r["cve_id"] in CASES:
                cna[r["cve_id"]] = r

    rows = []
    for cve, label in CASES.items():
        k, e, c = kev.get(cve, {}), epss.get(cve, {}), cna.get(cve, {})
        gh = gh_cols(github(cve))
        rows.append([
            cve, label, c.get("assigner", ""), c.get("date_published", ""), c.get("cvss_base", ""), c.get("cvss_version", ""),
            *gh,
            k.get("dateAdded", ""), k.get("dueDate", ""), e.get("epss", ""), e.get("percentile", ""),
        ])
    write_csv(PROCESSED / "case_study_signals.csv",
              ["cve", "label", "cna", "published", "cna_cvss", "cna_cvss_version",
               "ghsa", "ghsa_type", "github_severity", "github_cvss", "github_packages",
               "kev_added", "kev_due", "epss", "epss_percentile"],
              rows, f"GitHub Advisory Database API + CISA KEV + FIRST EPSS (score date {epss_date}) + CVE.org cvelistV5",
              "fetch_case_studies.py")

    if not OFFLINE:
        nrows = []
        for name, s, e in NVD_WINDOWS:
            crit, total = nvd_total(s, e)
            nrows.append([name, s or "", e or "", crit, total if total is not None else ""])
        write_csv(PROCESSED / "nvd_critical_totals.csv", ["window", "start", "end", "nvd_cvss3_critical", "nvd_published"],
                  nrows, "NVD CVE API 2.0 (cvssV3Severity=CRITICAL; matches NVD and CNA v3 metrics as stored by NVD)",
                  "fetch_case_studies.py")


if __name__ == "__main__":
    main()
