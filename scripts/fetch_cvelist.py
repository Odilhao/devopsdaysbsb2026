"""Download the CVE.org cvelistV5 bulk export and reduce it to one compact CSV.

The full repo is several GB, so we download the latest release zip
(all_CVEs_at_midnight), stream through it, and keep only the fields we need.

Output: data/raw/cvelist_index.csv
  cve_id, state, date_published, date_reserved, assigner (CNA short name),
  cvss_base (best of v4/v3.1/v3.0), cvss_version, cwe (first)
"""
import csv
import io
import json
import zipfile

from common import RAW, get, get_json

RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"


def best_cvss(cna):
    for m in cna.get("metrics", []) or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in m and "baseScore" in m[key]:
                return m[key]["baseScore"], key
    return "", ""


def first_cwe(cna):
    for pt in cna.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            if d.get("cweId"):
                return d["cweId"]
    return ""


def iter_records(outer_zip_bytes):
    outer = zipfile.ZipFile(io.BytesIO(outer_zip_bytes))
    for name in outer.namelist():
        data = outer.read(name)
        if name.endswith(".zip"):  # release zip wraps an inner cves.zip
            yield from iter_records(data)
        elif name.endswith(".json") and name.rsplit("/", 1)[-1].startswith("CVE-"):
            yield json.loads(data)


def main():
    rel = get_json(RELEASES)
    asset = next(a for a in rel["assets"] if "all_CVEs" in a["name"] and a["name"].endswith(".zip"))
    print(f"downloading {asset['name']} ({asset['size'] / 1e6:.0f} MB)")
    blob = get(asset["browser_download_url"], timeout=1200)
    out = RAW / "cvelist_index.csv"
    n = 0
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "state", "date_published", "date_reserved", "assigner",
                    "cvss_base", "cvss_version", "cwe"])
        for rec in iter_records(blob):
            meta = rec.get("cveMetadata", {})
            cna = rec.get("containers", {}).get("cna", {})
            score, ver = best_cvss(cna)
            w.writerow([meta.get("cveId"), meta.get("state"),
                        (meta.get("datePublished") or "")[:10],
                        (meta.get("dateReserved") or "")[:10],
                        meta.get("assignerShortName"), score, ver, first_cwe(cna)])
            n += 1
    print(f"wrote {out} ({n} records, release {rel['tag_name']})")


if __name__ == "__main__":
    main()
