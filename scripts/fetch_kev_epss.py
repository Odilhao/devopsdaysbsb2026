"""Fetch the CISA KEV catalog and today's FIRST EPSS scores.

Output: data/raw/kev.json, data/raw/epss.csv.gz
"""
from common import RAW, get

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / "kev.json").write_bytes(get(KEV))
    print("kev.json ok")
    try:
        (RAW / "epss.csv.gz").write_bytes(get(EPSS))
        print("epss.csv.gz ok")
    except Exception as e:  # noqa: BLE001
        print(f"EPSS fetch failed (optional): {e}")


if __name__ == "__main__":
    main()
