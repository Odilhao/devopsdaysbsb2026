"""Shared helpers for fetch/analyze scripts."""
import datetime
import json
import os
import pathlib
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
TODAY = datetime.date.today().isoformat()
UA = {"User-Agent": "devopsdaysbsb2026-slides (https://github.com/Odilhao/devopsdaysbsb2026)"}


def get(url, retries=4, timeout=180):
    """GET a URL and return bytes, retrying on transient errors."""
    for attempt in range(retries):
        try:
            headers = dict(UA)
            token = os.environ.get("GITHUB_TOKEN")
            if token and url.startswith("https://api.github.com/"):  # CI: avoid the anonymous rate limit
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            if attempt == retries - 1:
                raise
            print(f"  retry {attempt + 1} for {url}: {e}")
            time.sleep(5 * (attempt + 1))


def get_json(url, **kw):
    return json.loads(get(url, **kw))


def write_csv(path, header, rows, source, script):
    """Write a CSV whose first lines are '#' comments with provenance."""
    import csv

    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        f.write(f"# source: {source}\n# fetched: {TODAY}\n# script: scripts/{script}\n")
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {path.relative_to(ROOT)} ({len(rows)} rows)")
