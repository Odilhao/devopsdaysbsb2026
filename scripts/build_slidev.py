"""Render the Slidev decks (one per language) from one Jinja template.

  slides/deck.md.j2                 slide structure + layouts (tahta theme)
  slides/i18n/<lang>.yaml    all text; strings may use {{ n.… }} to pull numbers
  data/processed/*.csv              numbers computed by the scripts (rebuild: scripts/build.sh)
  data/manual/article_facts.yaml    numbers from articles, each with its source URL

Writes slides/slides.<lang>.md (one Slidev project, shared style.css / package.json). Every number on a slide is rendered from the
CSVs or article_facts.yaml at build time, so a data refresh + this script = new decks.

  .venv/bin/python scripts/build_slidev.py            # all languages
  .venv/bin/python scripts/build_slidev.py en         # one language
"""
import json
import sys

import jinja2
import segno
import pandas as pd
import yaml

from common import PROCESSED, ROOT, TODAY

DECK = ROOT / "slides"
LANGS = {"en": {"thou": ",", "dec": "."}, "pt-BR": {"thou": ".", "dec": ","}}


def rd(name):
    return pd.read_csv(PROCESSED / name, comment="#")


def metric_dict(name, key="metric", val="value"):
    d = rd(name)
    return {r[key]: r[val] for _, r in d.iterrows()}


def load_data():
    """Everything the slides may quote, keyed for templates as n.<group>…"""
    cut = pd.Timestamp(TODAY)
    ytd = f"jan1_to_{cut.strftime('%m-%d')}"
    cve = rd("cve_yearly.csv").set_index("year")
    kev = rd("kev_yearly.csv").set_index("year")
    cm = rd("cve_monthly_critical.csv")
    # Include the current month as month-to-date; the chart footnote marks it partial.
    cm = cm[cm.month <= cut.strftime("%Y-%m")]
    tte = rd("kev_time_to_exploit.csv")
    tte["cve_year"] = tte.cve_year.astype(int)
    scan = rd("scanner_comparison.csv")
    case = rd("case_study_signals.csv").fillna("")
    nvd = rd("nvd_critical_totals.csv").set_index("window")
    return {
        "cut": cut,
        "crit": metric_dict("cve_critical_checks.csv"),
        "crit_monthly": cm[["month", "critical"]].to_dict("records"),
        "cve": {int(y): {"full": int(r.full_year), "ytd": int(r[ytd])} for y, r in cve.iterrows()},
        "hl": metric_dict("headline_numbers.csv"),
        "kev": {int(y): {"full": int(r.full_year), "ytd": int(r[ytd])} for y, r in kev.iterrows()},
        "kev7": {int(r.cve_year): float(r.pct_within_7_days) for _, r in tte.iterrows()},
        "kev7_years": [str(y) for y in tte.cve_year if 2021 <= y <= cut.year],
        "kev7_values": [round(float(v)) for y, v in zip(tte.cve_year, tte.pct_within_7_days) if 2021 <= y <= cut.year],
        "scan": {(r.image, r.tool): int(r.unique_ids) for _, r in scan.iterrows()},
        "case": {r.cve: r.to_dict() for _, r in case.iterrows()},
        "nvd": {w: r.to_dict() for w, r in nvd.iterrows()},
        "art": yaml.safe_load(open(ROOT / "data" / "manual" / "article_facts.yaml")),
    }


def make_env(lang):
    sep = LANGS[lang]

    def num(x, places=0):
        """Locale number: 96879 -> 96,879 (en) / 96.879 (pt-BR); places for decimals."""
        s = f"{float(x):,.{places}f}"
        return s.replace(",", "\0").replace(".", sep["dec"]).replace("\0", sep["thou"])

    def pct(x, places=0):
        """0.189 -> 18.9% style share (x in 0..1)."""
        return num(float(x) * 100, places) + "%"

    def month(m):
        """'2026-10' -> 'Oct 2026' / 'out/2026'."""
        t = pd.Timestamp(m + "-01")
        if lang == "pt-BR":
            return "jan fev mar abr mai jun jul ago set out nov dez".split()[t.month - 1] + f"/{t.year}"
        return t.strftime("%b %Y")

    def day(d):
        """'2026-11-09' -> 'Nov 9' / '9/nov'."""
        t = pd.Timestamp(d)
        if lang == "pt-BR":
            return f"{t.day}/" + "jan fev mar abr mai jun jul ago set out nov dez".split()[t.month - 1]
        return t.strftime("%b ") + str(t.day)

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(DECK), undefined=jinja2.StrictUndefined,
                             keep_trailing_newline=True, trim_blocks=True, lstrip_blocks=True)
    def qr(url):
        """QR code for a URL as a PNG data URI (no files, no base-path issues in the static build)."""
        return segno.make(url, error="m").png_data_uri(scale=12, border=2, dark="#14181f", light="#ffffff")

    env.globals["qr"] = qr
    env.filters.update(num=num, pct=pct, month=month, day=day,
                       y=lambda v: json.dumps(v, ensure_ascii=False), js=js)  # YAML-safe scalar/list/object
    return env


def js(v):
    """JS literal for a Vue :prop="…" binding: single-quoted strings, no double quotes (tahta rule)."""
    if isinstance(v, str):
        return "'" + v.replace("\\", "\\\\").replace("'", "\\'").replace('"', "&quot;") + "'"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(js(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}: {js(x)}" for k, x in v.items()) + "}"
    return json.dumps(v)


def render_strings(obj, env, ctx):
    """Render every i18n string through Jinja so text can embed {{ n.… }} numbers."""
    if isinstance(obj, dict):
        return {k: render_strings(v, env, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_strings(v, env, ctx) for v in obj]
    if isinstance(obj, str) and ("{{" in obj or "{%" in obj):
        return env.from_string(obj).render(**ctx).strip()
    return obj


def build(lang, n):
    env = make_env(lang)
    t = yaml.safe_load(open(DECK / "i18n" / f"{lang}.yaml"))
    ctx = {"n": n, "lang": lang}
    t = render_strings(t, env, ctx)
    out = env.get_template("deck.md.j2").render(t=t, **ctx)
    dest = DECK / f"slides.{lang}.md"
    dest.write_text(out)
    print(f"wrote {dest.relative_to(ROOT)} ({out.count(chr(10) + 'layout: ')} slides)")


def main():
    n = load_data()
    for lang in sys.argv[1:] or LANGS:
        build(lang, n)


if __name__ == "__main__":
    main()
