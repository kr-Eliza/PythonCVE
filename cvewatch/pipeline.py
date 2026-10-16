import argparse
import logging
import time

import pandas as pd

from . import alerts, versions
from .config import ALERT_WINDOW_DAYS, COLUMNS, DATA_FILE, NA
from .enrich import enrich_cve, fetch_epss_batch, fetch_mitre, fetch_nvd_cvss, parse_mitre
from .feeds import extract_cves, fetch_bulletins, to_naive_utc
from .kev import load_kev
from .priority import prioritize

log = logging.getLogger(__name__)


def load_dataset(path=DATA_FILE):
    if path.exists():
        # reindex: a CSV from an older version may lack some columns.
        # object everywhere since columns mix numbers and "N/A"
        return pd.read_csv(path, sep=";").reindex(columns=COLUMNS).astype(object)
    return pd.DataFrame(columns=COLUMNS)


def save_dataset(df, path=DATA_FILE):
    tmp = path.with_suffix(".tmp")
    df.to_csv(tmp, sep=";", index=False)
    tmp.replace(path)


def last_bulletin_date(df):
    dates = df["Date"].map(to_naive_utc).dropna()
    if dates.empty:
        return pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(days=1)
    return dates.max()


def collect(since, known):
    """One row per (bulletin, CVE) pair. A bulletin without CVEs gives one row with an empty CVE."""
    rows = []
    for bulletin in fetch_bulletins(since):
        cves = extract_cves(bulletin["Link"])
        log.info("%s: %d CVEs", bulletin["Title"], len(cves))
        for cve in cves or [""]:
            if (bulletin["Link"], cve) in known:
                continue
            info = enrich_cve(cve) if cve else {col: NA for col in ("CVSS", "CWE", "EPSS")}
            rows.append({**bulletin, "CVE": cve, **info})
    return pd.DataFrame(rows, columns=COLUMNS)


def refresh_epss(df, cve_ids=None):
    """EPSS changes every day: updates the score of the given CVEs (all of them by default)."""
    if cve_ids is None:
        cve_ids = df["CVE"].dropna().unique()
    cve_ids = [c for c in cve_ids if c]
    scores = fetch_epss_batch(cve_ids)
    if scores is None:
        log.warning("EPSS API unreachable, scores not updated")
        return 0
    updated = df["CVE"].isin(scores.keys())
    df.loc[updated, "EPSS"] = df.loc[updated, "CVE"].map(scores)
    log.info("EPSS updated for %d CVEs", len(scores))
    return len(scores)


def to_reassess(df, new_rows, window_days=ALERT_WINDOW_DAYS):
    """CVEs to re-assess: the new ones, and those from recent bulletins (their EPSS or their
    presence in KEV may have changed since the last run)."""
    dates = df["Date"].map(to_naive_utc)
    limit = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(days=window_days)
    recent = set(df.loc[dates >= limit, "CVE"].dropna())
    return recent | set(new_rows["CVE"].dropna())


def run_once(send_mails=True):
    df = load_dataset()
    since = last_bulletin_date(df)
    log.info("Looking for bulletins published after %s", since)

    known = set(zip(df["Link"], df["CVE"].fillna("")))
    new_rows = collect(since, known)
    df = pd.concat([df, new_rows], ignore_index=True)
    reassess = to_reassess(df, new_rows) - {""}
    if new_rows.empty and not reassess:
        log.info("Nothing new")
        return new_rows

    refresh_epss(df, reassess)
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    # rewrite the whole file instead of appending, to keep the columns aligned
    save_dataset(df)
    log.info("%d row(s) added to %s", len(new_rows), DATA_FILE.name)

    cves = prioritize(df[df["CVE"].isin(reassess)], load_kev())
    alerts.notify_critical(cves, alerts.load_subscriptions(), send=send_mails)
    return new_rows


def _backfill_cvss(df, save):
    has_cvss = pd.to_numeric(df["CVSS"], errors="coerce").notna()
    df.loc[has_cvss & df["CVSS_Source"].isna(), "CVSS_Source"] = "MITRE"

    todo = df.loc[~has_cvss & df["CVE"].notna() & df["CVSS_Source"].isna(), "CVE"].unique()
    log.info("%d CVEs without CVSS to look up in NVD", len(todo))
    for i, cve in enumerate(todo, 1):
        if i % 50 == 0:
            save()
            log.info("%d/%d CVEs done", i, len(todo))
        result = fetch_nvd_cvss(cve)
        if result is None:
            continue  # NVD unreachable, the CVE will be retried on the next run
        cvss, severity = result
        rows = df["CVE"] == cve
        if cvss != NA:
            df.loc[rows, ["CVSS", "Base Severity", "CVSS_Source"]] = [cvss, severity, "NVD"]
        else:
            # marked so it is not asked again on every run
            df.loc[rows, "CVSS_Source"] = "none"
    log.info("%d CVEs done", len(todo))


def _backfill_products(df, save):
    """The first collections only kept the first affected product, without version ranges."""
    todo = df.loc[df["CVE"].notna() & df["Affected"].isna(), "CVE"].unique()
    log.info("%d CVEs without an affected list to re-read from MITRE", len(todo))
    for i, cve in enumerate(todo, 1):
        if i % 100 == 0:
            save()
            log.info("%d/%d MITRE records read", i, len(todo))
        data = fetch_mitre(cve)
        if data is None:
            continue
        info = parse_mitre(data)
        rows = df["CVE"] == cve
        df.loc[rows, "Affected"] = info["Affected"]
        if versions.loads(info["Affected"]):
            df.loc[rows, ["Vendor", "Product", "Versions"]] = [info["Vendor"], info["Product"], info["Versions"]]
        time.sleep(0.1)
    # leftovers from the first collections: git commit hashes instead of versions
    git_hashes = df["Versions"].astype(str).str.contains(r"\b[0-9a-f]{40}\b")
    df.loc[git_hashes, "Versions"] = NA
    log.info("%d MITRE records read", len(todo))


def backfill(path=DATA_FILE):
    """Completes data already collected: missing CVSS (NVD) and affected products (MITRE).
    Saves regularly and can be run again if interrupted."""
    df = load_dataset(path)

    def save():
        save_dataset(df, path)

    _backfill_cvss(df, save)
    _backfill_products(df, save)
    save()
    return df


def main():
    parser = argparse.ArgumentParser(description="CVE watch based on CERT-FR feeds")
    parser.add_argument("--loop", type=int, metavar="MINUTES",
                        help="run a collection every MINUTES minutes")
    parser.add_argument("--no-mail", action="store_true", help="do not send alert mails")
    parser.add_argument("--backfill", action="store_true",
                        help="fill in missing CVSS (NVD) and affected products (MITRE) in existing data")
    parser.add_argument("--refresh-epss", action="store_true",
                        help="update the EPSS score of every CVE in existing data")
    parser.add_argument("--evaluate", action="store_true",
                        help="compare the priority rules with the CISA KEV catalog")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
    if args.backfill:
        backfill()
        return
    if args.refresh_epss:
        df = load_dataset()
        if refresh_epss(df):
            save_dataset(df)
        return
    if args.evaluate:
        from .evaluate import print_report
        print_report(load_dataset(), load_kev())
        return
    while True:
        try:
            run_once(send_mails=not args.no_mail)
        except Exception:
            log.exception("Collection failed")
        if not args.loop:
            break
        log.info("Next collection in %d min", args.loop)
        time.sleep(args.loop * 60)


if __name__ == "__main__":
    main()
