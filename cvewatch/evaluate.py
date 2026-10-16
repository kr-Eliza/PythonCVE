"""Evaluates the priority signals against the CISA KEV catalog.

KEV is used as ground truth: a good rule should surface exploited CVEs without flooding
the analyst with alerts. KEV itself is not one of the rules under test, otherwise it would
trivially find itself.
"""
import pandas as pd

from .config import CVSS_ALERT_THRESHOLD, EPSS_ALERT_THRESHOLD
from .priority import by_cve


def evaluate(df, kev, cvss_threshold=CVSS_ALERT_THRESHOLD, epss_threshold=EPSS_ALERT_THRESHOLD):
    cves = by_cve(df)
    in_kev = cves["CVE"].isin(set(kev))
    high_cvss = cves["CVSS"] >= cvss_threshold
    high_epss = cves["EPSS"] >= epss_threshold
    alert = cves["CERT_FR_Alert"].astype(bool)
    rules = {
        f"CVSS >= {cvss_threshold:g}": high_cvss,
        f"CVSS >= {cvss_threshold:g} or EPSS >= {epss_threshold:g}": high_cvss | high_epss,
        "CERT-FR alert": alert,
        "CVSS, EPSS or CERT-FR alert": high_cvss | high_epss | alert,
    }
    rows = []
    for name, flagged in rules.items():
        hits = int((flagged & in_kev).sum())
        rows.append({
            "Rule": name,
            "Flagged CVEs": int(flagged.sum()),
            "KEV CVEs found": f"{hits} / {int(in_kev.sum())}",
            "Recall": hits / in_kev.sum() if in_kev.sum() else float("nan"),
            "Precision": hits / flagged.sum() if flagged.sum() else float("nan"),
        })
    return pd.DataFrame(rows), len(cves), int(in_kev.sum())


def print_report(df, kev):
    table, total, in_kev = evaluate(df, kev)
    print(f"{total} distinct CVEs, {in_kev} of them in KEV\n")
    table["Recall"] = table["Recall"].map("{:.0%}".format)
    table["Precision"] = table["Precision"].map("{:.0%}".format)
    print(table.to_string(index=False))
