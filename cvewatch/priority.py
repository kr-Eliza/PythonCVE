"""Priority level of each CVE.

1 - Exploited: listed in the CISA KEV catalog, or cited in a CERT-FR "Alerte"
    (CERT-FR publishes an Alerte, not just an Avis, when a flaw is being exploited).
2 - Watch: EPSS or CVSS above the thresholds.
3 - Everything else.
"""
import pandas as pd

from .config import CVSS_ALERT_THRESHOLD, EPSS_ALERT_THRESHOLD

LEVELS = {1: "1 - Exploited", 2: "2 - Watch", 3: "3 - Other"}


def by_cve(df):
    """One row per CVE (the same CVE is often cited by several bulletins)."""
    df = df[df["CVE"].notna() & (df["CVE"] != "")].copy()
    df["_cvss"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["_epss"] = pd.to_numeric(df["EPSS"], errors="coerce")
    df["_date"] = pd.to_datetime(df["Date"], errors="coerce", utc=True).dt.tz_localize(None)
    df = df.sort_values("_date")
    grouped = df.groupby("CVE", sort=False)
    out = grouped.agg(
        CVSS=("_cvss", "max"),
        EPSS=("_epss", "max"),
        CERT_FR_Alert=("Type", lambda t: (t == "Alerte").any()),
        Bulletins=("Link", "nunique"),
        First_bulletin=("_date", "min"),
        Last_bulletin=("_date", "max"),
    )
    # descriptive fields come from the most recent bulletin
    last = grouped.last()
    for col in ("Title", "Link", "Vendor", "Product", "Versions", "Affected", "CWE", "CWE_ID",
                "Base Severity", "CVE_Description"):
        if col in last:
            out[col] = last[col]
    return out.reset_index()


def add_priority(cves, kev, cvss_threshold=CVSS_ALERT_THRESHOLD, epss_threshold=EPSS_ALERT_THRESHOLD):
    """Adds KEV, Level and Reasons to a table made by by_cve()."""
    cves = cves.copy()
    cves["KEV"] = cves["CVE"].isin(set(kev))

    def reasons(row):
        found = []
        if row["KEV"]:
            found.append(f"KEV (added {kev[row['CVE']]})" if kev.get(row["CVE"]) else "KEV")
        if row["CERT_FR_Alert"]:
            found.append("CERT-FR alert")
        if pd.notna(row["EPSS"]) and row["EPSS"] >= epss_threshold:
            found.append(f"EPSS {row['EPSS']:.2f}")
        if pd.notna(row["CVSS"]) and row["CVSS"] >= cvss_threshold:
            found.append(f"CVSS {row['CVSS']:g}")
        return ", ".join(found)

    exploited = cves["KEV"] | cves["CERT_FR_Alert"]
    watch = (cves["EPSS"] >= epss_threshold) | (cves["CVSS"] >= cvss_threshold)
    cves["Level"] = 3
    cves.loc[watch, "Level"] = 2
    cves.loc[exploited, "Level"] = 1
    cves["Reasons"] = cves.apply(reasons, axis=1) if len(cves) else ""
    # within a level: KEV first, then likelihood of exploitation, then severity
    return cves.sort_values(["Level", "KEV", "EPSS", "CVSS"], ascending=[True, False, False, False],
                            na_position="last").reset_index(drop=True)


def prioritize(df, kev, **thresholds):
    return add_priority(by_cve(df), kev, **thresholds)
