import pandas as pd

from .alerts import LOG_COLUMNS
from .config import DATA_FILE, EMAIL_LOG_FILE, NA
from .enrich import extract_cwe
from .priority import prioritize

REQUIRED = ["CWE", "Vendor", "Product", "CVSS", "EPSS", "Date"]


def load_cves(path=DATA_FILE):
    """Dataset ready for the dashboard: only fully enriched CVEs."""
    df = pd.read_csv(path, sep=";")
    df = df[~df[REQUIRED].isin([NA, "Not enough information"]).any(axis=1)]
    df = df.dropna(subset=REQUIRED).copy()

    df["Date"] = pd.to_datetime(df["Date"], errors="coerce", utc=True).dt.tz_localize(None)
    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")
    df["CWE_ID"] = df["CWE"].map(extract_cwe)
    return df.dropna(subset=["Date"])


def load_email_log(path=EMAIL_LOG_FILE):
    if path.exists():
        return pd.read_csv(path, sep=";", encoding="utf-8", on_bad_lines="warn")
    return pd.DataFrame(columns=LOG_COLUMNS)


def load_priorities(kev, path=DATA_FILE):
    """One row per CVE with its priority level. Starts from every row, not only complete
    CVEs: an exploited CVE with no known CWE must still show up."""
    df = pd.read_csv(path, sep=";")
    cves = prioritize(df, kev)
    cves["CWE_ID"] = cves["CWE"].map(extract_cwe)
    return cves
