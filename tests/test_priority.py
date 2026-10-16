import pandas as pd

from cvewatch.kev import parse_kev
from cvewatch.priority import prioritize


def rows():
    return pd.DataFrame([
        # same CVE in two bulletins: a single output row
        {"CVE": "CVE-KEV", "CVSS": 6.9, "EPSS": 0.01, "Type": "Avis", "Link": "a", "Date": "2024-12-01"},
        {"CVE": "CVE-KEV", "CVSS": 6.9, "EPSS": 0.01, "Type": "Avis", "Link": "b", "Date": "2024-12-05"},
        {"CVE": "CVE-ALERT", "CVSS": 5.0, "EPSS": 0.02, "Type": "Alerte", "Link": "c", "Date": "2024-12-02"},
        {"CVE": "CVE-EPSS", "CVSS": 5.5, "EPSS": 0.4, "Type": "Avis", "Link": "a", "Date": "2024-12-01"},
        {"CVE": "CVE-CVSS", "CVSS": 9.8, "EPSS": 0.001, "Type": "Avis", "Link": "a", "Date": "2024-12-01"},
        {"CVE": "CVE-LOW", "CVSS": "N/A", "EPSS": 0.001, "Type": "Avis", "Link": "a", "Date": "2024-12-01"},
        {"CVE": None, "CVSS": None, "EPSS": None, "Type": "Avis", "Link": "d", "Date": "2024-12-01"},
    ])


def test_levels_and_order():
    cves = prioritize(rows(), {"CVE-KEV": "2024-12-10"}, cvss_threshold=9.0, epss_threshold=0.1)
    assert cves["CVE"].tolist() == ["CVE-KEV", "CVE-ALERT", "CVE-EPSS", "CVE-CVSS", "CVE-LOW"]
    assert cves["Level"].tolist() == [1, 1, 2, 2, 3]
    kev_row = cves.iloc[0]
    assert kev_row["Bulletins"] == 2
    assert kev_row["Reasons"] == "KEV (added 2024-12-10)"
    assert cves.loc[cves["CVE"] == "CVE-ALERT", "Reasons"].item() == "CERT-FR alert"
    assert cves.loc[cves["CVE"] == "CVE-EPSS", "Reasons"].item() == "EPSS 0.40"


def test_parse_kev():
    data = {"vulnerabilities": [{"cveID": "CVE-2024-3400", "dateAdded": "2024-04-12"}]}
    assert parse_kev(data) == {"CVE-2024-3400": "2024-04-12"}
