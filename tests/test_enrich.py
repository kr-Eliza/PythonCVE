from cvewatch.config import NA
from cvewatch.enrich import extract_cwe, parse_mitre, parse_nvd


def mitre_record(cna=None, adp=None):
    return {"containers": {"cna": cna or {}, "adp": adp or []}}


def test_parse_mitre_full_cna():
    data = mitre_record(cna={
        "descriptions": [{"lang": "en", "value": "Buffer overflow"}],
        "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": "CWE-787",
                                            "description": "Out-of-bounds Write"}]}],
        "affected": [{"vendor": "OpenSSL", "product": "OpenSSL",
                      "versions": [{"version": "3.0.0", "status": "affected"},
                                   {"version": "3.0.8", "status": "unaffected"}]}],
    })
    info = parse_mitre(data)
    assert info["CVSS"] == 9.8
    assert info["Base Severity"] == "CRITICAL"
    assert info["CWE"] == "CWE-787 - Out-of-bounds Write"
    assert info["CVE_Description"] == "Buffer overflow"
    assert (info["Vendor"], info["Product"], info["Versions"]) == ("OpenSSL", "OpenSSL", "3.0.0")


def test_parse_mitre_filled_by_adp():
    # common case: the CNA gives no score, CISA (ADP) adds one
    data = mitre_record(
        cna={"descriptions": [{"value": "x"}]},
        adp=[{"metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}],
    )
    assert parse_mitre(data)["CVSS"] == 7.5


def test_parse_mitre_without_cvss():
    info = parse_mitre(mitre_record(cna={"descriptions": [{"value": "x"}]}))
    assert info["CVSS"] == NA
    assert info["Vendor"] == NA


def nvd_response(metrics):
    return {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "metrics": metrics}}]}


def cvss_entry(score, severity, kind):
    return {"type": kind, "cvssData": {"baseScore": score, "baseSeverity": severity}}


def test_parse_nvd_prefers_primary():
    data = nvd_response({"cvssMetricV31": [cvss_entry(7.8, "HIGH", "Secondary"),
                                           cvss_entry(4.7, "MEDIUM", "Primary")]})
    assert parse_nvd(data) == (4.7, "MEDIUM")


def test_parse_nvd_takes_newest_cvss_version():
    data = nvd_response({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                                           "cvssData": {"baseScore": 7.2}}],
                         "cvssMetricV31": [cvss_entry(5.5, "MEDIUM", "Primary")]})
    assert parse_nvd(data) == (5.5, "MEDIUM")


def test_parse_nvd_cvss_v2_only():
    data = nvd_response({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                                           "cvssData": {"baseScore": 7.2}}]})
    assert parse_nvd(data) == (7.2, "HIGH")


def test_parse_nvd_unknown_or_not_yet_analyzed():
    assert parse_nvd({"vulnerabilities": []}) == (NA, NA)
    assert parse_nvd(nvd_response({})) == (NA, NA)


def test_extract_cwe():
    assert extract_cwe("CWE-79 - Cross-site Scripting") == "CWE-79"
    assert extract_cwe("N/A") is None
    assert extract_cwe(None) is None
