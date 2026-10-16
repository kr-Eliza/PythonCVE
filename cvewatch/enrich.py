import logging
import re
import time
from functools import lru_cache

import pandas as pd
import requests

from . import versions
from .config import NA, NVD_API_KEY, REQUEST_TIMEOUT, http

log = logging.getLogger(__name__)

MITRE_API = "https://cveawg.mitre.org/api/cve/{}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
EPSS_BATCH = 100  # the API takes several comma-separated CVEs
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_KEYS = ("cvssV3_0", "cvssV3_1", "cvssV4_0")
# newest first, CVSS v2 is only there for old CVEs
NVD_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
_last_nvd_call = 0.0


def _get_json(url):
    try:
        resp = http.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("Error on %s: %s", url, e)
        return None


def _first_cvss(sections):
    for metrics in sections:
        for metric in metrics:
            for key in CVSS_KEYS:
                if key in metric:
                    return metric[key].get("baseScore", NA), metric[key].get("baseSeverity", NA)
    return NA, NA


def _first_cwe(sections):
    for problem_types in sections:
        for problem in problem_types:
            for desc in problem.get("descriptions", []):
                if desc.get("type") == "CWE":
                    return desc.get("cweId", NA), desc.get("description", NA)
    return NA, NA


def parse_mitre(data):
    """Scores, CWE and affected products from a CVE JSON 5 record."""
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    # the CNA often leaves fields empty, CISA (ADP) fills some of them
    blocks = [cna] + containers.get("adp", [])

    cvss, severity = _first_cvss(b.get("metrics", []) for b in blocks)
    cwe_id, cwe_desc = _first_cwe(b.get("problemTypes", []) for b in blocks)
    description = next((d["value"] for d in cna.get("descriptions", []) if "value" in d), NA)

    affected = versions.parse_affected(blocks)
    first = affected[0] if affected else {}

    return {
        "CVSS": cvss,
        "CWE": f"{cwe_id} - {cwe_desc}",
        "CVE_Description": description,
        "Vendor": first.get("vendor") or NA,
        "Product": first.get("product") or NA,
        "Versions": (versions.describe(first) or NA) if first else NA,
        "Base Severity": severity,
        # every affected product, not just the first one (e.g. FortiOS and FortiProxy)
        "Affected": versions.dumps(affected),
    }


def parse_nvd(data):
    """CVSS from an NVD response, preferring the Primary score (computed by NVD) over Secondary (CNA)."""
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return NA, NA
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in NVD_METRICS:
        entries = sorted(metrics.get(key, []), key=lambda m: m.get("type") != "Primary")
        if entries:
            cvss = entries[0].get("cvssData", {})
            severity = cvss.get("baseSeverity") or entries[0].get("baseSeverity", NA)
            return cvss.get("baseScore", NA), severity
    return NA, NA


def fetch_nvd_cvss(cve_id):
    """CNAs such as kernel.org publish no CVSS in the MITRE record, NVD computes one.

    Returns None when NVD could not be reached, so that a network failure is not mistaken
    for a CVE that NVD has not scored yet.
    """
    global _last_nvd_call
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(3):
        wait = NVD_DELAY - (time.monotonic() - _last_nvd_call)
        if wait > 0:
            time.sleep(wait)
        _last_nvd_call = time.monotonic()
        try:
            resp = http.get(NVD_API, params={"cveId": cve_id}, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code in (403, 429, 503):
                log.warning("NVD rate limit hit for %s, retrying in 30 s", cve_id)
                time.sleep(30)
                continue
            resp.raise_for_status()
            return parse_nvd(resp.json())
        except (requests.RequestException, ValueError) as e:
            log.warning("NVD error on %s: %s", cve_id, e)
            return None
    return None


def fetch_epss(cve_id):
    data = _get_json(EPSS_API.format(cve_id))
    if not data or not data.get("data"):
        return NA
    return data["data"][0].get("epss", NA)


def fetch_epss_batch(cve_ids):
    """{cve: today's EPSS score}. CVEs missing from the response are left out."""
    cve_ids = list(cve_ids)
    scores = {}
    for i in range(0, len(cve_ids), EPSS_BATCH):
        data = _get_json(EPSS_API.format(",".join(cve_ids[i:i + EPSS_BATCH])))
        if data is None:
            return None  # API unreachable, keep the previous scores
        scores.update({d["cve"]: d["epss"] for d in data.get("data", [])})
    return scores


def fetch_mitre(cve_id):
    return _get_json(MITRE_API.format(cve_id))


# the same CVE often shows up in several bulletins
@lru_cache(maxsize=None)
def enrich_cve(cve_id):
    info = {"CVSS": NA, "CWE": NA, "CVE_Description": NA, "Vendor": NA,
            "Product": NA, "Versions": NA, "Base Severity": NA, "Affected": NA}
    data = fetch_mitre(cve_id)
    if data:
        info.update(parse_mitre(data))
    info["CVSS_Source"] = "MITRE" if info["CVSS"] != NA else NA
    if info["CVSS"] == NA:
        nvd = fetch_nvd_cvss(cve_id)
        if nvd and nvd[0] != NA:
            info["CVSS"], info["Base Severity"] = nvd
            info["CVSS_Source"] = "NVD"
    info["EPSS"] = fetch_epss(cve_id)
    info["CWE_ID"] = extract_cwe(info["CWE"])
    log.info("%s: CVSS %s, EPSS %s, %s", cve_id, info["CVSS"], info["EPSS"], info["Product"])
    return info


def extract_cwe(value):
    """'CWE-79 - Cross-site Scripting' -> 'CWE-79'"""
    if pd.isna(value):
        return None
    match = re.search(r"CWE-\d+", str(value))
    return match.group(0) if match else None
