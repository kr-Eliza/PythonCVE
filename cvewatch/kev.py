"""CISA KEV catalog: vulnerabilities with confirmed exploitation."""
import json
import logging

import requests

from .config import KEV_CACHE_FILE, REQUEST_TIMEOUT, http

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev(data):
    """{cve: date added to the catalog}"""
    return {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}


def load_kev(path=KEV_CACHE_FILE, refresh=True):
    """Downloads the catalog and caches it. Offline, the cache is used instead."""
    if refresh:
        try:
            resp = http.get(KEV_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
            return parse_kev(data)
        except (requests.RequestException, ValueError) as e:
            log.warning("KEV catalog unreachable (%s), using the cache", e)
    if path.exists():
        try:
            return parse_kev(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            log.warning("Unreadable KEV cache: %s", path)
    log.warning("No KEV catalog available, priorities ignore KEV")
    return {}
