import logging
import re

import feedparser
import pandas as pd
import requests

from .config import FEEDS, MAX_ENTRIES_PER_FEED, REQUEST_TIMEOUT, http

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def to_naive_utc(value):
    ts = pd.to_datetime(value, errors="coerce", utc=True)
    return ts.tz_localize(None) if not pd.isna(ts) else pd.NaT


def fetch_bulletins(since=None):
    """Latest CERT-FR advisories and alerts published after `since`."""
    bulletins = []
    for kind, url in FEEDS.items():
        resp = http.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        if not feed.entries:
            log.warning("Empty or unreadable feed: %s", url)
            continue

        kept = 0
        for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
            published = to_naive_utc(entry.get("published"))
            if pd.isna(published) or (since is not None and published <= since):
                continue
            bulletins.append({
                "Title": entry.title,
                "Description": entry.description,
                "Link": entry.link,
                "Date": entry.published,
                "Type": kind,
            })
            kept += 1
        log.info("%s: %d new bulletin(s)", kind, kept)
    return bulletins


def extract_cves(link):
    """Each bulletin also exists as JSON, which lists the CVEs it covers."""
    try:
        resp = http.get(link.rstrip("/") + "/json/", timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        log.warning("Could not read %s: %s", link, e)
        return []
    return sorted(set(CVE_RE.findall(resp.text)))
