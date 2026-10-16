import os
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_FILE = Path(os.getenv("CVE_DATA_FILE", ROOT / "data" / "cve_data.csv"))
EMAIL_LOG_FILE = Path(os.getenv("EMAIL_LOG_FILE", ROOT / "data" / "email_log.csv"))
KEV_CACHE_FILE = Path(os.getenv("KEV_CACHE_FILE", ROOT / "data" / "kev.json"))
SUBSCRIPTIONS_FILE = Path(os.getenv("SUBSCRIPTIONS_FILE", ROOT / "subscriptions.json"))

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

CVSS_ALERT_THRESHOLD = float(os.getenv("CVSS_ALERT_THRESHOLD", "9.0"))
# probability of exploitation in the next 30 days, 0.1 is roughly the top 5 % of CVEs
EPSS_ALERT_THRESHOLD = float(os.getenv("EPSS_ALERT_THRESHOLD", "0.1"))
MAX_ENTRIES_PER_FEED = int(os.getenv("MAX_ENTRIES_PER_FEED", "5"))
# on each run, CVEs from bulletins newer than this are re-assessed (EPSS, KEV)
ALERT_WINDOW_DAYS = int(os.getenv("ALERT_WINDOW_DAYS", "30"))
REQUEST_TIMEOUT = 15

# without a key the NVD allows 5 requests per 30 s, 50 with a key
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# one session to reuse connections (big win on bulletins listing 1000+ CVEs)
http = requests.Session()
http.headers["User-Agent"] = "cvewatch/1.0"

# bulletin types as named by CERT-FR: "Avis" (advisory) and "Alerte" (alert, used for exploited flaws)
FEEDS = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

NA = "N/A"

# CSV column order
COLUMNS = [
    "Title", "Description", "Link", "Date", "CVE", "CVSS", "CWE", "EPSS",
    "CVE_Description", "Type", "Vendor", "Product", "Versions", "Base Severity",
    "CWE_ID", "CVSS_Source", "Affected",
]
