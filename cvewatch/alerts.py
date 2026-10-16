import json
import logging
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

import pandas as pd

from . import versions
from .config import EMAIL_LOG_FILE, NA, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USER, SUBSCRIPTIONS_FILE
from .priority import LEVELS

log = logging.getLogger(__name__)

LOG_COLUMNS = ["User", "Email", "CVE", "Subject", "Body", "Date"]
ALERT_LEVELS = (1, 2)


def load_subscriptions(path=SUBSCRIPTIONS_FILE):
    """{email: [watched products]}. A product is a name, or {"product": ..., "version": ...}."""
    if not path.exists():
        log.warning("%s not found, nobody to notify", path.name)
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _normalize(item):
    if isinstance(item, str):
        return item, None
    return item["product"], item.get("version")


def match(cve, subscription):
    """Watched products affected by the CVE, as a list of (product, watched version, status).

    status is True (version affected) or None (no version given, or not decidable);
    versions that are not affected are left out.
    """
    affected = versions.loads(cve.get("Affected"))
    found = []
    for item in subscription:
        product, version = _normalize(item)
        entry = versions.find_product(affected, product)
        if entry is None:
            # record without an affected list: fall back on the product name
            if str(cve.get("Product", "")).lower() != product.lower():
                continue
            found.append((product, version, None))
            continue
        status = versions.is_affected(version, entry) if version else None
        if status is not False:
            found.append((product, version, status))
    return found


def build_message(cve, matched):
    level = LEVELS.get(cve.get("Level"), "")
    subject = f"CVE alert: {cve['CVE']} ({cve.get('Reasons') or level}) - Product: {matched[0][0]}"
    lines = []
    for product, version, status in matched:
        if version is None:
            lines.append(f"  - {product}")
        elif status:
            lines.append(f"  - {product} {version}: affected version")
        else:
            lines.append(f"  - {product} {version}: version could not be checked, please verify")
    body = "\n".join([
        "Alert: an exploited or high-risk vulnerability affects software you watch.",
        "",
        f"Priority          : {level}",
        f"Reasons           : {cve.get('Reasons') or NA}",
        "",
        "Watched software concerned:",
        *lines,
        "",
        f"Bulletin          : {cve.get('Title', NA)}",
        f"CVE               : {cve['CVE']}",
        f"CVSS              : {cve.get('CVSS', NA)}/10",
        f"EPSS              : {cve.get('EPSS', NA)}",
        f"Affected versions : {cve.get('Versions', NA)}",
        f"Link              : {cve.get('Link', NA)}",
        "",
        str(cve.get("CVE_Description") or ""),
    ])
    return subject, body


def already_sent(path=EMAIL_LOG_FILE):
    """(email, CVE) pairs already notified, so the same alert is not sent on every run."""
    if not path.exists():
        return set()
    sent = pd.read_csv(path, sep=";", encoding="utf-8", on_bad_lines="warn")
    return set(zip(sent["Email"], sent["CVE"]))


def log_email(to_email, cve_id, subject, body):
    row = pd.DataFrame([{
        "User": "System",
        "Email": to_email,
        "CVE": cve_id,
        "Subject": subject,
        "Body": body.replace("\n", " "),
        "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }], columns=LOG_COLUMNS)
    EMAIL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    row.to_csv(EMAIL_LOG_FILE, mode="a", header=not EMAIL_LOG_FILE.exists(),
               index=False, sep=";", encoding="utf-8")


def select_alerts(cves):
    """Level 1 and 2 CVEs from a table made by priority.prioritize()."""
    return cves[cves["Level"].isin(ALERT_LEVELS)]


def build_messages(cves, subscriptions, sent=frozenset()):
    messages = []
    for email, subscription in subscriptions.items():
        for _, cve in select_alerts(cves).iterrows():
            if (email, cve["CVE"]) in sent:
                continue
            matched = match(cve, subscription)
            if matched:
                messages.append((email, cve["CVE"], *build_message(cve, matched)))
    return messages


def notify_critical(cves, subscriptions, send=True):
    """Sends one mail per flagged CVE to every subscriber watching an affected product."""
    log.info("%d level 1 or 2 vulnerabilit(ies)", len(select_alerts(cves)))
    messages = build_messages(cves, subscriptions, already_sent())

    if not messages:
        return 0
    if not send or not (SMTP_USER and SMTP_PASSWORD):
        if send:
            log.warning("SMTP_USER / SMTP_PASSWORD missing from .env, no mail sent")
        for email, _, subject, _ in messages:
            log.info("[not sent] %s: %s", email, subject)
        return 0

    sent = 0
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        for email, cve_id, subject, body in messages:
            msg = MIMEText(body)
            msg["From"], msg["To"], msg["Subject"] = SMTP_USER, email, subject
            try:
                server.sendmail(SMTP_USER, email, msg.as_string())
            except smtplib.SMTPException as e:
                log.error("Could not send to %s: %s", email, e)
                continue
            log_email(email, cve_id, subject, body)
            sent += 1
            log.info("Mail sent to %s (%s)", email, subject)
    return sent
