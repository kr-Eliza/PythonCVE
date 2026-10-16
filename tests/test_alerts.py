import pandas as pd

from cvewatch import alerts
from cvewatch.versions import dumps, parse_affected

AFFECTED = dumps(parse_affected([{"affected": [
    {"vendor": "Fortinet", "product": "FortiOS", "defaultStatus": "unaffected", "versions": [
        {"version": "7.2.0", "lessThanOrEqual": "7.2.6", "status": "affected"}]},
    {"vendor": "Fortinet", "product": "FortiProxy", "defaultStatus": "unaffected", "versions": [
        {"version": "7.2.0", "lessThanOrEqual": "7.2.8", "status": "affected"}]},
]}]))


def cve(**extra):
    base = {"CVE": "CVE-2024-21762", "Level": 1, "Reasons": "KEV, CERT-FR alert", "CVSS": 9.6,
            "EPSS": 0.02, "Product": "FortiOS", "Affected": AFFECTED, "Title": "Alerte Fortinet",
            "Link": "https://x", "Versions": "7.2.0 to 7.2.6", "CVE_Description": "Out-of-bounds write"}
    return pd.Series({**base, **extra})


def test_match_every_product():
    # FortiProxy is not the first product of the record but must still trigger the alert
    assert alerts.match(cve(), ["FortiProxy"]) == [("FortiProxy", None, None)]


def test_match_version():
    assert alerts.match(cve(), [{"product": "FortiOS", "version": "7.2.4"}]) == [("FortiOS", "7.2.4", True)]
    assert alerts.match(cve(), [{"product": "FortiOS", "version": "7.2.7"}]) == []


def test_match_record_without_affected_list():
    assert alerts.match(cve(Affected=float("nan")), ["FortiOS"]) == [("FortiOS", None, None)]
    assert alerts.match(cve(Affected=float("nan")), ["FortiProxy"]) == []


def test_build_messages_levels_and_duplicates():
    cves = pd.DataFrame([cve(), cve(CVE="CVE-LOW", Level=3)])
    subs = {"soc@example.com": ["FortiOS"], "dev@example.com": ["OpenSSL"]}
    messages = alerts.build_messages(cves, subs)
    assert [(m[0], m[1]) for m in messages] == [("soc@example.com", "CVE-2024-21762")]
    subject, body = messages[0][2], messages[0][3]
    assert "CVE-2024-21762" in subject and "KEV" in subject
    assert "1 - Exploited" in body and "  - FortiOS" in body
    assert body.startswith("Alert: ")

    # already notified: no new mail
    assert alerts.build_messages(cves, subs, sent={("soc@example.com", "CVE-2024-21762")}) == []


def test_message_with_multiline_description():
    _, body = alerts.build_message(cve(CVE_Description="line 1\nline 2"), [("FortiOS", "7.2.4", True)])
    assert all(not line.startswith("        ") for line in body.splitlines())
    assert "  - FortiOS 7.2.4: affected version" in body


def test_already_sent(tmp_path):
    path = tmp_path / "log.csv"
    pd.DataFrame([{"User": "System", "Email": "a@example.com", "CVE": "CVE-2024-3400",
                   "Subject": "CVE alert: CVE-2024-3400", "Body": "", "Date": ""}]
                 ).to_csv(path, sep=";", index=False)
    assert alerts.already_sent(path) == {("a@example.com", "CVE-2024-3400")}
