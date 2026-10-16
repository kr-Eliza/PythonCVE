import pandas as pd

from cvewatch import pipeline
from cvewatch.config import COLUMNS, NA
from cvewatch.feeds import CVE_RE


def test_cve_regex():
    text = "CVE-2024-3094, cve-2024-1, CVE-2021-44228 and CVE-2024-1234567"
    assert CVE_RE.findall(text) == ["CVE-2024-3094", "CVE-2021-44228", "CVE-2024-1234567"]


def test_backfill(tmp_path, monkeypatch):
    path = tmp_path / "cve.csv"
    old_columns = [c for c in COLUMNS if c not in ("CVSS_Source", "Affected")]
    pd.DataFrame([
        {"CVE": "CVE-1", "CVSS": 9.8, "Link": "a"},
        {"CVE": "CVE-2", "CVSS": NA, "Link": "a"},
        {"CVE": "CVE-2", "CVSS": NA, "Link": "b"},
        {"CVE": "CVE-3", "CVSS": NA, "Link": "b"},
        {"CVE": "CVE-4", "CVSS": NA, "Link": "b"},
    ]).reindex(columns=old_columns).to_csv(path, sep=";", index=False)

    calls = []

    def fake_nvd(cve):
        calls.append(cve)
        if cve == "CVE-4":
            return None  # network failure
        return (5.5, "MEDIUM") if cve == "CVE-2" else (NA, NA)

    monkeypatch.setattr(pipeline, "fetch_nvd_cvss", fake_nvd)
    monkeypatch.setattr(pipeline, "fetch_mitre", lambda cve: None)
    df = pipeline.backfill(path)

    assert calls == ["CVE-2", "CVE-3", "CVE-4"]  # a single request per CVE
    assert df["CVSS_Source"].tolist()[:4] == ["MITRE", "NVD", "NVD", "none"]
    assert pd.isna(df["CVSS_Source"].iloc[4])  # not marked, it will be retried
    assert df.loc[df["CVE"] == "CVE-2", "CVSS"].astype(float).tolist() == [5.5, 5.5]

    # on a second run only the failed CVE is asked again
    calls.clear()
    pipeline.backfill(path)
    assert calls == ["CVE-4"]


def test_backfill_affected_products(tmp_path, monkeypatch):
    path = tmp_path / "cve.csv"
    pd.DataFrame([{"CVE": "CVE-1", "CVSS": 9.8, "Product": "FortiOS", "Versions": "7.2.0"}]
                 ).reindex(columns=COLUMNS).to_csv(path, sep=";", index=False)
    record = {"containers": {"cna": {"affected": [
        {"vendor": "Fortinet", "product": "FortiOS", "versions": [
            {"version": "7.2.0", "lessThanOrEqual": "7.2.6", "status": "affected"}]},
        {"vendor": "Fortinet", "product": "FortiProxy", "versions": []}]}}}
    monkeypatch.setattr(pipeline, "fetch_mitre", lambda cve: record)
    monkeypatch.setattr(pipeline.time, "sleep", lambda s: None)
    df = pipeline.backfill(path)
    assert "FortiProxy" in df.loc[0, "Affected"]
    assert df.loc[0, "Versions"] == "7.2.0 to 7.2.6"


def test_refresh_epss(monkeypatch):
    df = pd.DataFrame({"CVE": ["CVE-1", "CVE-2", "CVE-1"], "EPSS": ["0.01", "0.02", "0.01"]})
    monkeypatch.setattr(pipeline, "fetch_epss_batch", lambda ids: {"CVE-1": "0.9"})
    assert pipeline.refresh_epss(df) == 1
    assert df["EPSS"].tolist() == ["0.9", "0.02", "0.9"]

    # API down: nothing changes
    monkeypatch.setattr(pipeline, "fetch_epss_batch", lambda ids: None)
    assert pipeline.refresh_epss(df) == 0
    assert df["EPSS"].tolist() == ["0.9", "0.02", "0.9"]


def test_epss_batch_in_chunks(monkeypatch):
    from cvewatch import enrich
    calls = []

    def fake_get(url):
        ids = url.split("cve=")[1].split(",")
        calls.append(len(ids))
        return {"data": [{"cve": c, "epss": "0.5"} for c in ids]}

    monkeypatch.setattr(enrich, "_get_json", fake_get)
    scores = enrich.fetch_epss_batch([f"CVE-2024-{i}" for i in range(250)])
    assert calls == [100, 100, 50]
    assert len(scores) == 250
