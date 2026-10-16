import io
import logging

import pandas as pd
import plotly.express as px
import streamlit as st

from cvewatch import pipeline
from cvewatch.config import CVSS_ALERT_THRESHOLD, DATA_FILE, EPSS_ALERT_THRESHOLD
from cvewatch.data import load_cves, load_email_log, load_priorities
from cvewatch.kev import load_kev
from cvewatch.priority import LEVELS

st.set_page_config(page_title="CVE watch", layout="wide")

LEVEL_COLORS = ["#c0392b", "#e67e22", "#95a5a6"]


@st.cache_data
def cves():
    return load_cves()


@st.cache_data(ttl=6 * 3600)
def kev():
    return load_kev()


@st.cache_data
def priorities():
    return load_priorities(kev())


def without_linux(df):
    """A single kernel bulletin can cite hundreds of CVEs, which flattens every chart."""
    if st.session_state.get("hide_linux"):
        return df[df["Vendor"] != "Linux"]
    return df


def cwe_labels(df):
    """CWE-79 -> 'CWE-79 - Improper Neutralization...' for readable axes."""
    return df.dropna(subset=["CWE_ID"]).groupby("CWE_ID")["CWE"].first()


def page_home():
    st.title("Vulnerability watch")
    st.write(
        "Collects the latest CERT-FR advisories and alerts, enriches every CVE with the MITRE API "
        "(and NVD when the MITRE record has no CVSS), the EPSS score and the CISA KEV catalog, "
        "then emails the subscribers concerned."
    )
    prio = without_linux(priorities())
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Distinct CVEs", len(prio))
    col2.metric("Level 1: exploited", int((prio["Level"] == 1).sum()))
    col3.metric("Level 2: watch", int((prio["Level"] == 2).sum()))
    col4.metric("Last bulletin", prio["Last_bulletin"].max().strftime("%d/%m/%Y"))
    st.caption(
        f"Level 1: in KEV or cited in a CERT-FR alert. Level 2: EPSS >= {EPSS_ALERT_THRESHOLD:g} "
        f"or CVSS >= {CVSS_ALERT_THRESHOLD:g}. KEV catalog: {len(kev())} CVEs. "
        f"CVSS taken from NVD: {(cves()['CVSS_Source'] == 'NVD').mean():.0%} of rows."
    )

    st.subheader("Run a collection")
    st.caption("For continuous monitoring: `python -m cvewatch --loop 30`")
    send = st.checkbox("Send alert mails", value=False)
    if st.button("Collect now"):
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        try:
            with st.spinner("Collecting..."):
                new_rows = pipeline.run_once(send_mails=send)
            st.success(f"{len(new_rows)} new row(s) added to {DATA_FILE.name}")
            cves.clear()
            priorities.clear()
        except Exception as e:
            st.error(f"Collection failed: {e}")
        finally:
            root.removeHandler(handler)
        st.text_area("Logs", buffer.getvalue(), height=300)


def page_priorities():
    st.title("What to fix first")
    st.write("One row per CVE, from most to least urgent.")
    prio = without_linux(priorities())

    col1, col2, col3 = st.columns(3)
    levels = col1.multiselect("Level", list(LEVELS), default=[1, 2], format_func=LEVELS.get)
    vendors = sorted(prio["Vendor"].dropna().astype(str).unique())
    vendor = col2.selectbox("Vendor", ["All"] + vendors)
    search = col3.text_input("Product contains")

    shown = prio[prio["Level"].isin(levels)]
    if vendor != "All":
        shown = shown[shown["Vendor"] == vendor]
    if search:
        shown = shown[shown["Affected"].astype(str).str.contains(search, case=False, regex=False)
                      | shown["Product"].astype(str).str.contains(search, case=False, regex=False)]

    st.write(f"{len(shown)} CVEs")
    st.dataframe(
        shown.assign(Level=shown["Level"].map(LEVELS))[
            ["CVE", "Level", "Reasons", "CVSS", "EPSS", "Vendor", "Product", "Versions",
             "Last_bulletin", "Link"]],
        hide_index=True,
        column_config={
            "EPSS": st.column_config.ProgressColumn("EPSS", min_value=0.0, max_value=1.0, format="%.2f"),
            "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "Last_bulletin": st.column_config.DateColumn("Last bulletin", format="DD/MM/YYYY"),
            "Link": st.column_config.LinkColumn("Bulletin", display_text="CERT-FR"),
        },
    )


def page_cve():
    st.title("CVE details")
    df = cves()
    st.subheader("10 latest CVEs")
    st.dataframe(df.sort_values("Date", ascending=False).head(10), hide_index=True)

    st.subheader("Look up a CVE")
    selected = st.selectbox("CVE", sorted(df["CVE"].unique(), reverse=True))
    if selected:
        prio = priorities()
        row = prio[prio["CVE"] == selected]
        if not row.empty:
            st.write(f"Priority: **{LEVELS[row['Level'].iloc[0]]}**. {row['Reasons'].iloc[0]}")
        st.dataframe(df[df["CVE"] == selected].T.astype(str), width="stretch")


def page_mails():
    st.title("Sent mails")
    log = load_email_log()
    if log.empty:
        st.info("No mail sent yet.")
        return
    user = st.selectbox("Recipient", log["Email"].unique())
    st.dataframe(log[log["Email"] == user], hide_index=True)


def page_charts():
    st.title("Charts")
    st.caption("Each CVE is counted once, even when several bulletins cite it.")
    df = without_linux(priorities()).dropna(subset=["CVSS", "EPSS"]).copy()
    labels = cwe_labels(df)

    per_level = df["Level"].map(LEVELS).value_counts().sort_index().rename_axis("Level").reset_index(name="CVEs")
    fig = px.bar(per_level, x="Level", y="CVEs", color="Level", title="CVEs per priority level",
                 color_discrete_sequence=LEVEL_COLORS)
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, width="stretch")

    top_cwe = df["CWE_ID"].value_counts().head(10).rename_axis("CWE").reset_index(name="CVEs")
    top_cwe["CWE"] = top_cwe["CWE"].map(labels)
    fig = px.bar(top_cwe, x="CWE", y="CVEs", color="CVEs", color_continuous_scale="Blues",
                 title="Top 10 weakness types (CWE)", height=600)
    fig.update_layout(xaxis_tickangle=45, xaxis_title=None)
    st.plotly_chart(fig, width="stretch")

    fig = px.histogram(df, x="EPSS", nbins=50, marginal="box", color_discrete_sequence=["green"],
                       title="EPSS score distribution")
    fig.update_layout(xaxis_title="EPSS score", yaxis_title="CVEs")
    st.plotly_chart(fig, width="stretch")

    df["Priority"] = df["Level"].map(LEVELS)
    fig = px.scatter(df, x="CVSS", y="EPSS", color="Priority", hover_data=["CVE", "Vendor", "Product", "Reasons"],
                     color_discrete_map=dict(zip(LEVELS.values(), LEVEL_COLORS)),
                     title="CVSS and EPSS: a high CVSS does not mean likely exploitation")
    st.plotly_chart(fig, width="stretch")
    st.caption(f"CVSS / EPSS correlation: {df['CVSS'].corr(df['EPSS']):.2f}")

    per_month = df.groupby(df["First_bulletin"].dt.to_period("M").astype(str)).size().reset_index(name="CVEs")
    fig = px.bar(per_month, x="First_bulletin", y="CVEs", color="CVEs", color_continuous_scale="Teal",
                 title="New CVEs per month (first bulletin citing them)")
    fig.update_layout(xaxis_title="Month")
    st.plotly_chart(fig, width="stretch")

    products = df["Product"].value_counts().head(10).rename_axis("Product").reset_index(name="CVEs")
    fig = px.bar(products, x="Product", y="CVEs", color="CVEs", color_continuous_scale="Oranges",
                 title="Top 10 most affected products")
    fig.update_layout(xaxis_tickangle=45)
    st.plotly_chart(fig, width="stretch")

    df["Severity"] = pd.cut(df["CVSS"], bins=[0, 3.9, 6.9, 8.9, 10], labels=["Low", "Medium", "High", "Critical"])
    per_day = df.groupby([df["First_bulletin"].dt.date, "Severity"], observed=False).size().reset_index(name="CVEs")
    fig = px.area(per_day, x="First_bulletin", y="CVEs", color="Severity",
                  color_discrete_sequence=px.colors.sequential.Viridis,
                  title="Vulnerabilities over time by CVSS severity")
    fig.update_layout(xaxis_title="Date")
    st.plotly_chart(fig, width="stretch")


def page_dates():
    st.title("Filter by date")
    df = cves()
    first, last = df["Date"].min().date(), df["Date"].max().date()
    day = st.date_input("Publication date", value=last, min_value=first, max_value=last)
    selected = df[df["Date"].dt.date == day]
    st.write(f"{len(selected)} CVE(s) published on {day:%d/%m/%Y}")
    if not selected.empty:
        st.dataframe(selected, hide_index=True)


PAGES = {
    "Home": page_home,
    "What to fix first": page_priorities,
    "CVE": page_cve,
    "Mails": page_mails,
    "Charts": page_charts,
    "Filter by date": page_dates,
}

choice = st.sidebar.radio("Navigation", list(PAGES))
st.sidebar.checkbox("Hide Linux kernel CVEs", key="hide_linux")
PAGES[choice]()
