from pathlib import Path
from collections import Counter
import json

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st


# ============================================================
# AI SECURITY COPILOT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "Data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

EVIDENCE_FILE = BASE_DIR / "security_evidence.json"
SCHEMA_FILE = BASE_DIR / "security_schema.json"
ALERT_FILE = BASE_DIR / "security_alerts.json"
MITRE_FILE = BASE_DIR / "MITRE" / "mitre_evaluated.json"
REPORT_FILE = BASE_DIR / "ai_security_report.txt"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Security Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# COLOURS
# ============================================================

BG = "#0b0f17"
SIDEBAR_BG = "#080d15"

PANEL = "#171c27"
PANEL_DARK = "#111722"
BORDER = "#2b3442"

TEXT = "#f4f7fb"
MUTED = "#8995a7"

RED = "#ff3b45"
ORANGE = "#ff7043"
YELLOW = "#ffd21f"
BLUE = "#3b9cff"
GREY = "#94a3b8"

GREEN = "#25e878"
CYAN = "#18d6c2"
PURPLE = "#b832e8"


SEVERITY_COLOURS = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": YELLOW,
    "Low": BLUE,
    "Informational": GREY,
}


# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    f"""
<style>

.stApp {{
    background: {BG};
}}

[data-testid="stSidebar"] {{
    background: {SIDEBAR_BG};
    border-right: 1px solid {BORDER};
}}

[data-testid="stSidebar"] * {{
    color: {TEXT};
}}

.block-container {{
    max-width: 1750px;
    padding-top: 1.3rem;
    padding-left: 1.2rem;
    padding-right: 1.2rem;
    padding-bottom: 2rem;
}}

h1, h2, h3 {{
    color: {TEXT} !important;
}}

h1 {{
    font-size: 32px !important;
    font-weight: 800 !important;
}}

h2 {{
    font-size: 23px !important;
    font-weight: 750 !important;
}}

h3 {{
    font-size: 18px !important;
    font-weight: 700 !important;
}}

p {{
    color: {MUTED};
}}

div[data-testid="stMetric"] {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 13px;
    min-height: 90px;
}}

div[data-testid="stMetricLabel"] {{
    color: #9ca8ba !important;
    font-size: 12px !important;
}}

div[data-testid="stMetricValue"] {{
    color: white !important;
    font-size: 28px !important;
    font-weight: 700 !important;
}}

div[data-testid="stExpander"] {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}

.stButton button {{
    background: #202733;
    color: white;
    border: 1px solid #394454;
    border-radius: 6px;
}}

.stButton button:hover {{
    border-color: {CYAN};
    color: white;
}}

.stSelectbox label,
.stFileUploader label {{
    color: #b8c2d1 !important;
}}

hr {{
    border-color: {BORDER};
}}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():
        return {}

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception:

        return {}


evidence = load_json(EVIDENCE_FILE)
schema = load_json(SCHEMA_FILE)
alerts_data = load_json(ALERT_FILE)
mitre_data = load_json(MITRE_FILE)


# ============================================================
# DATASET
# ============================================================

def get_latest_dataset():

    if not PROCESSED_DIR.exists():
        return None

    files = sorted(
        PROCESSED_DIR.glob("*.csv"),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )

    if not files:
        return None

    return files[0]


dataset = get_latest_dataset()

dataset_name = (
    dataset.name
    if dataset
    else "No processed dataset"
)


dataset_type = schema.get(
    "dataset_type",
    "unknown"
)

dataset_mode = evidence.get(
    "dataset_mode",
    "UNKNOWN"
)


# ============================================================
# TOTAL EVENTS
# ============================================================

def get_total_events():

    keys = [
        "total_records",
        "records_analyzed",
        "record_count",
        "records"
    ]

    for key in keys:

        value = evidence.get(key)

        if value is not None:

            try:
                return int(float(value))
            except Exception:
                pass

    dataset_section = evidence.get(
        "dataset",
        {}
    )

    if isinstance(
        dataset_section,
        dict
    ):

        value = dataset_section.get(
            "records"
        )

        if value is not None:

            try:
                return int(
                    float(value)
                )
            except Exception:
                pass

    if dataset:

        try:

            total = 0

            for chunk in pd.read_csv(
                dataset,
                chunksize=100000
            ):

                total += len(chunk)

            return total

        except Exception:

            return 0

    return 0


total_events = get_total_events()


# ============================================================
# FINDINGS
# ============================================================

def get_findings():

    data = evidence.get(
        "behavioural_indicators",
        []
    )

    if isinstance(
        data,
        dict
    ):

        data = list(
            data.values()
        )

    if not isinstance(
        data,
        list
    ):

        return []

    results = []

    for item in data:

        if not isinstance(
            item,
            dict
        ):
            continue

        finding = item.get(
            "finding",
            item
        )

        if isinstance(
            finding,
            dict
        ):

            results.append(
                finding
            )

    return results


findings = get_findings()


# ============================================================
# FINDING NAME
# ============================================================

def get_finding_name(
    finding
):

    return finding.get(
        "label",
        finding.get(
            "finding",
            "Unknown"
        )
    )


# ============================================================
# ALERTS
# ============================================================

def get_alerts():

    data = alerts_data.get(
        "alerts",
        []
    )

    if isinstance(
        data,
        list
    ):

        return data

    return []


alerts = get_alerts()


# ============================================================
# SEVERITY COUNTS
# ============================================================

severity_counts = {
    "Critical": 0,
    "High": 0,
    "Medium": 0,
    "Low": 0,
    "Informational": 0
}

for alert in alerts:

    severity = alert.get(
        "severity",
        "Informational"
    )

    if severity in severity_counts:

        severity_counts[
            severity
        ] += 1


active_alerts = sum(
    severity_counts[x]
    for x in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]
)


# ============================================================
# MITRE EXTRACTION
# ============================================================

def extract_mitre(
    obj,
    results
):

    if isinstance(
        obj,
        dict
    ):

        if (
            "technique_id" in obj
            and (
                "status" in obj
                or "assessment" in obj
            )
        ):

            technique_id = str(
                obj.get(
                    "technique_id",
                    "-"
                )
            )

            technique_name = str(
                obj.get(
                    "technique_name",
                    obj.get(
                        "name",
                        "-"
                    )
                )
            )

            finding = str(
                obj.get(
                    "finding",
                    obj.get(
                        "finding_label",
                        obj.get(
                            "label",
                            "-"
                        )
                    )
                )
            )

            status = str(
                obj.get(
                    "status",
                    obj.get(
                        "assessment",
                        ""
                    )
                )
            ).upper()

            if "NOT_SUPPORTED" in status:

                status = "NOT_SUPPORTED"

            elif "POSSIBLE" in status:

                status = "POSSIBLE"

            elif "SUPPORTED" in status:

                status = "SUPPORTED"

            else:

                status = "UNKNOWN"

            results.append(
                {
                    "finding": finding,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "status": status
                }
            )

        for value in obj.values():

            extract_mitre(
                value,
                results
            )

    elif isinstance(
        obj,
        list
    ):

        for item in obj:

            extract_mitre(
                item,
                results
            )


mitre_assessments = []

extract_mitre(
    mitre_data,
    mitre_assessments
)


# ============================================================
# DEDUPLICATE MITRE
# ============================================================

unique_mitre = {}

for item in mitre_assessments:

    key = (
        item["finding"],
        item["technique_id"],
        item["status"]
    )

    unique_mitre[
        key
    ] = item


mitre_assessments = list(
    unique_mitre.values()
)


mitre_supported = sum(
    1
    for item in mitre_assessments
    if item["status"]
    == "SUPPORTED"
)

mitre_possible = sum(
    1
    for item in mitre_assessments
    if item["status"]
    == "POSSIBLE"
)

mitre_not_supported = sum(
    1
    for item in mitre_assessments
    if item["status"]
    == "NOT_SUPPORTED"
)


# ============================================================
# MITRE CANDIDATE GROUPS
# ============================================================

candidate_groups = 0

if isinstance(
    mitre_data,
    dict
):

    candidate_groups = mitre_data.get(
        "candidate_groups",
        0
    )

    if not candidate_groups:

        candidate_groups = len(
            [
                f
                for f in findings
                if str(
                    f.get(
                        "classification",
                        ""
                    )
                ).lower()
                == "attack"
            ]
        )


# ============================================================
# PORT ANALYSIS
# ============================================================

def get_port_data():

    counter = Counter()

    def walk(obj):

        if isinstance(
            obj,
            dict
        ):

            for key, value in obj.items():

                key_lower = str(
                    key
                ).lower()

                if (
                    "associated_destination_ports"
                    in key_lower
                ):

                    if isinstance(
                        value,
                        dict
                    ):

                        for port, count in value.items():

                            try:

                                counter[
                                    str(port)
                                ] += int(
                                    float(
                                        count
                                    )
                                )

                            except Exception:

                                pass

                walk(value)

        elif isinstance(
            obj,
            list
        ):

            for item in obj:

                walk(item)

    walk(evidence)

    return counter.most_common(8)


# ============================================================
# TIMELINE
# ============================================================

def get_timeline():

    rows = []

    for finding in findings:

        temporal = finding.get(
            "temporal_evidence",
            {}
        )

        if not isinstance(
            temporal,
            dict
        ):

            continue

        name = get_finding_name(
            finding
        )

        earliest = temporal.get(
            "earliest_timestamp"
        )

        latest = temporal.get(
            "latest_timestamp"
        )

        if earliest:

            rows.append(
                {
                    "Finding": name,
                    "Timestamp": earliest
                }
            )

        if latest:

            rows.append(
                {
                    "Finding": name,
                    "Timestamp": latest
                }
            )

    if not rows:

        return pd.DataFrame()

    df = pd.DataFrame(
        rows
    )

    df[
        "Timestamp"
    ] = pd.to_datetime(
        df["Timestamp"],
        errors="coerce"
    )

    return df.dropna(
        subset=["Timestamp"]
    )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "## 🛡️ AI Security Copilot"
    )

    st.caption(
        "See the signal. Catch the threat."
    )

    st.divider()

    st.markdown(
        "### Navigation"
    )

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Alerts",
            "Security Findings",
            "Timeline",
            "MITRE ATT&CK",
            "AI Analyst",
            "Evidence"
        ],
        label_visibility="collapsed"
    )

    st.divider()

    st.markdown(
        "### Dataset"
    )

    st.write(
        f"**{dataset_name}**"
    )

    st.caption(
        f"Mode: {dataset_mode}"
    )

    st.caption(
        f"Type: {dataset_type}"
    )

    st.divider()

    st.markdown(
        "### Upload New Dataset"
    )

    uploaded_file = st.file_uploader(
        "CSV dataset",
        type=["csv"]
    )

    if uploaded_file:

        if st.button(
            "Upload / Save Dataset",
            use_container_width=True
        ):

            RAW_DIR.mkdir(
                parents=True,
                exist_ok=True
            )

            save_path = (
                RAW_DIR /
                uploaded_file.name
            )

            with open(
                save_path,
                "wb"
            ) as file:

                file.write(
                    uploaded_file.getbuffer()
                )

            st.success(
                "Dataset saved."
            )

            st.info(
                "Run the analysis pipeline "
                "from the terminal."
            )

    st.divider()

    st.markdown(
        "### Pipeline"
    )

    for step in [
        "✓ Data Cleaning",
        "✓ Data Validation",
        "✓ Schema Discovery",
        "✓ Behaviour Analysis",
        "✓ MITRE Retrieval",
        "✓ Evidence Validation",
        "✓ AI Report",
        "✓ Risk & Alert Engine"
    ]:

        st.caption(
            step
        )


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    left, right = st.columns(
        [7, 1.5]
    )

    with left:

        st.title(
            "🛡️ AI Security Copilot"
        )

        st.caption(
            "See the signal. Catch the threat. "
            "AI-powered security intelligence."
        )

    with right:

        st.metric(
            "Active Alerts",
            active_alerts
        )

    # --------------------------------------------------------
    # KPI ROW
    # --------------------------------------------------------

    k1, k2, k3, k4, k5 = st.columns(
        5
    )

    with k1:

        st.metric(
            "Events Analysed",
            f"{total_events:,}"
        )

    with k2:

        st.metric(
            "Security Findings",
            len(findings)
        )

    with k3:

        st.metric(
            "Active Alerts",
            active_alerts
        )

    with k4:

        st.metric(
            "MITRE Possible",
            mitre_possible
        )

    with k5:

        st.metric(
            "MITRE Supported",
            mitre_supported
        )

    st.divider()

    # --------------------------------------------------------
    # PIPELINE
    # --------------------------------------------------------

    st.subheader(
        "Analysis Pipeline"
    )

    p1, p2, p3, p4, p5 = st.columns(
        5
    )

    with p1:

        st.info(
            "📡 **Telemetry**\n\n"
            "Security data"
        )

    with p2:

        st.info(
            "🔬 **Behaviour**\n\n"
            "Pattern analysis"
        )

    with p3:

        st.error(
            "🚨 **Alerts**\n\n"
            "Risk triage"
        )

    with p4:

        st.warning(
            "🎯 **MITRE**\n\n"
            "Technique assessment"
        )

    with p5:

        st.success(
            "🧠 **AI Analyst**\n\n"
            "Security assessment"
        )

    st.divider()

    # --------------------------------------------------------
    # FIRST CHART ROW
    # --------------------------------------------------------

    c1, c2, c3 = st.columns(
        [1.15, 1.15, 1]
    )

    # ========================================================
    # EVENTS ACTIVITY
    # ========================================================

    with c1:

        st.subheader(
            "Events Activity"
        )

        timeline = get_timeline()

        if not timeline.empty:

            trend = (
                timeline
                .groupby(
                    pd.Grouper(
                        key="Timestamp",
                        freq="15min"
                    )
                )
                .size()
                .reset_index(
                    name="Events"
                )
            )

            fig = px.line(
                trend,
                x="Timestamp",
                y="Events"
            )

            fig.update_traces(
                line=dict(
                    color=CYAN,
                    width=2
                ),
                marker=dict(
                    color=CYAN,
                    size=6
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=10,
                    t=10,
                    b=10
                ),
                showlegend=False,
                xaxis=dict(
                    showgrid=False
                ),
                yaxis=dict(
                    gridcolor="#29303d"
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.metric(
                "Events Analysed",
                f"{total_events:,}"
            )

    # ========================================================
    # RISK SCORE
    # ========================================================

    with c2:

        st.subheader(
            "Risk Score by Finding"
        )

        if alerts:

            risk_df = pd.DataFrame(
                [
                    {
                        "Finding":
                            alert.get(
                                "finding",
                                "Unknown"
                            ),

                        "Risk Score":
                            int(
                                alert.get(
                                    "risk_score",
                                    0
                                )
                            ),

                        "Severity":
                            alert.get(
                                "severity",
                                "Informational"
                            )
                    }
                    for alert in alerts
                ]
            )

            fig = go.Figure()

            for _, row in risk_df.iterrows():

                severity = row[
                    "Severity"
                ]

                fig.add_trace(
                    go.Bar(
                        x=[
                            row["Finding"]
                        ],
                        y=[
                            row["Risk Score"]
                        ],
                        marker_color=(
                            SEVERITY_COLOURS.get(
                                severity,
                                GREY
                            )
                        ),
                        text=[
                            row["Risk Score"]
                        ],
                        textposition="outside",
                        showlegend=False
                    )
                )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=30,
                    t=10,
                    b=35
                ),
                yaxis=dict(
                    title="Risk Score",
                    range=[0, 100],
                    gridcolor="#29303d"
                ),
                xaxis=dict(
                    showgrid=False
                ),
                bargap=0.45
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.info(
                "No risk scores available."
            )

    # ========================================================
    # ALERT SEVERITY
    # ========================================================

    with c3:

        st.subheader(
            "Alert Severity Distribution"
        )

        severity_df = pd.DataFrame(
            {
                "Severity": [
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Informational"
                ],
                "Count": [
                    severity_counts[
                        "Critical"
                    ],
                    severity_counts[
                        "High"
                    ],
                    severity_counts[
                        "Medium"
                    ],
                    severity_counts[
                        "Low"
                    ],
                    severity_counts[
                        "Informational"
                    ]
                ]
            }
        )

        severity_df = severity_df[
            severity_df["Count"] > 0
        ]

        if not severity_df.empty:

            fig = go.Figure(
                go.Pie(
                    labels=severity_df[
                        "Severity"
                    ],
                    values=severity_df[
                        "Count"
                    ],
                    hole=0.58,
                    textinfo="label+value",
                    textposition="outside",
                    marker=dict(
                        colors=[
                            SEVERITY_COLOURS[
                                value
                            ]
                            for value
                            in severity_df[
                                "Severity"
                            ]
                        ],
                        line=dict(
                            color=BG,
                            width=2
                        )
                    )
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=5,
                    r=5,
                    t=5,
                    b=20
                ),
                legend=dict(
                    orientation="h",
                    y=-0.08,
                    x=0.5,
                    xanchor="center"
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.info(
                "No severity data available."
            )

    st.divider()

    # --------------------------------------------------------
    # SECOND CHART ROW
    # --------------------------------------------------------

    c1, c2, c3 = st.columns(
        [1.15, 1.15, 1]
    )

    # ========================================================
    # FINDINGS SHARE
    # ========================================================

    with c1:

        st.subheader(
            "Findings by Dataset Share"
        )

        rows = []

        for finding in findings:

            rows.append(
                {
                    "Finding":
                        get_finding_name(
                            finding
                        ),

                    "Share":
                        float(
                            finding.get(
                                "percentage_of_dataset",
                                0
                            )
                        )
                }
            )

        if rows:

            df = pd.DataFrame(
                rows
            )

            fig = px.bar(
                df,
                x="Share",
                y="Finding",
                orientation="h",
                text="Share"
            )

            fig.update_traces(
                marker_color=CYAN,
                texttemplate="%{text:.2f}%",
                textposition="outside"
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=45,
                    t=10,
                    b=10
                ),
                xaxis=dict(
                    title="Dataset Share (%)",
                    gridcolor="#29303d"
                ),
                yaxis=dict(
                    title=""
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.info(
                "No findings available."
            )

    # ========================================================
    # MITRE ASSESSMENT
    # ========================================================

    with c2:

        st.subheader(
            "MITRE ATT&CK Assessment"
        )

        mitre_df = pd.DataFrame(
            {
                "Assessment": [
                    "Supported",
                    "Possible",
                    "Not Supported"
                ],
                "Count": [
                    mitre_supported,
                    mitre_possible,
                    mitre_not_supported
                ]
            }
        )

        mitre_df = mitre_df[
            mitre_df["Count"] > 0
        ]

        if not mitre_df.empty:

            fig = go.Figure(
                go.Pie(
                    labels=mitre_df[
                        "Assessment"
                    ],
                    values=mitre_df[
                        "Count"
                    ],
                    hole=0.58,
                    textinfo="label+value"
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=5,
                    r=5,
                    t=5,
                    b=20
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.info(
                "No MITRE assessments."
            )

    # ========================================================
    # TOP PORTS
    # ========================================================

    with c3:

        st.subheader(
            "Top Destination Ports"
        )

        port_data = get_port_data()

        if port_data:

            df = pd.DataFrame(
                port_data,
                columns=[
                    "Port",
                    "Records"
                ]
            )

            df[
                "Port"
            ] = df[
                "Port"
            ].astype(str)

            fig = px.bar(
                df,
                x="Records",
                y="Port",
                orientation="h",
                text="Records"
            )

            fig.update_traces(
                marker_color=BLUE,
                texttemplate="%{text:,}",
                textposition="outside"
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=45,
                    t=10,
                    b=10
                ),
                xaxis=dict(
                    title="Records",
                    gridcolor="#29303d"
                ),
                yaxis=dict(
                    title=""
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        else:

            st.info(
                "No port evidence available."
            )

    st.divider()

    # --------------------------------------------------------
    # ANOMALIES / THREAT INDICATORS
    # --------------------------------------------------------

    c1, c2 = st.columns(
        [1.15, 1]
    )

    with c1:

        st.subheader(
            "⚠️ Anomalies"
        )

        st.caption(
            "Findings requiring analyst attention"
        )

        suspicious = [
            alert
            for alert in alerts
            if alert.get(
                "severity",
                "Informational"
            )
            != "Informational"
        ]

        if suspicious:

            for alert in suspicious:

                finding = alert.get(
                    "finding",
                    "Unknown"
                )

                risk = alert.get(
                    "risk_score",
                    0
                )

                confidence = alert.get(
                    "confidence",
                    "Unknown"
                )

                severity = alert.get(
                    "severity",
                    "Informational"
                )

                a, b, c = st.columns(
                    [4, 1, 1]
                )

                with a:

                    st.write(
                        f"🚨 **{finding}**"
                    )

                    st.caption(
                        f"Confidence: {confidence}"
                    )

                with b:

                    st.metric(
                        "Risk",
                        risk
                    )

                with c:

                    st.write(
                        severity
                    )

                st.divider()

        else:

            st.success(
                "No active anomalies."
            )

    with c2:

        st.subheader(
            "🎯 Threat Indicators"
        )

        st.caption(
            "MITRE techniques requiring attention"
        )

        threat_items = [
            item
            for item in mitre_assessments
            if item["status"]
            in [
                "POSSIBLE",
                "SUPPORTED"
            ]
        ]

        if threat_items:

            seen = set()

            for item in threat_items:

                key = (
                    item["finding"],
                    item["technique_id"]
                )

                if key in seen:
                    continue

                seen.add(key)

                st.write(
                    f"🎯 **{item['technique_id']}**"
                )

                st.caption(
                    f"{item['technique_name']} • "
                    f"{item['finding']}"
                )

                if item["status"] == "SUPPORTED":

                    st.success(
                        "SUPPORTED"
                    )

                else:

                    st.warning(
                        "POSSIBLE"
                    )

        else:

            st.info(
                "No possible MITRE indicators."
            )


# ============================================================
# ALERTS
# ============================================================

elif page == "Alerts":

    st.title(
        "🚨 Risk & Alert Centre"
    )

    st.caption(
        "Security alerts, risk prioritisation and analyst triage."
    )

    # --------------------------------------------------------
    # SEVERITY CARDS
    # --------------------------------------------------------

    c1, c2, c3, c4, c5 = st.columns(
        5
    )

    with c1:

        st.metric(
            "Critical",
            severity_counts["Critical"]
        )

    with c2:

        st.metric(
            "High",
            severity_counts["High"]
        )

    with c3:

        st.metric(
            "Medium",
            severity_counts["Medium"]
        )

    with c4:

        st.metric(
            "Low",
            severity_counts["Low"]
        )

    with c5:

        st.metric(
            "Informational",
            severity_counts["Informational"]
        )

    st.divider()

    # --------------------------------------------------------
    # CHARTS
    # --------------------------------------------------------

    chart1, chart2 = st.columns(
        [1, 1]
    )

    with chart1:

        st.subheader(
            "Alert Severity Distribution"
        )

        severity_df = pd.DataFrame(
            {
                "Severity": [
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Informational"
                ],
                "Count": [
                    severity_counts[
                        "Critical"
                    ],
                    severity_counts[
                        "High"
                    ],
                    severity_counts[
                        "Medium"
                    ],
                    severity_counts[
                        "Low"
                    ],
                    severity_counts[
                        "Informational"
                    ]
                ]
            }
        )

        severity_df = severity_df[
            severity_df["Count"] > 0
        ]

        if not severity_df.empty:

            fig = go.Figure(
                go.Pie(
                    labels=severity_df[
                        "Severity"
                    ],
                    values=severity_df[
                        "Count"
                    ],
                    hole=0.58,
                    textinfo="label+value",
                    textposition="outside",
                    marker=dict(
                        colors=[
                            SEVERITY_COLOURS[
                                value
                            ]
                            for value
                            in severity_df[
                                "Severity"
                            ]
                        ],
                        line=dict(
                            color=BG,
                            width=2
                        )
                    )
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=400,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=20,
                    r=20,
                    t=20,
                    b=25
                ),
                legend=dict(
                    orientation="h",
                    y=-0.08,
                    x=0.5,
                    xanchor="center"
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

    with chart2:

        st.subheader(
            "Risk Score by Finding"
        )

        if alerts:

            fig = go.Figure()

            for alert in alerts:

                finding = alert.get(
                    "finding",
                    "Unknown"
                )

                score = int(
                    alert.get(
                        "risk_score",
                        0
                    )
                )

                severity = alert.get(
                    "severity",
                    "Informational"
                )

                fig.add_trace(
                    go.Bar(
                        x=[finding],
                        y=[score],
                        marker_color=(
                            SEVERITY_COLOURS.get(
                                severity,
                                GREY
                            )
                        ),
                        text=[score],
                        textposition="outside",
                        showlegend=False
                    )
                )

            fig.update_layout(
                template="plotly_dark",
                height=400,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=20,
                    r=25,
                    t=20,
                    b=45
                ),
                yaxis=dict(
                    title="Risk Score",
                    range=[0, 100],
                    gridcolor="#29303d"
                ),
                xaxis=dict(
                    title="",
                    showgrid=False
                ),
                bargap=0.45
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

    st.divider()

    # --------------------------------------------------------
    # ALERT TABLE
    # --------------------------------------------------------

    st.subheader(
        "Security Alerts"
    )

    if alerts:

        rows = []

        for alert in alerts:

            rows.append(
                {
                    "Alert":
                        alert.get(
                            "alert_id",
                            "-"
                        ),

                    "Finding":
                        alert.get(
                            "finding",
                            "-"
                        ),

                    "Severity":
                        alert.get(
                            "severity",
                            "-"
                        ),

                    "Risk Score":
                        int(
                            alert.get(
                                "risk_score",
                                0
                            )
                        ),

                    "Confidence":
                        alert.get(
                            "confidence",
                            "-"
                        ),

                    "Status":
                        alert.get(
                            "status",
                            "-"
                        )
                }
            )

        alert_df = pd.DataFrame(
            rows
        )

        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score":
                    st.column_config.ProgressColumn(
                        "Risk Score",
                        min_value=0,
                        max_value=100
                    )
            }
        )

        st.divider()

        st.subheader(
            "Alert Details"
        )

        options = [
            f"{alert.get('alert_id')} — "
            f"{alert.get('finding')}"
            for alert in alerts
        ]

        selected = st.selectbox(
            "Select alert",
            options
        )

        selected_index = options.index(
            selected
        )

        alert = alerts[
            selected_index
        ]

        d1, d2, d3, d4 = st.columns(
            4
        )

        with d1:

            st.metric(
                "Risk Score",
                alert.get(
                    "risk_score",
                    0
                )
            )

        with d2:

            st.metric(
                "Severity",
                alert.get(
                    "severity",
                    "-"
                )
            )

        with d3:

            st.metric(
                "Confidence",
                alert.get(
                    "confidence",
                    "-"
                )
            )

        with d4:

            st.metric(
                "Status",
                alert.get(
                    "status",
                    "-"
                )
            )

        st.divider()

        e1, e2 = st.columns(
            2
        )

        with e1:

            st.subheader(
                "🔎 Evidence"
            )

            items = alert.get(
                "evidence",
                []
            )

            if items:

                for item in items:

                    st.write(
                        f"• {item}"
                    )

            else:

                st.caption(
                    "No evidence available."
                )

        with e2:

            st.subheader(
                "⚠️ Evidence Gaps"
            )

            gaps = alert.get(
                "evidence_gaps",
                []
            )

            if gaps:

                for gap in gaps:

                    st.write(
                        f"• {gap}"
                    )

            else:

                st.caption(
                    "No evidence gaps recorded."
                )

        st.divider()

        i1, i2 = st.columns(
            2
        )

        with i1:

            st.subheader(
                "🔬 Investigation Steps"
            )

            steps = alert.get(
                "investigation_steps",
                []
            )

            if steps:

                for number, step in enumerate(
                    steps,
                    start=1
                ):

                    st.write(
                        f"{number}. {step}"
                    )

            else:

                st.caption(
                    "No investigation steps available."
                )

        with i2:

            st.subheader(
                "🛡️ Defensive Actions"
            )

            actions = alert.get(
                "defensive_actions",
                []
            )

            if actions:

                for action in actions:

                    st.write(
                        f"• {action}"
                    )

            else:

                st.caption(
                    "No defensive actions available."
                )

    else:

        st.info(
            "No security alerts found."
        )


# ============================================================
# SECURITY FINDINGS
# ============================================================

elif page == "Security Findings":

    st.title(
        "🔎 Security Findings"
    )

    st.caption(
        "Behavioural findings identified from the analysed security telemetry."
    )

    if findings:

        total_findings = len(
            findings
        )

        attack_findings = sum(
            1
            for finding in findings
            if str(
                finding.get(
                    "classification",
                    ""
                )
            ).lower()
            == "attack"
        )

        baseline_findings = sum(
            1
            for finding in findings
            if str(
                finding.get(
                    "classification",
                    ""
                )
            ).lower()
            == "benign"
        )

        classified_records = sum(
            int(
                finding.get(
                    "record_count",
                    0
                )
            )
            for finding in findings
        )

        c1, c2, c3, c4 = st.columns(
            4
        )

        with c1:

            st.metric(
                "Findings",
                total_findings
            )

        with c2:

            st.metric(
                "Attack Findings",
                attack_findings
            )

        with c3:

            st.metric(
                "Baseline Findings",
                baseline_findings
            )

        with c4:

            st.metric(
                "Records Classified",
                f"{classified_records:,}"
            )

        st.divider()

        # ----------------------------------------------------
        # FINDING CHARTS
        # ----------------------------------------------------

        chart1, chart2 = st.columns(
            [1, 1]
        )

        finding_rows = []

        for finding in findings:

            finding_rows.append(
                {
                    "Finding":
                        get_finding_name(
                            finding
                        ),

                    "Records":
                        int(
                            finding.get(
                                "record_count",
                                0
                            )
                        ),

                    "Share":
                        float(
                            finding.get(
                                "percentage_of_dataset",
                                0
                            )
                        )
                }
            )

        finding_df = pd.DataFrame(
            finding_rows
        )

        with chart1:

            st.subheader(
                "Findings Distribution"
            )

            fig = go.Figure(
                go.Pie(
                    labels=finding_df[
                        "Finding"
                    ],
                    values=finding_df[
                        "Records"
                    ],
                    hole=0.55,
                    textinfo="label+percent",
                    marker=dict(
                        line=dict(
                            color=BG,
                            width=2
                        )
                    )
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=370,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        with chart2:

            st.subheader(
                "Records by Finding"
            )

            fig = px.bar(
                finding_df,
                x="Records",
                y="Finding",
                orientation="h",
                text="Records"
            )

            fig.update_traces(
                marker_color=CYAN,
                texttemplate="%{text:,}",
                textposition="outside"
            )

            fig.update_layout(
                template="plotly_dark",
                height=370,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=50,
                    t=10,
                    b=20
                ),
                xaxis=dict(
                    title="Records",
                    gridcolor="#29303d"
                ),
                yaxis=dict(
                    title=""
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        st.divider()

        # ----------------------------------------------------
        # OVERVIEW TABLE
        # ----------------------------------------------------

        st.subheader(
            "Finding Overview"
        )

        table_rows = []

        for finding in findings:

            classification = str(
                finding.get(
                    "classification",
                    "unknown"
                )
            ).lower()

            if classification == "benign":

                display_classification = (
                    "🟢 Baseline"
                )

            elif classification == "attack":

                display_classification = (
                    "🚨 Attack"
                )

            else:

                display_classification = (
                    "⚠️ Unknown"
                )

            table_rows.append(
                {
                    "Finding":
                        get_finding_name(
                            finding
                        ),

                    "Classification":
                        display_classification,

                    "Records":
                        int(
                            finding.get(
                                "record_count",
                                0
                            )
                        ),

                    "Dataset Share":
                        float(
                            finding.get(
                                "percentage_of_dataset",
                                0
                            )
                        )
                }
            )

        overview_df = pd.DataFrame(
            table_rows
        )

        st.dataframe(
            overview_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Records":
                    st.column_config.NumberColumn(
                        "Records",
                        format="%d"
                    ),

                "Dataset Share":
                    st.column_config.NumberColumn(
                        "Dataset Share",
                        format="%.2f%%"
                    )
            }
        )

        st.divider()

        # ----------------------------------------------------
        # BEHAVIOURAL FINDINGS
        # ----------------------------------------------------

        st.subheader(
            "Behavioural Findings"
        )

        for finding in findings:

            label = get_finding_name(
                finding
            )

            classification = str(
                finding.get(
                    "classification",
                    "unknown"
                )
            ).lower()

            if classification == "benign":

                icon = "🟢"

            elif classification == "attack":

                icon = "🚨"

            else:

                icon = "⚠️"

            records = int(
                finding.get(
                    "record_count",
                    0
                )
            )

            share = float(
                finding.get(
                    "percentage_of_dataset",
                    0
                )
            )

            with st.expander(
                f"{icon} {label}  •  "
                f"{records:,} records  •  "
                f"{share:.2f}%"
            ):

                a1, a2, a3 = st.columns(
                    3
                )

                with a1:

                    st.metric(
                        "Records",
                        f"{records:,}"
                    )

                with a2:

                    st.metric(
                        "Dataset Share",
                        f"{share:.2f}%"
                    )

                with a3:

                    st.metric(
                        "Classification",
                        classification.title()
                    )

                st.divider()

                # --------------------------------------------
                # PORTS
                # --------------------------------------------

                ports = finding.get(
                    "associated_destination_ports",
                    {}
                )

                if ports:

                    st.markdown(
                        "#### 🌐 Destination Ports"
                    )

                    port_rows = []

                    for port, count in sorted(
                        ports.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]:

                        try:

                            count = int(
                                float(count)
                            )

                        except Exception:

                            continue

                        port_rows.append(
                            {
                                "Port":
                                    str(port),

                                "Records":
                                    count
                            }
                        )

                    if port_rows:

                        st.dataframe(
                            pd.DataFrame(
                                port_rows
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                # --------------------------------------------
                # PROTOCOLS
                # --------------------------------------------

                protocols = finding.get(
                    "associated_protocols",
                    {}
                )

                if protocols:

                    st.markdown(
                        "#### 📡 Protocols"
                    )

                    protocol_rows = []

                    for protocol, count in sorted(
                        protocols.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]:

                        try:

                            count = int(
                                float(count)
                            )

                        except Exception:

                            continue

                        protocol_rows.append(
                            {
                                "Protocol":
                                    str(protocol),

                                "Records":
                                    count
                            }
                        )

                    if protocol_rows:

                        st.dataframe(
                            pd.DataFrame(
                                protocol_rows
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                # --------------------------------------------
                # STATISTICS
                # --------------------------------------------

                statistics = finding.get(
                    "behavioural_statistics",
                    {}
                )

                if statistics:

                    st.markdown(
                        "#### 📊 Behavioural Statistics"
                    )

                    statistic_rows = []

                    for name, value in statistics.items():

                        if isinstance(
                            value,
                            dict
                        ):

                            for sub_name, sub_value in value.items():

                                statistic_rows.append(
                                    {
                                        "Metric":
                                            f"{name} • {sub_name}",

                                        "Value":
                                            str(
                                                sub_value
                                            )
                                    }
                                )

                        else:

                            statistic_rows.append(
                                {
                                    "Metric":
                                        str(name),

                                    "Value":
                                        str(value)
                                }
                            )

                    if statistic_rows:

                        st.dataframe(
                            pd.DataFrame(
                                statistic_rows
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                # --------------------------------------------
                # TEMPORAL
                # --------------------------------------------

                temporal = finding.get(
                    "temporal_evidence",
                    {}
                )

                if temporal:

                    st.markdown(
                        "#### 🕒 Temporal Evidence"
                    )

                    t1, t2, t3 = st.columns(
                        3
                    )

                    with t1:

                        st.write(
                            "**First observed**"
                        )

                        st.caption(
                            str(
                                temporal.get(
                                    "earliest_timestamp",
                                    "Not available"
                                )
                            )
                        )

                    with t2:

                        st.write(
                            "**Last observed**"
                        )

                        st.caption(
                            str(
                                temporal.get(
                                    "latest_timestamp",
                                    "Not available"
                                )
                            )
                        )

                    with t3:

                        st.write(
                            "**Peak activity**"
                        )

                        st.caption(
                            str(
                                temporal.get(
                                    "peak_hour",
                                    temporal.get(
                                        "peak_period",
                                        "Not available"
                                    )
                                )
                            )
                        )

                # --------------------------------------------
                # COMPARATIVE
                # --------------------------------------------

                comparative = finding.get(
                    "comparative_behavioural_evidence",
                    {}
                )

                if comparative:

                    st.markdown(
                        "#### 🔬 Comparative Behaviour"
                    )

                    if isinstance(
                        comparative,
                        dict
                    ):

                        for key, value in comparative.items():

                            if isinstance(
                                value,
                                dict
                            ):

                                st.write(
                                    f"**{key}**"
                                )

                                for sub_key, sub_value in value.items():

                                    st.caption(
                                        f"{sub_key}: "
                                        f"{sub_value}"
                                    )

                            else:

                                st.write(
                                    f"**{key}:** {value}"
                                )

                    elif isinstance(
                        comparative,
                        list
                    ):

                        for item in comparative:

                            st.write(
                                f"• {item}"
                            )

                    else:

                        st.write(
                            str(comparative)
                        )

                # --------------------------------------------
                # LIMITATIONS
                # --------------------------------------------

                limitations = finding.get(
                    "evidence_limitations",
                    []
                )

                if limitations:

                    st.markdown(
                        "#### ⚠️ Evidence Limitations"
                    )

                    for limitation in limitations:

                        st.write(
                            f"• {limitation}"
                        )

    else:

        st.info(
            "No security findings available."
        )


# ============================================================
# TIMELINE
# ============================================================

elif page == "Timeline":

    st.title(
        "🕒 Security Timeline"
    )

    st.caption(
        "Temporal view of observed security activity."
    )

    timeline = get_timeline()

    if not timeline.empty:

        counts = (
            timeline
            .groupby(
                [
                    pd.Grouper(
                        key="Timestamp",
                        freq="15min"
                    ),
                    "Finding"
                ]
            )
            .size()
            .reset_index(
                name="Events"
            )
        )

        fig = px.line(
            counts,
            x="Timestamp",
            y="Events",
            color="Finding",
            markers=True
        )

        fig.update_layout(
            template="plotly_dark",
            height=500,
            paper_bgcolor=BG,
            plot_bgcolor=BG,
            margin=dict(
                l=10,
                r=10,
                t=20,
                b=20
            )
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )

        st.divider()

        st.subheader(
            "Timeline Evidence"
        )

        st.dataframe(
            timeline,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No timeline data available."
        )


# ============================================================
# MITRE ATT&CK
# ============================================================

elif page == "MITRE ATT&CK":

    st.title(
        "🎯 MITRE ATT&CK Assessment"
    )

    st.caption(
        "Evidence-based validation of retrieved ATT&CK techniques."
    )

    c1, c2, c3 = st.columns(
        3
    )

    with c1:

        st.metric(
            "Supported",
            mitre_supported
        )

    with c2:

        st.metric(
            "Possible",
            mitre_possible
        )

    with c3:

        st.metric(
            "Not Supported",
            mitre_not_supported
        )

    st.divider()

    # --------------------------------------------------------
    # MITRE VISUAL
    # --------------------------------------------------------

    mitre_df = pd.DataFrame(
        {
            "Assessment": [
                "Supported",
                "Possible",
                "Not Supported"
            ],
            "Count": [
                mitre_supported,
                mitre_possible,
                mitre_not_supported
            ]
        }
    )

    mitre_df = mitre_df[
        mitre_df["Count"] > 0
    ]

    if not mitre_df.empty:

        fig = go.Figure(
            go.Pie(
                labels=mitre_df[
                    "Assessment"
                ],
                values=mitre_df[
                    "Count"
                ],
                hole=0.58,
                textinfo="label+value"
            )
        )

        fig.update_layout(
            template="plotly_dark",
            height=380,
            paper_bgcolor=PANEL,
            plot_bgcolor=PANEL
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )

    st.divider()

    # --------------------------------------------------------
    # SUPPORTED
    # --------------------------------------------------------

    supported = [
        item
        for item in mitre_assessments
        if item["status"]
        == "SUPPORTED"
    ]

    if supported:

        st.subheader(
            "Supported Techniques"
        )

        for item in supported:

            st.success(
                f"{item['technique_id']} — "
                f"{item['technique_name']} • "
                f"{item['finding']}"
            )

    # --------------------------------------------------------
    # POSSIBLE
    # --------------------------------------------------------

    possible = [
        item
        for item in mitre_assessments
        if item["status"]
        == "POSSIBLE"
    ]

    if possible:

        st.subheader(
            "Possible Techniques"
        )

        for item in possible:

            st.warning(
                f"{item['technique_id']} — "
                f"{item['technique_name']} • "
                f"{item['finding']}"
            )

    if not supported and not possible:

        st.info(
            "No supported or possible MITRE techniques."
        )


# ============================================================
# AI ANALYST
# ============================================================

elif page == "AI Analyst":

    st.title(
        "🧠 AI Security Analyst"
    )

    st.caption(
        "AI-generated security assessment based on "
        "the analysed evidence and validated findings."
    )

    if REPORT_FILE.exists():

        report = REPORT_FILE.read_text(
            encoding="utf-8"
        )

        st.text_area(
            "AI Security Assessment",
            report,
            height=750
        )

    else:

        st.warning(
            "AI security report has not been generated yet."
        )


# ============================================================
# EVIDENCE CENTRE
# ============================================================

elif page == "Evidence":

    st.title(
        "📚 Evidence Centre"
    )

    st.caption(
        "Technical evidence and validation context generated by the security pipeline."
    )

    # ========================================================
    # DATASET EVIDENCE
    # ========================================================

    st.subheader(
        "Dataset Evidence"
    )

    d1, d2, d3, d4 = st.columns(
        4
    )

    with d1:

        st.metric(
            "Dataset",
            dataset_name
        )

    with d2:

        st.metric(
            "Events",
            f"{total_events:,}"
        )

    with d3:

        st.metric(
            "Mode",
            dataset_mode
        )

    with d4:

        st.metric(
            "Dataset Type",
            dataset_type
        )

    st.divider()

    # ========================================================
    # MITRE VALIDATION SUMMARY
    # ========================================================

    st.subheader(
        "MITRE Validation"
    )

    m1, m2, m3, m4 = st.columns(
        4
    )

    with m1:

        st.metric(
            "Candidate Groups",
            candidate_groups
        )

    with m2:

        st.metric(
            "Candidates Evaluated",
            len(
                mitre_assessments
            )
        )

    with m3:

        st.metric(
            "Supported",
            mitre_supported
        )

    with m4:

        st.metric(
            "Possible",
            mitre_possible
        )

    st.divider()

    # ========================================================
    # VALIDATION STATUS
    # ========================================================

    st.subheader(
        "Validation Status"
    )

    v1, v2, v3 = st.columns(
        3
    )

    with v1:

        st.metric(
            "Supported",
            mitre_supported
        )

        st.caption(
            "Evidence supports the technique."
        )

    with v2:

        st.metric(
            "Possible",
            mitre_possible
        )

        st.caption(
            "Evidence is consistent with the technique, "
            "but does not confirm it."
        )

    with v3:

        st.metric(
            "Not Supported",
            mitre_not_supported
        )

        st.caption(
            "Available evidence does not support the candidate."
        )

    st.divider()

    # ========================================================
    # VALIDATION MODEL
    # ========================================================

    st.subheader(
        "AI Validation Model"
    )

    validation_model = "GPT-5.6"

    if isinstance(
        mitre_data,
        dict
    ):

        validation_model = mitre_data.get(
            "validation_model",
            validation_model
        )

    st.info(
        f"🧠 Validation model: **{validation_model}**"
    )

    # ========================================================
    # VALIDATION PRINCIPLES
    # ========================================================

    st.subheader(
        "Validation Principles"
    )

    principles = []

    if isinstance(
        mitre_data,
        dict
    ):

        principles = mitre_data.get(
            "validation_methodology",
            []
        )

    if not principles:

        principles = [
            "MITRE candidates are treated as hypotheses rather than confirmed mappings.",
            "Semantic similarity is not treated as proof.",
            "Dataset labels are not treated as proof of ATT&CK techniques.",
            "Security telemetry is evaluated against candidates independently.",
            "Observed evidence is distinguished from inferred behaviour.",
            "Missing telemetry is explicitly identified.",
            "The validator may reject all candidates.",
            "Network-flow telemetry is not assumed to contain application-layer authentication evidence.",
            "Final ATT&CK assessments are based on available evidence rather than forced mappings."
        ]

    for principle in principles:

        st.success(
            f"✓ {principle}"
        )

    st.divider()

    # ========================================================
    # MITRE ASSESSMENT VISUAL
    # ========================================================

    st.subheader(
        "MITRE Assessment Overview"
    )

    mitre_visual_df = pd.DataFrame(
        {
            "Assessment": [
                "Supported",
                "Possible",
                "Not Supported"
            ],
            "Count": [
                mitre_supported,
                mitre_possible,
                mitre_not_supported
            ]
        }
    )

    mitre_visual_df = mitre_visual_df[
        mitre_visual_df["Count"] > 0
    ]

    if not mitre_visual_df.empty:

        chart1, chart2 = st.columns(
            [1, 1]
        )

        with chart1:

            fig = go.Figure(
                go.Pie(
                    labels=mitre_visual_df[
                        "Assessment"
                    ],
                    values=mitre_visual_df[
                        "Count"
                    ],
                    hole=0.60,
                    textinfo="label+value"
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=350,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=10,
                    t=10,
                    b=10
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

        with chart2:

            fig = px.bar(
                mitre_visual_df,
                x="Assessment",
                y="Count",
                text="Count"
            )

            fig.update_traces(
                marker_color=CYAN,
                textposition="outside"
            )

            fig.update_layout(
                template="plotly_dark",
                height=350,
                paper_bgcolor=PANEL,
                plot_bgcolor=PANEL,
                margin=dict(
                    l=10,
                    r=10,
                    t=10,
                    b=10
                ),
                yaxis=dict(
                    title="Assessments",
                    gridcolor="#29303d"
                ),
                xaxis=dict(
                    title=""
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                }
            )

    st.divider()

    # ========================================================
    # FINDING-BY-FINDING ASSESSMENT
    # ========================================================

    st.subheader(
        "Finding-by-Finding Assessment"
    )

    if findings:

        finding_names = [
            get_finding_name(
                finding
            )
            for finding in findings
        ]

        for finding_name in finding_names:

            finding_mitre = [
                item
                for item in mitre_assessments
                if item["finding"].strip().lower()
                == finding_name.strip().lower()
            ]

            related_alert = next(
                (
                    alert
                    for alert in alerts
                    if str(
                        alert.get(
                            "finding",
                            ""
                        )
                    ).strip().lower()
                    == finding_name.strip().lower()
                ),
                None
            )

            with st.expander(
                f"🎯 {finding_name}"
            ):

                if related_alert:

                    a1, a2, a3 = st.columns(
                        3
                    )

                    with a1:

                        st.metric(
                            "Risk Score",
                            related_alert.get(
                                "risk_score",
                                0
                            )
                        )

                    with a2:

                        st.metric(
                            "Severity",
                            related_alert.get(
                                "severity",
                                "-"
                            )
                        )

                    with a3:

                        st.metric(
                            "Confidence",
                            related_alert.get(
                                "confidence",
                                "-"
                            )
                        )

                    st.divider()

                supported_items = [
                    item
                    for item in finding_mitre
                    if item["status"]
                    == "SUPPORTED"
                ]

                possible_items = [
                    item
                    for item in finding_mitre
                    if item["status"]
                    == "POSSIBLE"
                ]

                rejected_items = [
                    item
                    for item in finding_mitre
                    if item["status"]
                    == "NOT_SUPPORTED"
                ]

                r1, r2, r3 = st.columns(
                    3
                )

                with r1:

                    st.metric(
                        "Supported",
                        len(
                            supported_items
                        )
                    )

                with r2:

                    st.metric(
                        "Possible",
                        len(
                            possible_items
                        )
                    )

                with r3:

                    st.metric(
                        "Not Supported",
                        len(
                            rejected_items
                        )
                    )

                if supported_items:

                    st.markdown(
                        "##### 🟢 Supported"
                    )

                    for item in supported_items:

                        st.success(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                if possible_items:

                    st.markdown(
                        "##### 🟡 Possible"
                    )

                    for item in possible_items:

                        st.warning(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                if rejected_items:

                    st.markdown(
                        "##### ⚪ Not Supported"
                    )

                    for item in rejected_items[:10]:

                        st.caption(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                    if len(
                        rejected_items
                    ) > 10:

                        st.caption(
                            f"+ {len(rejected_items) - 10} "
                            "additional candidates not supported."
                        )

                if not finding_mitre:

                    st.info(
                        "No MITRE assessments are associated "
                        "with this finding."
                    )

    else:

        st.info(
            "No findings available for MITRE assessment."
        )

    st.divider()

    # ========================================================
    # EVIDENCE GAPS
    # ========================================================

    st.subheader(
        "⚠️ Evidence Gaps"
    )

    evidence_gaps = []

    for alert in alerts:

        gaps = alert.get(
            "evidence_gaps",
            []
        )

        if isinstance(
            gaps,
            list
        ):

            for gap in gaps:

                evidence_gaps.append(
                    {
                        "Finding":
                            alert.get(
                                "finding",
                                "Unknown"
                            ),

                        "Gap":
                            gap
                    }
                )

    if evidence_gaps:

        gaps_df = pd.DataFrame(
            evidence_gaps
        )

        st.dataframe(
            gaps_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No evidence gaps were recorded."
        )

    st.divider()

    # ========================================================
    # TECHNICAL DATASET CAPABILITIES
    # ========================================================

    st.subheader(
        "Telemetry Capabilities"
    )

    capabilities = schema.get(
        "capabilities",
        {}
    )

    if capabilities:

        capability_rows = []

        for capability, available in capabilities.items():

            capability_rows.append(
                {
                    "Capability":
                        str(
                            capability
                        ).replace(
                            "_",
                            " "
                        ).title(),

                    "Available":
                        "✓ Yes"
                        if available
                        else "✗ No"
                }
            )

        capability_df = pd.DataFrame(
            capability_rows
        )

        st.dataframe(
            capability_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "Telemetry capability information is unavailable."
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ AI Security Copilot  •  "
    "Behavioural Analytics  •  "
    "MITRE ATT&CK  •  "
    "Evidence-Based Triage"
)