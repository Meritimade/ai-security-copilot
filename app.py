from pathlib import Path
from collections import Counter
import json
import os
import subprocess
import sys

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

from multi_format_analyser import (
    SUPPORTED_EXTENSIONS,
    classify_file,
    safe_filename,
    convert_structured_to_csv,
    analyse_uploaded_file,
)
from report_export import build_filtered_package, EXPORTERS


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
MITRE_CANDIDATES_FILE = BASE_DIR / "MITRE" / "mitre_candidates.json"
REPORT_FILE = BASE_DIR / "ai_security_report.txt"
UPLOAD_DIR = BASE_DIR / "Uploads"
DOCUMENT_ANALYSIS_FILE = BASE_DIR / "document_analysis.json"
ANALYSIS_HISTORY_FILE = BASE_DIR / "analysis_history.json"
ANALYSIS_STATUS_FILE = BASE_DIR / "analysis_status.json"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Security Copilot",
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
# JSON LOADER
# ============================================================

def load_json(path):

    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return {}


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False, default=str)


def load_analysis_history():
    if not ANALYSIS_HISTORY_FILE.exists():
        return []
    data = load_json(ANALYSIS_HISTORY_FILE)
    return data if isinstance(data, list) else []


def update_analysis_status(
    status,
    run_id=None,
    current_step=None,
    step_number=0,
    total_steps=8,
    dataset_name=None,
    message=None,
    started_at=None,
    completed_at=None,
    duration_seconds=None,
):
    save_json(
        ANALYSIS_STATUS_FILE,
        {
            "run_id": run_id,
            "status": status,
            "current_step": current_step,
            "step_number": step_number,
            "total_steps": total_steps,
            "dataset_name": dataset_name,
            "message": message,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": duration_seconds,
            "updated_at": pd.Timestamp.now().isoformat(),
        },
    )


def record_completed_analysis(
    dataset_name,
    started_at=None,
    completed_at=None,
    duration_seconds=None,
):
    history = load_analysis_history()
    output_evidence = load_json(EVIDENCE_FILE)
    output_schema = load_json(SCHEMA_FILE)
    output_alerts = load_json(ALERT_FILE)

    events = 0
    for key in ["total_records", "records_analyzed", "record_count", "records"]:
        value = output_evidence.get(key)
        if value is not None:
            try:
                events = int(float(value))
                break
            except Exception:
                pass

    if not events:
        section = output_evidence.get("dataset", {})
        if isinstance(section, dict):
            try:
                events = int(float(section.get("records", 0)))
            except Exception:
                pass

    behavioural = output_evidence.get("behavioural_indicators", [])
    if isinstance(behavioural, dict):
        behavioural = list(behavioural.values())
    findings_count = len(behavioural) if isinstance(behavioural, list) else 0

    alert_list = output_alerts.get("alerts", [])
    alerts_count = len(alert_list) if isinstance(alert_list, list) else 0

    history.append(
        {
            "analysis_number": len(history) + 1,
            "timestamp": completed_at or pd.Timestamp.now().isoformat(),
            "started_at": started_at,
            "completed_at": completed_at or pd.Timestamp.now().isoformat(),
            "duration_seconds": duration_seconds,
            "analysis_type": "structured_security_telemetry",
            "dataset_name": dataset_name or "Unknown dataset",
            "events": events,
            "findings": findings_count,
            "alerts": alerts_count,
            "mode": output_evidence.get("dataset_mode", "UNKNOWN"),
            "dataset_type": output_schema.get("dataset_type", "unknown"),
        }
    )

    save_json(ANALYSIS_HISTORY_FILE, history)


def bootstrap_analysis_history():
    """
    Register the current analysis once if the history file does not yet exist.
    This makes analyses completed before the history feature visible.
    """
    if ANALYSIS_HISTORY_FILE.exists():
        return

    if not (
        EVIDENCE_FILE.exists()
        or ALERT_FILE.exists()
        or SCHEMA_FILE.exists()
    ):
        return

    current_dataset = get_latest_dataset()
    current_dataset_name = (
        current_dataset.name
        if current_dataset
        else "Existing analysis"
    )

    record_completed_analysis(current_dataset_name)


# ============================================================
# DATASET DISCOVERY
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


# Register an existing completed analysis the first time the
# upgraded dashboard is opened.
bootstrap_analysis_history()


# ============================================================
# CLEAR PREVIOUS ANALYSIS
# ============================================================

def clear_previous_analysis():

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    for folder in [RAW_DIR, PROCESSED_DIR]:

        for csv_file in folder.glob("*.csv"):
            try:
                csv_file.unlink()
            except Exception:
                pass

    generated_files = [
        EVIDENCE_FILE,
        SCHEMA_FILE,
        ALERT_FILE,
        REPORT_FILE,
        MITRE_CANDIDATES_FILE,
        MITRE_FILE,
        DOCUMENT_ANALYSIS_FILE,
    ]

    for file_path in generated_files:

        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass

    for uploaded in UPLOAD_DIR.iterdir():
        try:
            if uploaded.is_file():
                uploaded.unlink()
        except Exception:
            pass


def format_timestamp(value):
    if not value:
        return "Not available"

    try:
        timestamp = pd.to_datetime(value)
        return timestamp.strftime("%d %b %Y, %H:%M:%S")
    except Exception:
        return str(value)


def format_duration(seconds):
    if seconds is None:
        return "Not available"

    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "Not available"

    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes, remaining_seconds = divmod(int(round(seconds)), 60)

    if minutes < 60:
        return f"{minutes}m {remaining_seconds}s"

    hours, remaining_minutes = divmod(minutes, 60)
    return f"{hours}h {remaining_minutes}m {remaining_seconds}s"


# ============================================================
# RUN PIPELINE
# ============================================================

def run_analysis_pipeline(
    progress_container=None,
    status_container=None,
    dataset_name=None,
):

    pipeline = [
        ("Data Cleaning", "data_cleaner.py"),
        ("Data Validation", "data_validation.py"),
        ("Schema Discovery", "schema_discovery.py"),
        ("Security Analysis", "security_analysis.py"),
        ("MITRE Retrieval", "mitre_mapping.py"),
        ("MITRE Evidence Validation", "mitre_evaluator.py"),
        ("AI Security Report", "security_report.py"),
        ("Risk & Alert Engine", "risk_alert_engine.py"),
    ]

    logs = []
    total_steps = len(pipeline)
    run_id = pd.Timestamp.now().strftime("%Y%m%d%H%M%S")
    started_timestamp = pd.Timestamp.now()
    started_at = started_timestamp.isoformat()

    progress_container = progress_container or st.empty()
    status_container = status_container or st.empty()

    progress = progress_container.progress(
        0,
        text="Starting security analysis..."
    )

    update_analysis_status(
        "RUNNING",
        run_id,
        "Starting analysis",
        0,
        total_steps,
        dataset_name,
        "Initialising security analysis pipeline.",
        started_at=started_at,
    )

    try:
        for index, (step_name, script_name) in enumerate(pipeline, start=1):

            script_path = BASE_DIR / script_name

            if not script_path.exists():
                raise FileNotFoundError(
                    f"Required pipeline script not found: {script_name}"
                )

            status_container.info(
                f"Analysis in progress — {step_name} ({index}/{total_steps})"
            )

            progress.progress(
                (index - 1) / total_steps,
                text=f"{step_name}..."
            )

            update_analysis_status(
                "RUNNING",
                run_id,
                step_name,
                index,
                total_steps,
                dataset_name,
                f"Running {step_name}.",
                started_at=started_at,
            )

            try:
                result = subprocess.run(
                    [sys.executable, str(script_path)],
                    cwd=str(BASE_DIR),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=1800,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    f"{step_name} timed out after 30 minutes."
                )
            except Exception as exc:
                raise RuntimeError(
                    f"{step_name} failed to start: {exc}"
                )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            logs.append(
                {
                    "step": step_name,
                    "script": script_name,
                    "return_code": result.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )

            if result.returncode != 0:
                error_text = stderr or stdout
                raise RuntimeError(
                    f"{step_name} failed.\n\n{error_text[-5000:]}"
                )

            progress.progress(
                index / total_steps,
                text=f"{step_name} complete"
            )

            update_analysis_status(
                "RUNNING",
                run_id,
                step_name,
                index,
                total_steps,
                dataset_name,
                f"{step_name} completed successfully.",
                started_at=started_at,
            )

        completed_timestamp = pd.Timestamp.now()
        completed_at = completed_timestamp.isoformat()
        duration_seconds = round(
            (completed_timestamp - started_timestamp).total_seconds(),
            2
        )

        record_completed_analysis(
            dataset_name,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
        )

        update_analysis_status(
            "COMPLETED",
            run_id,
            "Analysis Complete",
            total_steps,
            total_steps,
            dataset_name,
            "Security analysis pipeline completed successfully.",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
        )

        progress.progress(
            1.0,
            text=f"Security analysis complete — {format_duration(duration_seconds)}"
        )

        status_container.success(
            f"Security analysis pipeline completed successfully "
            f"in {format_duration(duration_seconds)}."
        )

        return logs

    except Exception as exc:

        failed_timestamp = pd.Timestamp.now()
        failed_at = failed_timestamp.isoformat()
        duration_seconds = round(
            (failed_timestamp - started_timestamp).total_seconds(),
            2
        )

        update_analysis_status(
            "FAILED",
            run_id,
            "Pipeline Error",
            0,
            total_steps,
            dataset_name,
            str(exc),
            started_at=started_at,
            completed_at=failed_at,
            duration_seconds=duration_seconds,
        )

        status_container.error(
            f"Security analysis failed after "
            f"{format_duration(duration_seconds)}: {exc}"
        )

        raise


# ============================================================
# LOAD CURRENT ANALYSIS
# ============================================================

evidence = load_json(EVIDENCE_FILE)
schema = load_json(SCHEMA_FILE)
alerts_data = load_json(ALERT_FILE)
mitre_data = load_json(MITRE_FILE)

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

if DOCUMENT_ANALYSIS_FILE.exists() and not dataset:
    dataset_type = "document/image"

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
                return int(float(value))
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

    if isinstance(data, dict):
        data = list(data.values())

    if not isinstance(data, list):
        return []

    results = []

    for item in data:

        if not isinstance(item, dict):
            continue

        finding = item.get(
            "finding",
            item
        )

        if isinstance(finding, dict):
            results.append(finding)

    return results


findings = get_findings()


# ============================================================
# FINDING NAME
# ============================================================

def get_finding_name(finding):

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

    if isinstance(data, list):
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

        severity_counts[severity] += 1


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

def extract_mitre(obj, results):

    if isinstance(obj, dict):

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

    elif isinstance(obj, list):

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

    unique_mitre[key] = item


mitre_assessments = list(
    unique_mitre.values()
)


mitre_supported = sum(
    1
    for item in mitre_assessments
    if item["status"] == "SUPPORTED"
)

mitre_possible = sum(
    1
    for item in mitre_assessments
    if item["status"] == "POSSIBLE"
)

mitre_not_supported = sum(
    1
    for item in mitre_assessments
    if item["status"] == "NOT_SUPPORTED"
)


# ============================================================
# MITRE CANDIDATE GROUPS
# ============================================================

candidate_groups = 0

if isinstance(mitre_data, dict):

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
                ).lower() == "attack"
            ]
        )



# ============================================================
# ACTIVE FILTERED DATA
# ============================================================

filtered_findings, filtered_alerts, filtered_mitre = (
    findings,
    alerts,
    mitre_assessments,
)


# ============================================================
# PORT ANALYSIS
# ============================================================

def get_port_data():

    counter = Counter()

    def walk(obj):

        if isinstance(obj, dict):

            for key, value in obj.items():

                key_lower = str(key).lower()

                if "associated_destination_ports" in key_lower:

                    if isinstance(value, dict):

                        for port, count in value.items():

                            try:

                                counter[str(port)] += int(
                                    float(count)
                                )

                            except Exception:
                                pass

                walk(value)

        elif isinstance(obj, list):

            for item in obj:
                walk(item)

    walk(evidence)

    return counter.most_common(8)


# ============================================================
# TIMELINE
# ============================================================

def get_timeline():

    rows = []

    for finding in filtered_findings:

        temporal = finding.get(
            "temporal_evidence",
            {}
        )

        if not isinstance(temporal, dict):
            continue

        name = get_finding_name(finding)

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

    df = pd.DataFrame(rows)

    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        errors="coerce"
    )

    return df.dropna(
        subset=["Timestamp"]
    )


# ============================================================
# GLOBAL FILTERS
# ============================================================

def get_filter_options():
    severities = sorted({
        str(a.get("severity", "Informational"))
        for a in alerts
        if isinstance(a, dict)
    })

    statuses = sorted({
        str(a.get("status", "Unknown"))
        for a in alerts
        if isinstance(a, dict)
    })

    findings_names = sorted({
        str(a.get("finding", "Unknown"))
        for a in alerts
        if isinstance(a, dict)
    } | {
        str(get_finding_name(f))
        for f in findings
        if isinstance(f, dict)
    })

    mitre_techniques = sorted({
        f"{m.get('technique_id', '')} — {m.get('technique_name', '')}"
        for m in mitre_assessments
        if isinstance(m, dict)
    })

    return severities, statuses, findings_names, mitre_techniques


def apply_global_filters(
    selected_severities,
    selected_statuses,
    selected_findings,
    selected_mitre,
    search_text,
):
    filtered_alerts = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        if selected_severities and alert.get("severity") not in selected_severities:
            continue

        if selected_statuses and alert.get("status") not in selected_statuses:
            continue

        finding_name = str(alert.get("finding", "Unknown"))

        if selected_findings and finding_name not in selected_findings:
            continue

        if search_text:
            haystack = json.dumps(alert, ensure_ascii=False).lower()
            if search_text.lower() not in haystack:
                continue

        if selected_mitre:
            related = [
                m for m in mitre_assessments
                if str(m.get("finding", "")).strip().lower()
                == finding_name.strip().lower()
                and f"{m.get('technique_id', '')} — {m.get('technique_name', '')}"
                in selected_mitre
            ]
            if not related:
                continue

        filtered_alerts.append(alert)

    filtered_finding_names = {
        str(a.get("finding", "Unknown"))
        for a in filtered_alerts
    }

    if not any([
        selected_severities,
        selected_statuses,
        selected_findings,
        selected_mitre,
        search_text,
    ]):
        filtered_findings = findings
    else:
        filtered_findings = [
            f for f in findings
            if str(get_finding_name(f)) in filtered_finding_names
        ]

    if selected_mitre:
        filtered_mitre = [
            m for m in mitre_assessments
            if f"{m.get('technique_id', '')} — {m.get('technique_name', '')}"
            in selected_mitre
        ]
    elif filtered_finding_names:
        filtered_mitre = [
            m for m in mitre_assessments
            if str(m.get("finding", "")).strip().lower()
            in {x.strip().lower() for x in filtered_finding_names}
        ]
    else:
        filtered_mitre = mitre_assessments

    return filtered_findings, filtered_alerts, filtered_mitre


def render_filters():
    """Render sidebar filters. Search is rendered in the main header."""
    st.markdown("### Filters")

    severities, statuses, finding_names, mitre_names = get_filter_options()

    selected_severities = st.multiselect(
        "Severity",
        severities,
        key="filter_severity",
    )

    selected_statuses = st.multiselect(
        "Status",
        statuses,
        key="filter_status",
    )

    selected_findings = st.multiselect(
        "Finding",
        finding_names,
        key="filter_finding",
    )

    selected_mitre = st.multiselect(
        "MITRE Technique",
        mitre_names,
        key="filter_mitre",
    )

    st.caption("Filters apply automatically.")

    return (
        selected_severities,
        selected_statuses,
        selected_findings,
        selected_mitre,
    )


def render_report_exports(
    filtered_findings,
    filtered_alerts,
    filtered_mitre,
    document_result=None,
):
    st.markdown("### Export Report")

    package = build_filtered_package(
        dataset_name=dataset_name,
        dataset_type=dataset_type,
        dataset_mode=dataset_mode,
        total_events=total_events,
        findings=filtered_findings,
        alerts=filtered_alerts,
        mitre_assessments=filtered_mitre,
        document_result=document_result,
    )

    formats = [
        ("PDF", "report.pdf", "application/pdf"),
        ("DOCX", "report.docx",
         "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ("XLSX", "report.xlsx",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("CSV", "report.csv", "text/csv"),
        ("JSON", "report.json", "application/json"),
        ("TXT", "report.txt", "text/plain"),
        ("Markdown", "report.md", "text/markdown"),
    ]

    columns = st.columns(4)

    for index, (format_name, filename, mime) in enumerate(formats):
        exporter = EXPORTERS.get(format_name)

        if exporter is None:
            continue

        with columns[index % 4]:
            try:
                content = exporter(package)
                st.download_button(
                    f"Export {format_name}",
                    data=content,
                    file_name=filename,
                    mime=mime,
                    use_container_width=True,
                    key=f"export_{format_name}",
                )
            except Exception as exc:
                st.error(f"{format_name} export failed: {exc}")


def render_page_export(
    page_name,
    page_findings,
    page_alerts,
    page_mitre,
    document_result=None,
):
    with st.expander(f"Export {page_name} Report", expanded=False):
        st.caption(
            "Exports include the current page data and active filters."
        )
        render_report_exports(
            page_findings,
            page_alerts,
            page_mitre,
            document_result=document_result,
        )


def render_document_result(result):
    st.subheader("AI Security Analysis")

    if not result:
        st.info("No document analysis available.")
        return

    summary = result.get("executive_summary")
    if summary:
        st.markdown("#### Executive Summary")
        st.write(summary)

    assessment = result.get("document_type_assessment")
    if assessment:
        st.markdown("#### Material Assessment")
        st.write(assessment)

    findings_result = result.get("findings", [])

    if findings_result:
        st.markdown("#### Findings")

        for finding in findings_result:
            if not isinstance(finding, dict):
                continue

            name = finding.get("finding", "Unknown")
            severity = finding.get("severity", "Unknown")
            confidence = finding.get("confidence", "Unknown")

            with st.expander(
                f"{name} • {severity} • {confidence}"
            ):
                for section, title in [
                    ("observed_evidence", "Observed Evidence"),
                    ("inference", "Inference"),
                    ("evidence_gaps", "Evidence Gaps"),
                    ("investigation_steps", "Investigation Steps"),
                    ("defensive_actions", "Defensive Actions"),
                ]:
                    values = finding.get(section, [])
                    if values:
                        st.markdown(f"##### {title}")
                        for value in values:
                            st.write(f"• {value}")

                candidates = finding.get("mitre_candidates", [])
                if candidates:
                    st.markdown("##### MITRE ATT&CK")
                    rows = []
                    for candidate in candidates:
                        if isinstance(candidate, dict):
                            rows.append({
                                "Technique": candidate.get("technique_id", ""),
                                "Name": candidate.get("technique_name", ""),
                                "Assessment": candidate.get("assessment", ""),
                                "Reason": candidate.get("reason", ""),
                            })
                    if rows:
                        st.dataframe(
                            pd.DataFrame(rows),
                            use_container_width=True,
                            hide_index=True,
                        )

    overall = result.get("overall_risk", {})
    if isinstance(overall, dict):
        st.markdown("#### Overall Risk")
        c1, c2 = st.columns(2)
        with c1:
            st.metric("Risk", overall.get("level", "Unknown"))
        with c2:
            st.metric("Confidence", overall.get("confidence", "Low"))
        if overall.get("reason"):
            st.write(overall["reason"])

    capabilities = result.get("telemetry_capabilities", {})
    if capabilities:
        st.markdown("#### Telemetry Capabilities")
        rows = [
            {
                "Capability": str(k).replace("_", " ").title(),
                "Available": "Yes" if bool(v) else "No",
            }
            for k, v in capabilities.items()
        ]
        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# LIVE ANALYSIS STATUS
# ============================================================

live_progress_container = st.empty()
live_status_container = st.empty()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "## AI Security Copilot"
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
            "Evidence",
            "Reports",
            "Settings"
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

    # ========================================================
    # UPLOAD
    # ========================================================

    st.markdown("### Upload Security Material")

    uploaded_file = st.file_uploader(
        "Security material",
        type=[ext.lstrip(".") for ext in SUPPORTED_EXTENSIONS],
        help=(
            "Upload CSV, Excel, JSON, Parquet, TXT, LOG, RTF, PDF, "
            "DOCX or PNG/JPG/JPEG security material."
        ),
    )

    if uploaded_file:

        file_size_mb = uploaded_file.size / (1024 * 1024)
        upload_type = classify_file(uploaded_file.name)

        st.caption(
            f"Selected: {uploaded_file.name} ({file_size_mb:.1f} MB)"
        )
        st.caption(f"Detected type: {upload_type.title()}")

        if st.button(
            "Upload & Analyse",
            use_container_width=True,
            type="primary",
        ):

            try:
                clear_previous_analysis()

                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                safe_name = safe_filename(uploaded_file.name)
                upload_path = UPLOAD_DIR / safe_name

                with open(upload_path, "wb") as file:
                    file.write(uploaded_file.getbuffer())

                if upload_type == "structured":

                    RAW_DIR.mkdir(parents=True, exist_ok=True)

                    # Convert Excel/JSON/Parquet to CSV so the existing
                    # security telemetry pipeline can process it.
                    destination = RAW_DIR / f"{Path(safe_name).stem}.csv"

                    convert_structured_to_csv(
                        upload_path,
                        destination,
                    )

                    st.success(
                        "Structured security data uploaded. "
                        "Starting the telemetry pipeline..."
                    )

                    run_analysis_pipeline(
                        progress_container=live_progress_container,
                        status_container=live_status_container,
                        dataset_name=safe_name,
                    )

                elif upload_type in {"document", "image"}:

                    with st.spinner(
                        "Extracting and analysing security material..."
                    ):
                        result = analyse_uploaded_file(
                            upload_path,
                            safe_name,
                        )

                    DOCUMENT_ANALYSIS_FILE.write_text(
                        json.dumps(
                            result,
                            indent=2,
                            ensure_ascii=False,
                        ),
                        encoding="utf-8",
                    )

                    st.success(
                        "Security material analysed successfully."
                    )

                    document_findings = result.get("findings", [])
                    if not isinstance(document_findings, list):
                        document_findings = []

                    history = load_analysis_history()
                    history.append(
                        {
                            "analysis_number": len(history) + 1,
                            "timestamp": pd.Timestamp.now().isoformat(),
                            "analysis_type": upload_type,
                            "dataset_name": safe_name,
                            "events": 0,
                            "findings": len(document_findings),
                            "alerts": 0,
                            "mode": "DOCUMENT_ANALYSIS",
                            "dataset_type": upload_type,
                        }
                    )
                    save_json(ANALYSIS_HISTORY_FILE, history)

                else:
                    raise ValueError(
                        f"Unsupported file type: {Path(safe_name).suffix}"
                    )

                st.rerun()

            except Exception as exc:

                st.error("The uploaded material could not be analysed.")
                st.exception(exc)
                st.stop()

    st.divider()

    (
        selected_severities,
        selected_statuses,
        selected_findings,
        selected_mitre,
    ) = render_filters()

    st.divider()



# ============================================================
# GLOBAL HEADER + SEARCH
# ============================================================

header_left, header_right = st.columns([7, 1.5])

with header_left:
    st.title("AI Security Copilot")
    st.caption(
        "See the signal. Catch the threat. "
        "AI-powered security intelligence."
    )

    search_text = st.text_input(
        "Global search",
        placeholder="Search alerts, findings or evidence",
        key="global_search",
        label_visibility="collapsed",
    )

with header_right:
    st.metric("Active Alerts", active_alerts)

(
    filtered_findings,
    filtered_alerts,
    filtered_mitre,
) = apply_global_filters(
    selected_severities,
    selected_statuses,
    selected_findings,
    selected_mitre,
    search_text,
)

st.divider()


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    render_page_export(
        "Overview",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    # ========================================================
    # ANALYSIS STATUS & HISTORY
    # ========================================================

    current_status = load_json(ANALYSIS_STATUS_FILE)
    history = load_analysis_history()

    status_value = current_status.get("status", "IDLE")

    if status_value == "RUNNING":
        st.info(
            f"Analysis in progress — "
            f"{current_status.get('current_step', 'Starting')} "
            f"({current_status.get('step_number', 0)}/"
            f"{current_status.get('total_steps', 8)})"
        )
    elif status_value == "FAILED":
        st.error(
            f"Last analysis failed: "
            f"{current_status.get('message', 'Unknown error.')}"
        )
    elif status_value == "COMPLETED":
        st.success(
            f"Last analysis completed — "
            f"{current_status.get('dataset_name', dataset_name)}"
        )

        completed_at = current_status.get("completed_at")
        duration_seconds = current_status.get("duration_seconds")

        if completed_at or duration_seconds is not None:
            st.caption(
                f"Completed: {format_timestamp(completed_at)}  •  "
                f"Duration: {format_duration(duration_seconds)}"
            )

    cumulative_events = sum(
        int(item.get("events", 0)) for item in history
    )
    cumulative_findings = sum(
        int(item.get("findings", 0)) for item in history
    )

    h1, h2, h3, h4 = st.columns(4)

    with h1:
        st.metric("Total Analyses", len(history))

    with h2:
        st.metric(
            "Datasets Analysed",
            len({
                item.get("dataset_name")
                for item in history
                if item.get("dataset_name")
            })
        )

    with h3:
        st.metric(
            "Cumulative Events",
            f"{cumulative_events:,}"
        )

    with h4:
        st.metric(
            "Cumulative Findings",
            f"{cumulative_findings:,}"
        )

    with st.expander("Analysis History", expanded=False):
        if history:
            rows = []
            for item in reversed(history):
                rows.append(
                    {
                        "Run": item.get("analysis_number", "-"),
                        "Dataset": item.get("dataset_name", "-"),
                        "Started": format_timestamp(item.get("started_at")),
                        "Completed": format_timestamp(item.get("completed_at")),
                        "Duration": format_duration(item.get("duration_seconds")),
                        "Events": int(item.get("events", 0)),
                        "Findings": int(item.get("findings", 0)),
                        "Alerts": int(item.get("alerts", 0)),
                        "Mode": item.get("mode", "-"),
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No completed analyses have been recorded yet.")

    st.divider()

    k1, k2, k3, k4, k5 = st.columns(5)

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

    c1, c2, c3 = st.columns([1.15, 1.15, 1])

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

    with c2:

        st.subheader(
            "Risk Score by Finding"
        )

        if filtered_alerts:

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
                    for alert in filtered_alerts
                ]
            )

            fig = go.Figure()

            for _, row in risk_df.iterrows():

                severity = row["Severity"]

                fig.add_trace(
                    go.Bar(
                        x=[row["Finding"]],
                        y=[row["Risk Score"]],
                        marker_color=SEVERITY_COLOURS.get(
                            severity,
                            GREY
                        ),
                        text=[row["Risk Score"]],
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

    with c3:

        st.subheader(
            "Alert Severity Distribution"
        )

        severity_df = pd.DataFrame(
            {
                "Severity": list(
                    severity_counts.keys()
                ),
                "Count": list(
                    severity_counts.values()
                )
            }
        )

        severity_df = severity_df[
            severity_df["Count"] > 0
        ]

        if not severity_df.empty:

            fig = go.Figure(
                go.Pie(
                    labels=severity_df["Severity"],
                    values=severity_df["Count"],
                    hole=0.58,
                    textinfo="label+value",
                    textposition="outside",
                    marker=dict(
                        colors=[
                            SEVERITY_COLOURS[value]
                            for value in severity_df["Severity"]
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

    c1, c2, c3 = st.columns([1.15, 1.15, 1])

    with c1:

        st.subheader(
            "Findings by Dataset Share"
        )

        rows = []

        for finding in filtered_findings:

            rows.append(
                {
                    "Finding":
                        get_finding_name(finding),
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

            df = pd.DataFrame(rows)

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
                    labels=mitre_df["Assessment"],
                    values=mitre_df["Count"],
                    hole=0.58,
                    textinfo="label+value"
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=310,
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

        else:

            st.info(
                "No MITRE assessments."
            )

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

            df["Port"] = df["Port"].astype(str)

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

    c1, c2 = st.columns([1.15, 1])

    with c1:

        st.subheader(
            "Anomalies"
        )

        st.caption(
            "Findings requiring analyst attention"
        )

        suspicious = [
            alert
            for alert in filtered_alerts
            if alert.get(
                "severity",
                "Informational"
            ) != "Informational"
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

                a, b, c = st.columns([4, 1, 1])

                with a:

                    st.write(
                        f"{finding}"
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
            "Threat Indicators"
        )

        st.caption(
            "MITRE techniques requiring attention"
        )

        threat_items = [
            item
            for item in filtered_mitre
            if item["status"] in [
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
                    f"{item['technique_id']}"
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


    filtered_severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for alert_item in filtered_alerts:
        severity_item = alert_item.get("severity", "Informational")
        if severity_item in filtered_severity_counts:
            filtered_severity_counts[severity_item] += 1

    st.title(
        "Risk & Alert Centre"
    )

    st.caption(
        "Security alerts, risk prioritisation and analyst triage."
    )
 
    render_page_export(
        "Alerts",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric(
            "Critical",
            filtered_severity_counts["Critical"]
        )

    with c2:
        st.metric(
            "High",
            filtered_severity_counts["High"]
        )

    with c3:
        st.metric(
            "Medium",
            filtered_severity_counts["Medium"]
        )

    with c4:
        st.metric(
            "Low",
            filtered_severity_counts["Low"]
        )

    with c5:
        st.metric(
            "Informational",
            filtered_severity_counts["Informational"]
        )

    st.divider()

    chart1, chart2 = st.columns(2)

    with chart1:

        st.subheader(
            "Alert Severity Distribution"
        )

        severity_df = pd.DataFrame(
            {
                "Severity": list(
                    severity_counts.keys()
                ),
                "Count": list(
                    severity_counts.values()
                )
            }
        )

        severity_df = severity_df[
            severity_df["Count"] > 0
        ]

        if not severity_df.empty:

            fig = go.Figure(
                go.Pie(
                    labels=severity_df["Severity"],
                    values=severity_df["Count"],
                    hole=0.58,
                    textinfo="label+value",
                    textposition="outside",
                    marker=dict(
                        colors=[
                            SEVERITY_COLOURS[value]
                            for value in severity_df["Severity"]
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
            "Risk Score by Finding"
        )

        if filtered_alerts:

            fig = go.Figure()

            for alert in filtered_alerts:

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
                        marker_color=SEVERITY_COLOURS.get(
                            severity,
                            GREY
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
                yaxis=dict(
                    title="Risk Score",
                    range=[0, 100],
                    gridcolor="#29303d"
                ),
                xaxis=dict(
                    title="",
                    showgrid=False
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
        "Security Alerts"
    )

    if filtered_alerts:

        rows = []

        for alert in filtered_alerts:

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

        alert_df = pd.DataFrame(rows)

        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.subheader(
            "Alert Details"
        )

        options = [
            f"{alert.get('alert_id')} — "
            f"{alert.get('finding')}"
            for alert in filtered_alerts
        ]

        selected = st.selectbox(
            "Select alert",
            options
        )

        selected_index = options.index(
            selected
        )

        alert = filtered_alerts[selected_index]

        d1, d2, d3, d4 = st.columns(4)

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

        # ====================================================
        # RISK CALCULATION BREAKDOWN
        # ====================================================

        risk_calculation = alert.get(
            "risk_calculation",
            {}
        )

        if risk_calculation:

            st.divider()
            st.subheader("Risk Calculation")

            rc1, rc2 = st.columns([1, 2])

            with rc1:
                st.metric(
                    "Calculated Risk Score",
                    f"{risk_calculation.get('score', alert.get('risk_score', 0))}/"
                    f"{risk_calculation.get('maximum_possible_score', 100)}"
                )

                st.caption(
                    risk_calculation.get(
                        "interpretation",
                        "Analytical prioritisation score."
                    )
                )

            with rc2:

                components = risk_calculation.get(
                    "components",
                    {}
                )

                rows = []

                for component_name, component_data in components.items():

                    if not isinstance(component_data, dict):
                        continue

                    rows.append(
                        {
                            "Component": component_name.replace(
                                "_",
                                " "
                            ).title(),
                            "Score": component_data.get("score", 0),
                            "Maximum": component_data.get("maximum", 0),
                            "Contribution": (
                                f"{component_data.get('score', 0)}/"
                                f"{component_data.get('maximum', 0)}"
                            ),
                            "Reason": component_data.get("reason", ""),
                        }
                    )

                if rows:
                    st.dataframe(
                        pd.DataFrame(rows),
                        use_container_width=True,
                        hide_index=True,
                    )

            baseline = risk_calculation.get("baseline", {})

            if isinstance(baseline, dict):
                description = baseline.get("description")
                if description:
                    st.caption(description)

        st.divider()

        e1, e2 = st.columns(2)

        with e1:

            st.subheader(
                "Evidence"
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
                "Evidence Gaps"
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

        i1, i2 = st.columns(2)

        with i1:

            st.subheader(
                "Investigation Steps"
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
                "Defensive Actions"
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
        "Security Findings"
    )

    st.caption(
        "Behavioural findings identified from the analysed security telemetry."
    )
 
    render_page_export(
        "Security Findings",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    if filtered_findings:

        total_findings = len(filtered_findings)

        attack_findings = sum(
            1
            for finding in findings
            if str(
                finding.get(
                    "classification",
                    ""
                )
            ).lower() == "attack"
        )

        baseline_findings = sum(
            1
            for finding in findings
            if str(
                finding.get(
                    "classification",
                    ""
                )
            ).lower() == "benign"
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

        c1, c2, c3, c4 = st.columns(4)

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

        chart1, chart2 = st.columns(2)

        finding_rows = []

        for finding in filtered_findings:

            finding_rows.append(
                {
                    "Finding":
                        get_finding_name(finding),
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
                    labels=finding_df["Finding"],
                    values=finding_df["Records"],
                    hole=0.55,
                    textinfo="label+percent"
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

        st.subheader(
            "Finding Overview"
        )

        table_rows = []

        for finding in filtered_findings:

            classification = str(
                finding.get(
                    "classification",
                    "unknown"
                )
            ).lower()

            if classification == "benign":
                display_classification = "Baseline"

            elif classification == "attack":
                display_classification = "Attack"

            else:
                display_classification = "Unknown"

            table_rows.append(
                {
                    "Finding":
                        get_finding_name(finding),
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

        st.subheader(
            "Behavioural Findings"
        )

        for finding in filtered_findings:

            label = get_finding_name(finding)

            classification = str(
                finding.get(
                    "classification",
                    "unknown"
                )
            ).lower()

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
                f"{label} • "
                f"{records:,} records • "
                f"{share:.2f}%"
            ):

                a1, a2, a3 = st.columns(3)

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

                ports = finding.get(
                    "associated_destination_ports",
                    {}
                )

                if ports:

                    st.markdown(
                        "#### Destination Ports"
                    )

                    port_rows = []

                    for port, count in sorted(
                        ports.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]:

                        try:
                            count = int(float(count))
                        except Exception:
                            continue

                        port_rows.append(
                            {
                                "Port": str(port),
                                "Records": count
                            }
                        )

                    if port_rows:

                        st.dataframe(
                            pd.DataFrame(port_rows),
                            use_container_width=True,
                            hide_index=True
                        )

                protocols = finding.get(
                    "associated_protocols",
                    {}
                )

                if protocols:

                    st.markdown(
                        "#### Protocols"
                    )

                    protocol_rows = []

                    for protocol, count in sorted(
                        protocols.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]:

                        try:
                            count = int(float(count))
                        except Exception:
                            continue

                        protocol_rows.append(
                            {
                                "Protocol": str(protocol),
                                "Records": count
                            }
                        )

                    if protocol_rows:

                        st.dataframe(
                            pd.DataFrame(protocol_rows),
                            use_container_width=True,
                            hide_index=True
                        )

                statistics = finding.get(
                    "behavioural_statistics",
                    {}
                )

                if statistics:

                    st.markdown(
                        "#### Behavioural Statistics"
                    )

                    statistic_rows = []

                    for name, value in statistics.items():

                        if isinstance(value, dict):

                            for sub_name, sub_value in value.items():

                                statistic_rows.append(
                                    {
                                        "Metric":
                                            f"{name} • {sub_name}",
                                        "Value":
                                            str(sub_value)
                                    }
                                )

                        else:

                            statistic_rows.append(
                                {
                                    "Metric": str(name),
                                    "Value": str(value)
                                }
                            )

                    if statistic_rows:

                        st.dataframe(
                            pd.DataFrame(statistic_rows),
                            use_container_width=True,
                            hide_index=True
                        )

                temporal = finding.get(
                    "temporal_evidence",
                    {}
                )

                if temporal:

                    st.markdown(
                        "#### Temporal Evidence"
                    )

                    t1, t2, t3 = st.columns(3)

                    with t1:

                        st.write(
                            "First observed"
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
                            "Last observed"
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
                            "Peak activity"
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

                comparative = finding.get(
                    "comparative_behavioural_evidence",
                    {}
                )

                if comparative:

                    st.markdown(
                        "#### Comparative Behaviour"
                    )

                    if isinstance(
                        comparative,
                        dict
                    ):

                        for key, value in comparative.items():

                            if isinstance(value, dict):

                                st.write(
                                    f"**{key}**"
                                )

                                for sub_key, sub_value in value.items():

                                    st.caption(
                                        f"{sub_key}: {sub_value}"
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

                limitations = finding.get(
                    "evidence_limitations",
                    []
                )

                if limitations:

                    st.markdown(
                        "#### Evidence Limitations"
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
        "Security Timeline"
    )

    st.caption(
        "Temporal view of observed security activity."
    )
 
    render_page_export(
        "Timeline",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
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
            plot_bgcolor=BG
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
        "MITRE ATT&CK Assessment"
    )

    st.caption(
        "Evidence-based validation of retrieved ATT&CK techniques."
    )
 
    render_page_export(
        "MITRE ATT&CK",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "Supported",
            sum(1 for item in filtered_mitre if item["status"] == "SUPPORTED")
        )

    with c2:
        st.metric(
            "Possible",
            sum(1 for item in filtered_mitre if item["status"] == "POSSIBLE")
        )

    with c3:
        st.metric(
            "Not Supported",
            sum(1 for item in filtered_mitre if item["status"] == "NOT_SUPPORTED")
        )

    st.divider()

    mitre_df = pd.DataFrame(
        {
            "Assessment": [
                "Supported",
                "Possible",
                "Not Supported"
            ],
            "Count": [
                sum(1 for item in filtered_mitre if item["status"] == "SUPPORTED"),
                sum(1 for item in filtered_mitre if item["status"] == "POSSIBLE"),
                sum(1 for item in filtered_mitre if item["status"] == "NOT_SUPPORTED")
            ]
        }
    )

    mitre_df = mitre_df[
        mitre_df["Count"] > 0
    ]

    if not mitre_df.empty:

        fig = go.Figure(
            go.Pie(
                labels=mitre_df["Assessment"],
                values=mitre_df["Count"],
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

    supported = [
        item
        for item in filtered_mitre
        if item["status"] == "SUPPORTED"
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

    possible = [
        item
        for item in filtered_mitre
        if item["status"] == "POSSIBLE"
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
        "AI Security Analyst"
    )

    st.caption(
        "AI-generated security assessment based on "
        "the analysed evidence and validated findings."
    )

    if DOCUMENT_ANALYSIS_FILE.exists():

        document_result = load_json(DOCUMENT_ANALYSIS_FILE)
        render_document_result(document_result)

        st.divider()
        render_report_exports(
            [],
            [],
            [],
            document_result=document_result,
        )

    elif REPORT_FILE.exists():

        render_page_export(
            "AI Analyst",
            filtered_findings,
            filtered_alerts,
            filtered_mitre,
        )

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
        "Evidence Centre"
    )

    st.caption(
        "Technical evidence and validation context generated by the security pipeline."
    )
 
    render_page_export(
        "Evidence",
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    st.subheader(
        "Dataset Evidence"
    )

    d1, d2, d3, d4 = st.columns(4)

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

    st.subheader(
        "MITRE Validation"
    )

    m1, m2, m3, m4 = st.columns(4)

    with m1:

        st.metric(
            "Candidate Groups",
            candidate_groups
        )

    with m2:

        st.metric(
            "Candidates Evaluated",
            len(mitre_assessments)
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

    st.subheader(
        "Validation Status"
    )

    v1, v2, v3 = st.columns(3)

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

    st.subheader(
        "AI Validation Model"
    )

    validation_model = "GPT-5.6"

    if isinstance(mitre_data, dict):

        validation_model = mitre_data.get(
            "validation_model",
            validation_model
        )

    st.info(
        f"Validation model: {validation_model}"
    )

    st.subheader(
        "Validation Principles"
    )

    principles = []

    if isinstance(mitre_data, dict):

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
            f"{principle}"
        )

    st.divider()

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

        chart1, chart2 = st.columns(2)

        with chart1:

            fig = go.Figure(
                go.Pie(
                    labels=mitre_visual_df["Assessment"],
                    values=mitre_visual_df["Count"],
                    hole=0.60,
                    textinfo="label+value"
                )
            )

            fig.update_layout(
                template="plotly_dark",
                height=350,
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

    st.subheader(
        "Finding-by-Finding Assessment"
    )

    if findings:

        finding_names = [
            get_finding_name(finding)
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
                finding_name
            ):

                if related_alert:

                    a1, a2, a3 = st.columns(3)

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
                    if item["status"] == "SUPPORTED"
                ]

                possible_items = [
                    item
                    for item in finding_mitre
                    if item["status"] == "POSSIBLE"
                ]

                rejected_items = [
                    item
                    for item in finding_mitre
                    if item["status"] == "NOT_SUPPORTED"
                ]

                r1, r2, r3 = st.columns(3)

                with r1:

                    st.metric(
                        "Supported",
                        len(supported_items)
                    )

                with r2:

                    st.metric(
                        "Possible",
                        len(possible_items)
                    )

                with r3:

                    st.metric(
                        "Not Supported",
                        len(rejected_items)
                    )

                if supported_items:

                    st.markdown(
                        "##### Supported"
                    )

                    for item in supported_items:

                        st.success(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                if possible_items:

                    st.markdown(
                        "##### Possible"
                    )

                    for item in possible_items:

                        st.warning(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                if rejected_items:

                    st.markdown(
                        "##### Not Supported"
                    )

                    for item in rejected_items[:10]:

                        st.caption(
                            f"{item['technique_id']} — "
                            f"{item['technique_name']}"
                        )

                    if len(rejected_items) > 10:

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

    st.subheader(
        "Evidence Gaps"
    )

    evidence_gaps = []

    for alert in alerts:

        gaps = alert.get(
            "evidence_gaps",
            []
        )

        if isinstance(gaps, list):

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
                        "Yes"
                        if available
                        else "No"
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
# REPORTS
# ============================================================

elif page == "Reports":

    st.title("Reports")

    st.caption(
        "Filter the current security results and export the report "
        "in the format required for SOC, audit or review workflows."
    )

    render_report_exports(
        filtered_findings,
        filtered_alerts,
        filtered_mitre,
    )

    st.divider()

    st.subheader("Filtered Report Preview")

    st.write(
        f"Findings: {len(filtered_findings)}"
    )
    st.write(
        f"Alerts: {len(filtered_alerts)}"
    )
    st.write(
        f"MITRE assessments: {len(filtered_mitre)}"
    )

    preview_rows = []

    for alert in filtered_alerts:
        preview_rows.append({
            "Type": "Alert",
            "Finding": alert.get("finding", "-"),
            "Severity": alert.get("severity", "-"),
            "Risk Score": alert.get("risk_score", 0),
            "Confidence": alert.get("confidence", "-"),
            "Status": alert.get("status", "-"),
        })

    for item in filtered_mitre:
        preview_rows.append({
            "Type": "MITRE",
            "Finding": item.get("finding", "-"),
            "Severity": "",
            "Risk Score": "",
            "Confidence": "",
            "Status": item.get("status", "-"),
        })

    if preview_rows:
        st.dataframe(
            pd.DataFrame(preview_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No records match the active filters.")


# ============================================================
# SETTINGS
# ============================================================

elif page == "Settings":

    st.title("Settings")
    st.caption(
        "Configure how the AI Security Copilot displays, analyses and exports security material."
    )

    st.subheader("Analysis Settings")

    c1, c2 = st.columns(2)

    with c1:
        st.checkbox(
            "Show evidence limitations",
            value=True,
            key="setting_evidence_limitations",
            help="Keep evidence gaps and telemetry limitations visible in analysis pages and exports.",
        )

        st.checkbox(
            "Show rejected MITRE candidates",
            value=True,
            key="setting_mitre_rejected",
            help="Display candidates that were evaluated but not supported by the available evidence.",
        )

    with c2:
        st.checkbox(
            "Show technical evidence",
            value=True,
            key="setting_technical_evidence",
            help="Display technical evidence tables where available.",
        )

        st.checkbox(
            "Show confidence indicators",
            value=True,
            key="setting_confidence",
            help="Display confidence values for alerts and AI assessments.",
        )

    st.divider()

    st.subheader("Export Settings")

    export_format = st.selectbox(
        "Preferred export format",
        ["PDF", "DOCX", "XLSX", "CSV", "JSON", "TXT", "Markdown"],
        index=0,
        key="setting_export_format",
    )

    st.caption(
        f"Preferred format: {export_format}. All export formats remain available from each page."
    )

    st.divider()

    st.subheader("Data & Privacy")

    st.info(
        "Uploaded security material is processed by this application for analysis. "
        "Do not upload passwords, API keys, private certificates or other secrets."
    )

    st.subheader("Supported Security Material")

    supported_display = [
        str(ext).upper()
        for ext in sorted(SUPPORTED_EXTENSIONS)
    ]

    st.write(", ".join(supported_display))

    st.caption(
        "Structured telemetry follows the network/security-data pipeline. "
        "Documents and images use document/image analysis and are not treated as network telemetry."
    )

    st.divider()

    st.subheader("Current Analysis")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("Dataset", dataset_name)

    with c2:
        st.metric("Events", f"{total_events:,}")

    with c3:
        st.metric("Findings", len(filtered_findings))

    with c4:
        st.metric("Alerts", len(filtered_alerts))

    st.divider()

    st.subheader("Analysis History")

    history = load_analysis_history()
    status = load_json(ANALYSIS_STATUS_FILE)

    c1, c2 = st.columns(2)

    with c1:
        st.metric("Total Analyses", len(history))

    with c2:
        st.metric("Last Status", status.get("status", "IDLE"))

    if history:
        settings_history_rows = []

        for item in reversed(history):
            settings_history_rows.append(
                {
                    "Run": item.get("analysis_number", "-"),
                    "Dataset": item.get("dataset_name", "-"),
                    "Started": format_timestamp(item.get("started_at")),
                    "Completed": format_timestamp(item.get("completed_at")),
                    "Duration": format_duration(item.get("duration_seconds")),
                    "Events": int(item.get("events", 0)),
                    "Findings": int(item.get("findings", 0)),
                    "Alerts": int(item.get("alerts", 0)),
                    "Mode": item.get("mode", "-"),
                }
            )

        st.dataframe(
            pd.DataFrame(settings_history_rows),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AI Security Copilot  •  "
    "Behavioural Analytics  •  "
    "MITRE ATT&CK  •  "
    "Evidence-Based Triage"
)