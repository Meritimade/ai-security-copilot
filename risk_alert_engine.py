import json
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# AI SECURITY COPILOT
# RISK & ALERT ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

EVIDENCE_FILE = BASE_DIR / "security_evidence.json"
SCHEMA_FILE = BASE_DIR / "security_schema.json"
MITRE_FILE = BASE_DIR / "MITRE" / "mitre_evaluated.json"
OUTPUT_FILE = BASE_DIR / "security_alerts.json"


# ============================================================
# SEVERITY ORDER
# ============================================================

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():

        print(
            f"[WARNING] File not found: {path.name}"
        )

        return {}

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"[ERROR] Could not load "
            f"{path.name}: {error}"
        )

        return {}


# ============================================================
# LOAD PROJECT DATA
# ============================================================

evidence = load_json(
    EVIDENCE_FILE
)

schema = load_json(
    SCHEMA_FILE
)

mitre_data = load_json(
    MITRE_FILE
)


# ============================================================
# HELPERS
# ============================================================

def safe_number(
    value,
    default=0
):

    try:

        if value is None:

            return default

        return float(value)

    except Exception:

        return default


def current_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# FINDINGS
# ============================================================

def get_findings():

    indicators = evidence.get(
        "behavioural_indicators",
        []
    )

    if isinstance(
        indicators,
        dict
    ):

        indicators = list(
            indicators.values()
        )

    if not isinstance(
        indicators,
        list
    ):

        return []

    findings = []

    for item in indicators:

        if not isinstance(
            item,
            dict
        ):

            continue

        finding = item.get(
            "finding",
            item
        )

        if not isinstance(
            finding,
            dict
        ):

            continue

        label = (
            finding.get(
                "label"
            )
            or finding.get(
                "finding"
            )
            or finding.get(
                "name"
            )
            or "Unknown"
        )

        classification = str(
            finding.get(
                "classification",
                "unknown"
            )
        ).lower()

        record_count = safe_number(
            finding.get(
                "record_count",
                finding.get(
                    "count",
                    finding.get(
                        "records",
                        0
                    )
                )
            )
        )

        percentage = safe_number(
            finding.get(
                "percentage_of_dataset",
                finding.get(
                    "percentage",
                    0
                )
            )
        )

        findings.append(
            {
                "label":
                    str(label),

                "classification":
                    classification,

                "record_count":
                    record_count,

                "percentage":
                    percentage,

                "ports":
                    finding.get(
                        "associated_destination_ports",
                        {}
                    ),

                "protocols":
                    finding.get(
                        "associated_protocols",
                        {}
                    ),

                "statistics":
                    finding.get(
                        "behavioural_statistics",
                        {}
                    ),

                "temporal":
                    finding.get(
                        "temporal_evidence",
                        {}
                    ),

                "comparative":
                    finding.get(
                        "comparative_behavioural_evidence",
                        {}
                    ),

                "limitations":
                    item.get(
                        "evidence_limitations",
                        []
                    ),
            }
        )

    return findings


# ============================================================
# MITRE EXTRACTION
# ============================================================

def collect_mitre(
    obj,
    output
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
                or "confidence" in obj
            )
        ):

            output.append(
                obj
            )

        for value in obj.values():

            collect_mitre(
                value,
                output
            )

    elif isinstance(
        obj,
        list
    ):

        for item in obj:

            collect_mitre(
                item,
                output
            )


# ============================================================
# EXTRACT RAW MITRE ASSESSMENTS
# ============================================================

mitre_items = []

collect_mitre(
    mitre_data,
    mitre_items
)


# ============================================================
# NORMALISE MITRE STATUS
# ============================================================

def normalise_mitre_status(
    item
):

    status = str(
        item.get(
            "status",
            item.get(
                "assessment",
                item.get(
                    "validation_status",
                    ""
                )
            )
        )
    ).upper()

    if "NOT_SUPPORTED" in status:

        return "NOT_SUPPORTED"

    if "POSSIBLE" in status:

        return "POSSIBLE"

    if "SUPPORTED" in status:

        return "SUPPORTED"

    return "UNKNOWN"


# ============================================================
# DEDUPLICATE MITRE ASSESSMENTS
# ============================================================

unique_mitre = {}

for item in mitre_items:

    technique_id = str(
        item.get(
            "technique_id",
            ""
        )
    )

    finding_name = str(
        item.get(
            "finding",
            item.get(
                "finding_label",
                item.get(
                    "label",
                    ""
                )
            )
        )
    )

    status = normalise_mitre_status(
        item
    )

    key = (
        finding_name,
        technique_id,
        status
    )

    unique_mitre[
        key
    ] = item


mitre_items = list(
    unique_mitre.values()
)


# ============================================================
# GROUP MITRE BY FINDING
# ============================================================

mitre_by_finding = {}


for item in mitre_items:

    finding_name = str(
        item.get(
            "finding",
            item.get(
                "finding_label",
                item.get(
                    "label",
                    ""
                )
            )
        )
    )

    if finding_name not in mitre_by_finding:

        mitre_by_finding[
            finding_name
        ] = []

    mitre_by_finding[
        finding_name
    ].append(
        item
    )


# ============================================================
# MITRE SUMMARY
# ============================================================

def get_mitre_summary(
    finding_name
):

    assessments = (
        mitre_by_finding.get(
            finding_name,
            []
        )
    )

    supported = []
    possible = []
    not_supported = []

    for item in assessments:

        status = normalise_mitre_status(
            item
        )

        if status == "SUPPORTED":

            supported.append(
                item
            )

        elif status == "POSSIBLE":

            possible.append(
                item
            )

        elif status == "NOT_SUPPORTED":

            not_supported.append(
                item
            )

    return {

        "total_assessments":
            len(assessments),

        "supported":
            len(supported),

        "possible":
            len(possible),

        "not_supported":
            len(not_supported),

        "supported_techniques": [

            {
                "id":
                    item.get(
                        "technique_id",
                        ""
                    ),

                "name":
                    item.get(
                        "technique_name",
                        item.get(
                            "name",
                            ""
                        )
                    ),

                "confidence":
                    item.get(
                        "confidence",
                        ""
                    ),
            }

            for item
            in supported
        ],

        "possible_techniques": [

            {
                "id":
                    item.get(
                        "technique_id",
                        ""
                    ),

                "name":
                    item.get(
                        "technique_name",
                        item.get(
                            "name",
                            ""
                        )
                    ),

                "confidence":
                    item.get(
                        "confidence",
                        ""
                    ),
            }

            for item
            in possible
        ],
    }


# ============================================================
# EVIDENCE SUMMARY
# ============================================================

def build_evidence_summary(
    finding
):

    evidence_items = []

    label = finding[
        "label"
    ]

    count = finding[
        "record_count"
    ]

    percentage = finding[
        "percentage"
    ]

    evidence_items.append(
        f"{label} contains "
        f"{int(count):,} records "
        f"({percentage:.2f}% of the dataset)."
    )

    # --------------------------------------------------------
    # DESTINATION PORTS
    # --------------------------------------------------------

    ports = finding[
        "ports"
    ]

    if (
        isinstance(
            ports,
            dict
        )
        and ports
    ):

        top_ports = sorted(
            ports.items(),
            key=lambda item:
                safe_number(
                    item[1]
                ),
            reverse=True
        )[:5]

        port_text = ", ".join(
            [
                f"port {port} "
                f"({int(safe_number(count)):,} records)"
                for port, count
                in top_ports
            ]
        )

        evidence_items.append(
            "Observed destination ports: "
            + port_text
            + "."
        )

    # --------------------------------------------------------
    # PROTOCOLS
    # --------------------------------------------------------

    protocols = finding[
        "protocols"
    ]

    if (
        isinstance(
            protocols,
            dict
        )
        and protocols
    ):

        top_protocols = sorted(
            protocols.items(),
            key=lambda item:
                safe_number(
                    item[1]
                ),
            reverse=True
        )[:5]

        protocol_text = ", ".join(
            [
                f"{protocol} "
                f"({int(safe_number(count)):,} records)"
                for protocol, count
                in top_protocols
            ]
        )

        evidence_items.append(
            "Observed protocols: "
            + protocol_text
            + "."
        )

    # --------------------------------------------------------
    # TEMPORAL EVIDENCE
    # --------------------------------------------------------

    temporal = finding[
        "temporal"
    ]

    if isinstance(
        temporal,
        dict
    ):

        start = (
            temporal.get(
                "earliest_timestamp"
            )
            or temporal.get(
                "start"
            )
            or temporal.get(
                "minimum_timestamp"
            )
        )

        end = (
            temporal.get(
                "latest_timestamp"
            )
            or temporal.get(
                "end"
            )
            or temporal.get(
                "maximum_timestamp"
            )
        )

        if start and end:

            evidence_items.append(
                f"Observed activity window: "
                f"{start} to {end}."
            )

    return evidence_items


# ============================================================
# EVIDENCE GAPS
# ============================================================

def build_evidence_gaps(
    finding
):

    gaps = []

    limitations = finding[
        "limitations"
    ]

    if isinstance(
        limitations,
        list
    ):

        for limitation in limitations:

            text = str(
                limitation
            ).strip()

            if (
                text
                and text not in gaps
            ):

                gaps.append(
                    text
                )

    # --------------------------------------------------------
    # ADD IMPORTANT TELEMETRY GAPS
    # --------------------------------------------------------

    gap_text = " ".join(
        gaps
    ).lower()

    if (
        "source" not in gap_text
        and "identity" not in gap_text
    ):

        gaps.append(
            "Source identity is not available "
            "for direct correlation."
        )

    if (
        "authentication"
        not in gap_text
    ):

        gaps.append(
            "Authentication attempts and "
            "success/failure outcomes are not "
            "available in the current telemetry."
        )

    if (
        "user" not in gap_text
    ):

        gaps.append(
            "User or account identity is not available."
        )

    if (
        "process" not in gap_text
    ):

        gaps.append(
            "Endpoint process information is not available."
        )

    return list(
        dict.fromkeys(
            gaps
        )
    )


# ============================================================
# INVESTIGATION STEPS
# ============================================================

def build_investigation_steps(
    finding,
    mitre
):

    steps = []

    label = finding[
        "label"
    ]

    steps.append(
        f"Review the original telemetry "
        f"associated with {label}."
    )

    steps.append(
        "Identify source and destination "
        "systems using available network, "
        "asset and endpoint telemetry."
    )

    steps.append(
        "Correlate the activity with "
        "authentication, endpoint and "
        "application logs."
    )

    if mitre[
        "possible"
    ] > 0:

        steps.append(
            "Investigate the MITRE ATT&CK "
            "techniques classified as possible "
            "and seek independent supporting evidence."
        )

    if mitre[
        "supported"
    ] > 0:

        steps.append(
            "Validate supported MITRE techniques "
            "against additional independent telemetry."
        )

    steps.append(
        "Determine whether the activity is "
        "expected, authorised or anomalous "
        "for the affected environment."
    )

    return steps


# ============================================================
# DEFENSIVE ACTIONS
# ============================================================

def build_defensive_actions(
    finding,
    severity
):

    actions = []

    classification = finding[
        "classification"
    ]

    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    if classification == "benign":

        actions.append(
            "Maintain the observed behaviour "
            "as part of the established baseline."
        )

        actions.append(
            "Continue monitoring for deviations "
            "from the current behavioural baseline."
        )

        return actions

    # --------------------------------------------------------
    # GENERAL SECURITY ACTIONS
    # --------------------------------------------------------

    actions.append(
        "Correlate the finding with "
        "authentication and endpoint telemetry."
    )

    actions.append(
        "Verify that the destination service "
        "is expected and authorised."
    )

    actions.append(
        "Validate affected assets and their "
        "normal communication patterns."
    )

    actions.append(
        "Apply appropriate access controls "
        "and network segmentation where required."
    )

    actions.append(
        "Continue monitoring for repeated "
        "or escalating activity."
    )

    if severity in [
        "High",
        "Critical"
    ]:

        actions.append(
            "Escalate for SOC investigation "
            "according to organisational "
            "incident response procedures."
        )

    return actions


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(
    finding,
    mitre
):

    classification = finding[
        "classification"
    ]

    percentage = finding[
        "percentage"
    ]

    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    if classification == "benign":

        return {

            "score":
                0,

            "severity":
                "Informational",

            "confidence":
                "High",
        }

    # --------------------------------------------------------
    # BASE SCORE
    # --------------------------------------------------------

    score = 20

    # --------------------------------------------------------
    # PREVALENCE
    # --------------------------------------------------------

    if percentage >= 25:

        score += 20

    elif percentage >= 15:

        score += 15

    elif percentage >= 10:

        score += 10

    elif percentage >= 5:

        score += 5

    # --------------------------------------------------------
    # MITRE SUPPORT
    # --------------------------------------------------------

    if mitre[
        "supported"
    ] > 0:

        score += 35

    elif mitre[
        "possible"
    ] > 0:

        score += 15

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    if mitre[
        "supported"
    ] > 0:

        confidence = "High"

    elif mitre[
        "possible"
    ] > 0:

        confidence = "Medium"

    else:

        confidence = "Low"

    # --------------------------------------------------------
    # LIMIT
    # --------------------------------------------------------

    score = min(
        score,
        100
    )

    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    if score >= 80:

        severity = "Critical"

    elif score >= 60:

        severity = "High"

    elif score >= 35:

        severity = "Medium"

    else:

        severity = "Low"

    return {

        "score":
            score,

        "severity":
            severity,

        "confidence":
            confidence,
    }


# ============================================================
# GENERATE ALERTS
# ============================================================

def generate_alerts(
    findings
):

    alerts = []

    alert_number = 1

    for finding in findings:

        label = finding[
            "label"
        ]

        mitre = get_mitre_summary(
            label
        )

        risk = calculate_risk(
            finding,
            mitre
        )

        severity = risk[
            "severity"
        ]

        classification = finding[
            "classification"
        ]

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        if classification == "benign":

            status = "Baseline"

        elif severity in [
            "Critical",
            "High"
        ]:

            status = "Open"

        else:

            status = "Needs Investigation"

        # ----------------------------------------------------
        # BUILD SUPPORTING INFORMATION
        # ----------------------------------------------------

        evidence_summary = (
            build_evidence_summary(
                finding
            )
        )

        evidence_gaps = (
            build_evidence_gaps(
                finding
            )
        )

        investigation_steps = (
            build_investigation_steps(
                finding,
                mitre
            )
        )

        defensive_actions = (
            build_defensive_actions(
                finding,
                severity
            )
        )

        # ----------------------------------------------------
        # ALERT OBJECT
        # ----------------------------------------------------

        alert = {

            "alert_id":
                f"ASC-{alert_number:04d}",

            "finding":
                label,

            "classification":
                classification,

            "severity":
                severity,

            "risk_score":
                risk["score"],

            "status":
                status,

            "confidence":
                risk["confidence"],

            "record_count":
                int(
                    finding[
                        "record_count"
                    ]
                ),

            "dataset_percentage":
                round(
                    finding[
                        "percentage"
                    ],
                    4
                ),

            "evidence":
                evidence_summary,

            "evidence_gaps":
                evidence_gaps,

            "mitre_assessment":
                mitre,

            "investigation_steps":
                investigation_steps,

            "defensive_actions":
                defensive_actions,

            "generated_at":
                current_timestamp(),

        }

        alerts.append(
            alert
        )

        alert_number += 1

    return alerts


# ============================================================
# MAIN EXECUTION
# ============================================================

print()

print(
    "=" * 60
)

print(
    "AI SECURITY COPILOT - RISK & ALERT ENGINE"
)

print(
    "=" * 60
)

dataset_mode = evidence.get(
    "dataset_mode",
    "UNKNOWN"
)

# IMPORTANT:
# Dataset type is taken from the authoritative
# security_schema.json rather than evidence JSON.

dataset_type = schema.get(
    "dataset_type",
    evidence.get(
        "dataset_type",
        "unknown"
    )
)

print(
    f"Dataset mode: {dataset_mode}"
)

print(
    f"Dataset type: {dataset_type}"
)

print()

# ------------------------------------------------------------
# FINDINGS
# ------------------------------------------------------------

findings = get_findings()

print(
    f"Security findings discovered: "
    f"{len(findings)}"
)

# ------------------------------------------------------------
# MITRE
# ------------------------------------------------------------

print(
    f"MITRE assessments loaded: "
    f"{len(mitre_items)}"
)

print()

# ------------------------------------------------------------
# ALERTS
# ------------------------------------------------------------

print(
    "Generating security alerts..."
)

alerts = generate_alerts(
    findings
)


# ============================================================
# SEVERITY SUMMARY
# ============================================================

severity_summary = {
    severity: 0
    for severity
    in SEVERITY_ORDER
}


for alert in alerts:

    severity_summary[
        alert[
            "severity"
        ]
    ] += 1


# ============================================================
# OUTPUT OBJECT
# ============================================================

output = {

    "generated_at":
        current_timestamp(),

    "dataset_mode":
        dataset_mode,

    "dataset_type":
        dataset_type,

    "total_alerts":
        len(alerts),

    "severity_summary":
        severity_summary,

    "alerts":
        alerts,

    "methodology": {

        "description":
            "Risk and alert prioritisation "
            "uses behavioural evidence, "
            "dataset prevalence and validated "
            "MITRE ATT&CK assessment.",

        "risk_score":
            "Risk scores are analytical "
            "prioritisation values and should "
            "not be interpreted as definitive "
            "measures of compromise.",

        "benign_handling":
            "Benign findings are represented "
            "as informational baseline events "
            "rather than active threats.",

        "mitre_handling":
            "MITRE candidate retrieval is "
            "contextual. Possible techniques "
            "are not treated as confirmed.",

        "evidence_handling":
            "Evidence gaps are retained in "
            "each alert so analysts can see "
            "what telemetry is unavailable.",

        "dataset_type_source":
            "security_schema.json",

    },
}


# ============================================================
# WRITE OUTPUT
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        output,
        file,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# CONSOLE SUMMARY
# ============================================================

print()

print(
    "=" * 60
)

print(
    "RISK & ALERT ENGINE COMPLETE"
)

print(
    "=" * 60
)

print(
    f"Alerts generated: "
    f"{len(alerts)}"
)

for severity in SEVERITY_ORDER:

    print(
        f"{severity}: "
        f"{severity_summary[severity]}"
    )

print()

for alert in alerts:

    print(
        f"[{alert['severity']}] "
        f"{alert['alert_id']} | "
        f"{alert['finding']} | "
        f"Risk score: "
        f"{alert['risk_score']} | "
        f"Status: "
        f"{alert['status']} | "
        f"Confidence: "
        f"{alert['confidence']}"
    )

print()

print(
    f"Output: "
    f"{OUTPUT_FILE}"
)

print()