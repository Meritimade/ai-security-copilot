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
# RISK MODEL VERSION
# ============================================================

RISK_MODEL_VERSION = "2.0"

MAX_SCORE = 100


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


def clamp(
    value,
    minimum=0,
    maximum=100
):

    return max(
        minimum,
        min(
            maximum,
            value
        )
    )


def current_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


def normalise_text(value):

    return str(
        value
        if value is not None
        else ""
    ).strip()


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
# MITRE STATUS
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
# EXTRACT MITRE ASSESSMENTS
# ============================================================

mitre_items = []

collect_mitre(
    mitre_data,
    mitre_items
)


# ============================================================
# DEDUPLICATE MITRE
# ============================================================

unique_mitre = {}

for item in mitre_items:

    technique_id = normalise_text(
        item.get(
            "technique_id",
            ""
        )
    )

    finding_name = normalise_text(
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

    finding_name = normalise_text(
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

        total_port_records = sum(
            safe_number(
                count
            )
            for _, count
            in ports.items()
        )

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

        if total_port_records > 0:

            top_port_count = safe_number(
                top_ports[0][1]
            )

            top_port_share = (
                top_port_count
                / total_port_records
            ) * 100

            evidence_items.append(
                f"The dominant destination port "
                f"accounts for approximately "
                f"{top_port_share:.2f}% of the "
                f"finding's port-attributed records."
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
# RISK MODEL
# ============================================================

def calculate_prevalence_component(
    percentage
):

    """
    Maximum: 15 points.

    This measures how much of the analysed
    dataset is represented by the finding.

    It does NOT mean that a larger percentage
    automatically means malicious behaviour.
    """

    percentage = max(
        0,
        percentage
    )

    if percentage >= 50:
        score = 15

    elif percentage >= 25:
        score = 12

    elif percentage >= 10:
        score = 9

    elif percentage >= 5:
        score = 6

    elif percentage >= 1:
        score = 3

    else:
        score = 1

    return {
        "score": score,
        "maximum": 15,
        "percentage": round(
            percentage,
            4
        ),
        "reason":
            "Finding prevalence within the analysed dataset."
    }


def calculate_port_concentration_component(
    finding
):

    """
    Maximum: 15 points.

    Measures concentration of observed
    destination-port activity.

    Concentration is treated as a behavioural
    signal, not proof of malicious activity.
    """

    ports = finding[
        "ports"
    ]

    if not isinstance(
        ports,
        dict
    ) or not ports:

        return {
            "score": 0,
            "maximum": 15,
            "top_port": None,
            "top_port_share": 0,
            "reason":
                "Destination-port distribution unavailable."
        }

    values = []

    for port, count in ports.items():

        numeric_count = safe_number(
            count
        )

        if numeric_count > 0:

            values.append(
                (
                    str(port),
                    numeric_count
                )
            )

    if not values:

        return {
            "score": 0,
            "maximum": 15,
            "top_port": None,
            "top_port_share": 0,
            "reason":
                "No usable destination-port counts."
        }

    total = sum(
        count
        for _, count
        in values
    )

    top_port, top_count = max(
        values,
        key=lambda x: x[1]
    )

    share = (
        top_count / total
    ) * 100

    if share >= 99:
        score = 15

    elif share >= 90:
        score = 12

    elif share >= 75:
        score = 9

    elif share >= 50:
        score = 6

    elif share >= 25:
        score = 3

    else:
        score = 1

    return {
        "score": score,
        "maximum": 15,
        "top_port": top_port,
        "top_port_share": round(
            share,
            4
        ),
        "reason":
            "Concentration of destination-port activity."
    }


def calculate_protocol_concentration_component(
    finding
):

    """
    Maximum: 10 points.

    Measures concentration of observed
    protocol values.
    """

    protocols = finding[
        "protocols"
    ]

    if not isinstance(
        protocols,
        dict
    ) or not protocols:

        return {
            "score": 0,
            "maximum": 10,
            "top_protocol": None,
            "top_protocol_share": 0,
            "reason":
                "Protocol distribution unavailable."
        }

    values = []

    for protocol, count in protocols.items():

        numeric_count = safe_number(
            count
        )

        if numeric_count > 0:

            values.append(
                (
                    str(protocol),
                    numeric_count
                )
            )

    if not values:

        return {
            "score": 0,
            "maximum": 10,
            "top_protocol": None,
            "top_protocol_share": 0,
            "reason":
                "No usable protocol counts."
        }

    total = sum(
        count
        for _, count
        in values
    )

    top_protocol, top_count = max(
        values,
        key=lambda x: x[1]
    )

    share = (
        top_count / total
    ) * 100

    if share >= 99:
        score = 10

    elif share >= 90:
        score = 8

    elif share >= 75:
        score = 6

    elif share >= 50:
        score = 4

    elif share >= 25:
        score = 2

    else:
        score = 1

    return {
        "score": score,
        "maximum": 10,
        "top_protocol": top_protocol,
        "top_protocol_share": round(
            share,
            4
        ),
        "reason":
            "Concentration of protocol activity."
    }


def calculate_temporal_component(
    finding
):

    """
    Maximum: 10 points.

    Temporal concentration is based on the
    presence of a peak period/hour in the
    supplied evidence.

    It is a prioritisation signal only.
    """

    temporal = finding[
        "temporal"
    ]

    if not isinstance(
        temporal,
        dict
    ):

        return {
            "score": 0,
            "maximum": 10,
            "peak_share": None,
            "reason":
                "Temporal evidence unavailable."
        }

    peak_share = None

    candidate_keys = [
        "peak_hour_percentage",
        "peak_period_percentage",
        "peak_percentage",
        "peak_share",
        "peak_hour_share"
    ]

    for key in candidate_keys:

        if key in temporal:

            value = safe_number(
                temporal.get(
                    key
                ),
                None
            )

            if value is not None:

                peak_share = value

                break

    if peak_share is None:

        return {
            "score": 2,
            "maximum": 10,
            "peak_share": None,
            "reason":
                "Temporal window is available, "
                "but peak-period share is not explicitly supplied."
        }

    if peak_share >= 75:
        score = 10

    elif peak_share >= 60:
        score = 8

    elif peak_share >= 40:
        score = 6

    elif peak_share >= 25:
        score = 4

    elif peak_share >= 10:
        score = 2

    else:
        score = 1

    return {
        "score": score,
        "maximum": 10,
        "peak_share": round(
            peak_share,
            4
        ),
        "reason":
            "Concentration of observed activity within a peak period."
    }


def calculate_mitre_component(
    mitre
):

    """
    Maximum: 25 points.

    Only evidence validation affects this
    component.

    SUPPORTED = stronger validated evidence.
    POSSIBLE = evidence is consistent but not confirmed.
    NOT_SUPPORTED = no contribution.
    """

    supported = int(
        mitre.get(
            "supported",
            0
        )
    )

    possible = int(
        mitre.get(
            "possible",
            0
        )
    )

    if supported > 0:

        score = 25

        reason = (
            f"{supported} MITRE technique(s) "
            "were assessed as SUPPORTED by the "
            "evidence-validation stage."
        )

    elif possible > 0:

        score = 10

        reason = (
            f"{possible} MITRE technique(s) "
            "were assessed as POSSIBLE. "
            "Possible techniques are not treated "
            "as confirmed."
        )

    else:

        score = 0

        reason = (
            "No MITRE technique was validated "
            "as supported or possible."
        )

    return {
        "score": score,
        "maximum": 25,
        "supported": supported,
        "possible": possible,
        "reason": reason
    }


# ============================================================
# EVIDENCE CONFIDENCE
# ============================================================

def calculate_confidence(
    finding,
    mitre
):

    """
    Confidence is separate from risk.

    More telemetry does not automatically increase
    risk. It can, however, increase confidence in
    the analytical assessment.
    """

    classification = finding[
        "classification"
    ]

    limitations = finding[
        "limitations"
    ]

    if not isinstance(
        limitations,
        list
    ):

        limitations = []

    limitation_count = len(
        [
            item
            for item
            in limitations
            if str(item).strip()
        ]
    )

    supported = mitre[
        "supported"
    ]

    possible = mitre[
        "possible"
    ]

    if classification == "benign":

        return "High"

    if supported > 0:

        if limitation_count <= 3:
            return "High"

        return "Medium"

    if possible > 0:

        if limitation_count <= 3:
            return "Medium"

        return "Low"

    return "Low"


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

            "model_version":
                RISK_MODEL_VERSION,

            "components": {},

            "baseline":
                {
                    "type":
                        "labelled_baseline",

                    "description":
                        "The finding is classified as benign "
                        "by the supplied dataset evidence. "
                        "It is displayed as a baseline reference "
                        "and does not contribute threat risk."
                },

            "interpretation":
                "Informational baseline activity."
        }

    # --------------------------------------------------------
    # COMPONENTS
    # --------------------------------------------------------

    prevalence = (
        calculate_prevalence_component(
            finding[
                "percentage"
            ]
        )
    )

    port_concentration = (
        calculate_port_concentration_component(
            finding
        )
    )

    protocol_concentration = (
        calculate_protocol_concentration_component(
            finding
        )
    )

    temporal = (
        calculate_temporal_component(
            finding
        )
    )

    mitre_component = (
        calculate_mitre_component(
            mitre
        )
    )

    # --------------------------------------------------------
    # TOTAL
    # --------------------------------------------------------

    score = (
        prevalence["score"]
        + port_concentration["score"]
        + protocol_concentration["score"]
        + temporal["score"]
        + mitre_component["score"]
    )

    score = int(
        round(
            clamp(
                score,
                0,
                MAX_SCORE
            )
        )
    )

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    confidence = calculate_confidence(
        finding,
        mitre
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

    elif score >= 15:

        severity = "Low"

    else:

        severity = "Informational"

    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    return {

        "score":
            score,

        "severity":
            severity,

        "confidence":
            confidence,

        "model_version":
            RISK_MODEL_VERSION,

        "components": {

            "prevalence": prevalence,

            "destination_port_concentration":
                port_concentration,

            "protocol_concentration":
                protocol_concentration,

            "temporal_concentration":
                temporal,

            "mitre_validation":
                mitre_component,
        },

        "maximum_possible_score":
            MAX_SCORE,

        "baseline":
            {
                "type":
                    "behavioural_prioritisation",

                "description":
                    "The score is calculated from observed "
                    "characteristics of the finding and "
                    "validated MITRE evidence. It is not "
                    "a probability of compromise and does "
                    "not use a fixed attack-specific score."
            },

        "interpretation":
            "Analytical prioritisation score requiring "
            "analyst investigation and contextual validation."
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
        # SUPPORTING INFORMATION
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

            "risk_model_version":
                risk[
                    "model_version"
                ],

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

            "risk_calculation":
                risk,

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
# METHODOLOGY
# ============================================================

methodology = {

    "risk_model_version":
        RISK_MODEL_VERSION,

    "score_range":
        "0-100",

    "score_type":
        "Analytical prioritisation score",

    "not_probability":
        True,

    "description":
        "Risk is prioritised using observed "
        "behavioural characteristics and independently "
        "validated MITRE ATT&CK evidence.",

    "components": {

        "prevalence":
            {
                "maximum":
                    15,

                "description":
                    "Measures how much of the analysed "
                    "dataset is represented by the finding."
            },

        "destination_port_concentration":
            {
                "maximum":
                    15,

                "description":
                    "Measures concentration of destination-port "
                    "activity within the finding."
            },

        "protocol_concentration":
            {
                "maximum":
                    10,

                "description":
                    "Measures concentration of protocol activity "
                    "within the finding."
            },

        "temporal_concentration":
            {
                "maximum":
                    10,

                "description":
                    "Measures concentration of activity within "
                    "an observed peak period when supplied."
            },

        "mitre_validation":
            {
                "maximum":
                    25,

                "supported":
                    25,

                "possible":
                    10,

                "not_supported":
                    0,

                "description":
                    "Only evidence-validation results contribute "
                    "to the MITRE component. Candidate retrieval "
                    "alone does not increase risk."
            },
    },

    "maximum_component_score":
        75,

    "score_note":
        "The currently defined evidence components have a "
        "maximum of 75 points. The remaining score range is "
        "intentionally unused rather than filled with an "
        "arbitrary base score.",

    "baseline_policy":
        "There is no universal fixed threat baseline. "
        "Labelled benign activity is treated as a dataset "
        "baseline reference. Non-benign findings are "
        "prioritised from their observed characteristics "
        "and validated evidence.",

    "label_policy":
        "Dataset labels are contextual evidence and are not "
        "treated as independent proof of malicious behaviour.",

    "mitre_policy":
        "POSSIBLE is not treated as SUPPORTED. "
        "NOT_SUPPORTED candidates contribute zero risk.",

    "confidence_policy":
        "Confidence is reported separately from risk severity. "
        "A high-risk score with low confidence means the "
        "activity should be investigated but the available "
        "evidence is insufficient for strong attribution or "
        "confirmation.",

    "evidence_policy":
        "Missing telemetry reduces confidence and limits "
        "interpretation. Missing telemetry is not converted "
        "into positive evidence.",

    "analyst_use":
        "Scores support triage and prioritisation only. "
        "They do not establish compromise, attacker intent, "
        "successful authentication, persistence, lateral "
        "movement or impact."
}


# ============================================================
# OUTPUT OBJECT
# ============================================================

output = {

    "generated_at":
        current_timestamp(),

    "risk_model_version":
        RISK_MODEL_VERSION,

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

    "methodology":
        methodology,
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
    f"Risk model version: "
    f"{RISK_MODEL_VERSION}"
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

    calculation = alert.get(
        "risk_calculation",
        {}
    )

    components = calculation.get(
        "components",
        {}
    )

    if components:

        print(
            "  Risk calculation:"
        )

        for name, component in components.items():

            if not isinstance(
                component,
                dict
            ):

                continue

            print(
                f"    - {name}: "
                f"{component.get('score', 0)}/"
                f"{component.get('maximum', 0)}"
            )

print()

print(
    f"Output: "
    f"{OUTPUT_FILE}"
)

print()