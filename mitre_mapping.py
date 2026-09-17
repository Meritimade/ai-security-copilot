import json
import os
import re
from pathlib import Path

import numpy as np
from dotenv import load_dotenv
from openai import OpenAI


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

EVIDENCE_FILE = BASE_DIR / "security_evidence.json"
SCHEMA_FILE = BASE_DIR / "security_schema.json"
MITRE_INDEX_FILE = BASE_DIR / "MITRE" / "mitre_technique_index.json"
EMBEDDING_FILE = BASE_DIR / "MITRE" / "mitre_embeddings.npz"
OUTPUT_FILE = BASE_DIR / "MITRE" / "mitre_candidates.json"

TOP_K = 30
BROAD_POOL_SIZE = 100

EMBEDDING_MODEL = "text-embedding-3-small"

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError(
        "OPENAI_API_KEY was not found in the environment."
    )

client = OpenAI(api_key=api_key)


# ============================================================
# FILE HELPERS
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# TEXT HELPERS
# ============================================================

def normalise_text(value):
    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        return " ".join(
            str(x)
            for x in value
        ).lower()

    if isinstance(value, dict):
        return " ".join(
            f"{key} {value}"
            for key, value in value.items()
        ).lower()

    return str(value).lower()


def tokenize(text):

    text = normalise_text(text)

    tokens = re.findall(
        r"[a-zA-Z0-9_]+",
        text
    )

    stop_words = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "into",
        "over",
        "using",
        "used",
        "were",
        "was",
        "are",
        "has",
        "have",
        "had",
        "record",
        "records",
        "dataset",
        "finding",
        "attack",
        "activity",
        "evidence",
        "observed",
        "observation",
        "possible",
        "potential",
        "network",
        "flow",
        "flows",
        "traffic",
        "information",
    }

    return {
        token
        for token in tokens
        if len(token) >= 3
        and token not in stop_words
    }


# ============================================================
# LABELLED FINDING TEXT
# ============================================================

def build_finding_text(finding):

    parts = []

    finding_data = finding.get(
        "finding",
        {}
    )

    for key in [
        "label",
        "classification",
        "record_count",
        "percentage_of_dataset",
    ]:

        if key in finding_data:

            parts.append(
                f"{key}: {finding_data[key]}"
            )

    ports = finding_data.get(
        "associated_destination_ports",
        {}
    )

    if ports:

        parts.append("destination ports:")

        for port, count in list(
            ports.items()
        )[:20]:

            parts.append(
                f"port {port}: {count} records"
            )

    protocols = finding_data.get(
        "associated_protocols",
        {}
    )

    if protocols:

        parts.append("protocols:")

        for protocol, count in list(
            protocols.items()
        )[:20]:

            parts.append(
                f"protocol {protocol}: {count} records"
            )

    behavioural = finding_data.get(
        "behavioural_statistics",
        {}
    )

    if behavioural:

        parts.append(
            "behavioural statistics:"
        )

        for field, stats in behavioural.items():

            if isinstance(stats, dict):

                selected_values = []

                for stat_name in [
                    "mean",
                    "median",
                    "min",
                    "max",
                    "p95",
                    "p99",
                    "unique_values",
                ]:

                    if stat_name in stats:

                        selected_values.append(
                            f"{stat_name}="
                            f"{stats[stat_name]}"
                        )

                if selected_values:

                    parts.append(
                        f"{field}: "
                        + ", ".join(
                            selected_values
                        )
                    )

            else:

                parts.append(
                    f"{field}: {stats}"
                )

    temporal = finding_data.get(
        "temporal_evidence",
        {}
    )

    if temporal:

        parts.append(
            "temporal evidence:"
        )

        for key, value in temporal.items():

            if isinstance(
                value,
                (dict, list)
            ):
                continue

            parts.append(
                f"{key}: {value}"
            )

    comparative = finding_data.get(
        "comparative_behavioural_evidence",
        {}
    )

    if comparative:

        parts.append(
            "comparative behavioural evidence:"
        )

        for key, value in comparative.items():

            if isinstance(value, dict):

                for sub_key, sub_value in value.items():

                    parts.append(
                        f"{key} "
                        f"{sub_key}: "
                        f"{sub_value}"
                    )

            elif isinstance(value, list):

                parts.append(
                    f"{key}: "
                    f"{', '.join(map(str, value))}"
                )

            else:

                parts.append(
                    f"{key}: {value}"
                )

    limitations = finding.get(
        "evidence_limitations",
        []
    )

    if limitations:

        parts.append(
            "evidence limitations:"
        )

        for limitation in limitations:

            parts.append(
                str(limitation)
            )

    return "\n".join(parts)


# ============================================================
# UNLABELLED BEHAVIOURAL PROFILE
# ============================================================

def build_unlabelled_profile(
    evidence_package
):

    indicators = evidence_package.get(
        "generic_behavioural_indicators",
        []
    )

    if not indicators:
        return None

    parts = [
        "Dataset mode: UNLABELLED",
        "Dataset type: network_flow",
        "",
        "Security evidence consists of "
        "telemetry-derived behavioural indicators.",
        "",
        "No attack label is available.",
        "No attack type is assumed.",
        "The observations are hypotheses for "
        "further ATT&CK investigation only.",
        "",
        "Generic behavioural indicators:"
    ]

    for number, indicator in enumerate(
        indicators,
        start=1
    ):

        indicator_type = indicator.get(
            "indicator_type",
            "unknown"
        )

        field = indicator.get(
            "field",
            "unknown"
        )

        column = indicator.get(
            "column",
            "unknown"
        )

        description = indicator.get(
            "description",
            ""
        )

        parts.append(
            f"{number}. "
            f"indicator_type={indicator_type}; "
            f"field={field}; "
            f"column={column}; "
            f"{description}"
        )

        # Include useful numerical evidence.
        for key in [
            "mean",
            "median",
            "mean_to_median_ratio",
            "p95",
            "p99",
            "maximum",
            "maximum_to_p99_ratio",
            "unique_values",
            "dominant_share",
        ]:

            if key in indicator:

                parts.append(
                    f"   {key}="
                    f"{indicator[key]}"
                )

    limitations = evidence_package.get(
        "evidence_limitations",
        []
    )

    if limitations:

        parts.append("")
        parts.append(
            "Evidence limitations:"
        )

        for limitation in limitations:

            parts.append(
                f"- {limitation}"
            )

    parts.append("")
    parts.append(
        "Important interpretation rule: "
        "behavioural anomalies are observations, "
        "not confirmed ATT&CK techniques."
    )

    return "\n".join(parts)


# ============================================================
# MITRE TECHNIQUE TEXT
# ============================================================

def build_technique_text(technique):

    parts = [
        technique.get(
            "technique_id",
            ""
        ),
        technique.get(
            "technique_name",
            ""
        ),
        technique.get(
            "description",
            ""
        ),
    ]

    tactics = technique.get(
        "tactics",
        []
    )

    if tactics:

        parts.append(
            "tactics: "
            + ", ".join(tactics)
        )

    platforms = technique.get(
        "platforms",
        []
    )

    if platforms:

        parts.append(
            "platforms: "
            + ", ".join(platforms)
        )

    return "\n".join(
        str(part)
        for part in parts
        if part
    )


# ============================================================
# TOKEN OVERLAP
# ============================================================

def calculate_token_overlap(
    finding_text,
    technique_text
):

    finding_tokens = tokenize(
        finding_text
    )

    technique_tokens = tokenize(
        technique_text
    )

    if (
        not finding_tokens
        or not technique_tokens
    ):
        return 0.0

    overlap = (
        finding_tokens
        .intersection(technique_tokens)
    )

    return (
        len(overlap)
        / len(technique_tokens)
    )


# ============================================================
# START
# ============================================================

print("=" * 70)
print("MITRE ATT&CK CANDIDATE RETRIEVAL")
print("=" * 70)


# ============================================================
# REQUIRED FILES
# ============================================================

required_files = [
    EVIDENCE_FILE,
    MITRE_INDEX_FILE,
    EMBEDDING_FILE,
]

for file_path in required_files:

    if not file_path.exists():

        raise FileNotFoundError(
            f"Required file not found:\n"
            f"{file_path}"
        )


# ============================================================
# LOAD EVIDENCE
# ============================================================

evidence_package = load_json(
    EVIDENCE_FILE
)


# ============================================================
# LOAD SCHEMA
# ============================================================

dataset_type = "unknown"

if SCHEMA_FILE.exists():

    schema_package = load_json(
        SCHEMA_FILE
    )

    dataset_type = schema_package.get(
        "dataset_type",
        "unknown"
    )


dataset_mode = evidence_package.get(
    "dataset_mode",
    "UNKNOWN"
)


print(
    f"Dataset mode: {dataset_mode}"
)

print(
    f"Dataset type: {dataset_type}"
)


# ============================================================
# LOAD MITRE INDEX
# ============================================================

mitre_index = load_json(
    MITRE_INDEX_FILE
)

print(
    f"MITRE techniques available: "
    f"{len(mitre_index)}"
)


# ============================================================
# BUILD ELIGIBLE SECURITY EVIDENCE
# ============================================================

eligible_findings = []


# ------------------------------------------------------------
# MODE 1: LABELLED DATA
# ------------------------------------------------------------

if dataset_mode.upper() == "LABELLED":

    behavioural_indicators = evidence_package.get(
        "behavioural_indicators",
        []
    )

    for item in behavioural_indicators:

        finding = item.get(
            "finding",
            {}
        )

        classification = str(
            finding.get(
                "classification",
                ""
            )
        ).lower()

        if classification in {
            "attack",
            "potential_anomaly",
        }:

            eligible_findings.append(
                item
            )


    # Fallback to high-level findings.

    if not eligible_findings:

        for finding in evidence_package.get(
            "findings",
            []
        ):

            classification = str(
                finding.get(
                    "classification",
                    ""
                )
            ).lower()

            if classification in {
                "attack",
                "potential_anomaly",
            }:

                eligible_findings.append(
                    {
                        "finding": finding,
                        "evidence_limitations": []
                    }
                )


# ------------------------------------------------------------
# MODE 2: UNLABELLED DATA
# ------------------------------------------------------------

elif dataset_mode.upper() == "UNLABELLED":

    profile_text = build_unlabelled_profile(
        evidence_package
    )

    if profile_text:

        indicators = evidence_package.get(
            "generic_behavioural_indicators",
            []
        )

        eligible_findings.append(
            {
                "finding": {

                    "finding_id": (
                        "unlabelled_behavioural_profile"
                    ),

                    "finding_type": (
                        "generic_behavioural_profile"
                    ),

                    "classification": (
                        "potential_anomaly"
                    ),

                    "label": (
                        "Unlabelled behavioural anomaly profile"
                    ),

                    "indicator_count": len(
                        indicators
                    ),

                    "description": (
                        "A telemetry-derived behavioural "
                        "profile containing statistical, "
                        "categorical and temporal indicators. "
                        "No attack type is assumed."
                    )
                },

                "profile_text": profile_text,

                "generic_behavioural_indicators": indicators,

                "evidence_limitations": (
                    evidence_package.get(
                        "evidence_limitations",
                        []
                    )
                )
            }
        )


print(
    f"Findings eligible for MITRE retrieval: "
    f"{len(eligible_findings)}"
)


# ============================================================
# NO ELIGIBLE EVIDENCE
# ============================================================

if not eligible_findings:

    output = {

        "version": "4.0",

        "dataset_mode": dataset_mode,

        "dataset_type": dataset_type,

        "mitre_techniques_available": len(
            mitre_index
        ),

        "findings_processed": 0,

        "retrieval_configuration": {

            "candidate_pool_size": TOP_K,

            "broad_initial_pool": BROAD_POOL_SIZE,

            "primary_signal": (
                "semantic_similarity"
            ),

            "secondary_signal": (
                "structured_evidence_token_overlap"
            ),

            "validation_required": True
        },

        "findings": []
    }

    save_json(
        OUTPUT_FILE,
        output
    )

    print(
        "\nNo eligible security evidence "
        "was available for MITRE retrieval."
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    raise SystemExit(0)


# ============================================================
# LOAD MITRE EMBEDDINGS
# ============================================================

embedding_data = np.load(
    EMBEDDING_FILE,
    allow_pickle=True
)

cached_embeddings = embedding_data[
    "embeddings"
]

cached_ids = [
    str(x)
    for x in embedding_data[
        "technique_ids"
    ]
]


print(
    f"MITRE embedding vectors loaded: "
    f"{len(cached_embeddings)}"
)


# ============================================================
# MITRE LOOKUP
# ============================================================

mitre_lookup = {

    str(item["technique_id"]): item

    for item in mitre_index
}


# ============================================================
# VALIDATE EMBEDDING CACHE
# ============================================================

valid_positions = []

for index, technique_id in enumerate(
    cached_ids
):

    if technique_id in mitre_lookup:

        valid_positions.append(
            index
        )


if not valid_positions:

    raise RuntimeError(
        "No valid MITRE technique IDs were "
        "found in the embedding cache."
    )


cached_embeddings = (
    cached_embeddings[
        valid_positions
    ]
)

cached_ids = [
    cached_ids[index]
    for index in valid_positions
]


print(
    f"Valid cached MITRE techniques: "
    f"{len(cached_ids)}"
)


# ============================================================
# NORMALISE MITRE EMBEDDINGS
# ============================================================

embedding_norms = np.linalg.norm(
    cached_embeddings,
    axis=1,
    keepdims=True
)

embedding_norms[
    embedding_norms == 0
] = 1


normalised_embeddings = (
    cached_embeddings
    / embedding_norms
)


# ============================================================
# PROCESS EVIDENCE
# ============================================================

all_results = []


for finding_number, finding_item in enumerate(
    eligible_findings,
    start=1
):

    finding = finding_item.get(
        "finding",
        {}
    )

    label = finding.get(
        "label",
        "Unknown"
    )

    classification = finding.get(
        "classification",
        "Unknown"
    )


    print("\n" + "-" * 70)

    print(
        f"Finding {finding_number}: "
        f"{label}"
    )

    print(
        f"Classification: "
        f"{classification}"
    )


    # ========================================================
    # BUILD RETRIEVAL TEXT
    # ========================================================

    if finding_item.get(
        "profile_text"
    ):

        finding_text = finding_item[
            "profile_text"
        ]

    else:

        finding_text = build_finding_text(
            finding_item
        )


    # ========================================================
    # GENERATE EMBEDDING
    # ========================================================

    try:

        response = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=finding_text
        )

        finding_embedding = np.array(
            response.data[0].embedding,
            dtype=float
        )

    except Exception as exc:

        raise RuntimeError(
            f"Failed to generate embedding for "
            f"'{label}': {exc}"
        )


    # ========================================================
    # NORMALISE FINDING EMBEDDING
    # ========================================================

    finding_norm = np.linalg.norm(
        finding_embedding
    )

    if finding_norm == 0:

        raise RuntimeError(
            f"Zero embedding generated for "
            f"'{label}'."
        )


    finding_embedding = (
        finding_embedding
        / finding_norm
    )


    # ========================================================
    # SEMANTIC SIMILARITY
    # ========================================================

    semantic_scores = (
        normalised_embeddings
        @ finding_embedding
    )


    # ========================================================
    # BROAD INITIAL RETRIEVAL
    # ========================================================

    broad_pool_size = min(
        BROAD_POOL_SIZE,
        len(semantic_scores)
    )

    broad_indices = np.argsort(
        semantic_scores
    )[::-1][
        :broad_pool_size
    ]


    # ========================================================
    # BUILD CANDIDATES
    # ========================================================

    candidates = []


    for position in broad_indices:

        technique_id = cached_ids[
            position
        ]

        technique = mitre_lookup[
            technique_id
        ]

        technique_text = build_technique_text(
            technique
        )

        semantic_score = float(
            semantic_scores[position]
        )

        evidence_score = (
            calculate_token_overlap(
                finding_text,
                technique_text
            )
        )

        candidates.append(
            {

                "technique_id": technique_id,

                "technique_name": technique.get(
                    "technique_name",
                    ""
                ),

                "semantic_similarity": round(
                    semantic_score,
                    6
                ),

                "evidence_token_overlap": round(
                    evidence_score,
                    6
                ),

                "retrieval_basis": [
                    "semantic_similarity",
                    "structured_evidence"
                ],

                "validation_required": True,

                "mapping_status": "UNVALIDATED"
            }
        )


    # ========================================================
    # FINAL RANKING
    # ========================================================

    candidates = sorted(
        candidates,
        key=lambda item: (
            item["semantic_similarity"],
            item["evidence_token_overlap"]
        ),
        reverse=True
    )


    candidates = candidates[
        :TOP_K
    ]


    # ========================================================
    # PRINT CANDIDATES
    # ========================================================

    print(
        f"\nTop {len(candidates)} "
        f"MITRE candidates:"
    )


    for rank, candidate in enumerate(
        candidates,
        start=1
    ):

        print(
            f"  {rank:02d}. "
            f"{candidate['technique_id']} "
            f"{candidate['technique_name']} "
            f"(semantic="
            f"{candidate['semantic_similarity']}, "
            f"evidence="
            f"{candidate['evidence_token_overlap']})"
        )


    # ========================================================
    # STORE RESULT
    # ========================================================

    result = {

        "finding_id": finding.get(
            "finding_id",
            f"finding_{finding_number}"
        ),

        "finding": finding,

        "retrieval_evidence": finding_item,

        "candidate_count": len(
            candidates
        ),

        "candidate_pool_size": TOP_K,

        "candidates": candidates,

        "retrieval_method": {

            "primary": (
                "semantic_similarity"
            ),

            "secondary": (
                "structured_evidence_token_overlap"
            ),

            "semantic_weight": 1.0,

            "evidence_weight": 0.0,

            "broad_initial_pool": (
                broad_pool_size
            ),

            "validation_required": True
        },

        "important_note": (
            "MITRE candidates are retrieval "
            "hypotheses only. Semantic similarity "
            "and lexical overlap do not constitute "
            "proof of an ATT&CK technique. "
            "Candidates must be independently "
            "validated against observed evidence."
        )
    }


    all_results.append(
        result
    )


# ============================================================
# FINAL OUTPUT
# ============================================================

output = {

    "version": "4.0",

    "dataset_mode": dataset_mode,

    "dataset_type": dataset_type,

    "mitre_techniques_available": len(
        mitre_index
    ),

    "findings_processed": len(
        all_results
    ),

    "retrieval_configuration": {

        "candidate_pool_size": TOP_K,

        "broad_initial_pool": BROAD_POOL_SIZE,

        "primary_signal": (
            "semantic_similarity"
        ),

        "secondary_signal": (
            "structured_evidence_token_overlap"
        ),

        "semantic_weight": 1.0,

        "evidence_weight": 0.0,

        "validation_required": True
    },

    "methodology": [

        "Labelled datasets use attack or potential-anomaly behavioural evidence when available.",

        "Unlabelled datasets use telemetry-derived generic behavioural indicators to construct a behavioural anomaly profile.",

        "No attack type is inferred solely from the presence of a statistical anomaly.",

        "Security evidence is converted into structured retrieval text.",

        "MITRE ATT&CK techniques are represented using their IDs, names, descriptions, tactics and platforms.",

        "Semantic similarity is used as the primary retrieval signal.",

        "Structured lexical overlap is retained only as supporting retrieval information.",

        "No attack-specific MITRE mapping is hard-coded.",

        "Retrieved candidates are hypotheses and are not treated as confirmed techniques.",

        "Final ATT&CK validation must be evidence-based.",

        "The validation stage may reject all candidates when evidence is insufficient."
    ],

    "findings": all_results
}


# ============================================================
# SAVE
# ============================================================

save_json(
    OUTPUT_FILE,
    output
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("MITRE CANDIDATE RETRIEVAL COMPLETE")
print("=" * 70)

print(
    f"Findings processed: "
    f"{len(all_results)}"
)

print(
    f"Candidate pool per finding: "
    f"{TOP_K}"
)

print(
    f"Dataset type used: "
    f"{dataset_type}"
)

print(
    f"Output: "
    f"{OUTPUT_FILE}"
)

print(
    "\nMITRE candidates are retrieval hypotheses only."
)

print(
    "They must be validated against security evidence."
)