import json
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CANDIDATES_FILE = (
    BASE_DIR
    / "MITRE"
    / "mitre_candidates.json"
)

OUTPUT_FILE = (
    BASE_DIR
    / "MITRE"
    / "mitre_evaluated.json"
)

MODEL = "gpt-5.6"

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_json(path):
    """Load JSON from disk."""

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def save_json(path, data):
    """Save JSON to disk."""

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


def clean_json_response(text):
    """
    Remove markdown code fences if the model returns them.
    """

    text = text.strip()

    if text.startswith("```json"):
        text = text[7:]

    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    return text.strip()


# ============================================================
# LOAD CANDIDATES
# ============================================================

print("=" * 70)
print("MITRE ATT&CK EVIDENCE VALIDATION")
print("=" * 70)


if not CANDIDATES_FILE.exists():

    raise FileNotFoundError(
        f"Candidate file not found: "
        f"{CANDIDATES_FILE}"
    )


candidate_package = load_json(
    CANDIDATES_FILE
)


candidate_groups = candidate_package.get(
    "findings",
    []
)


print(
    f"\nCandidate result groups: "
    f"{len(candidate_groups)}"
)


if not candidate_groups:

    print(
        "\nNo candidate results found."
    )

    raise SystemExit(0)


# ============================================================
# DATASET INFORMATION
# ============================================================

dataset_mode = candidate_package.get(
    "dataset_mode",
    "UNKNOWN"
)

dataset_type = candidate_package.get(
    "dataset_type",
    "UNKNOWN"
)

print(
    f"Dataset mode: {dataset_mode}"
)

print(
    f"Dataset type: {dataset_type}"
)


# ============================================================
# VALIDATION RESULTS
# ============================================================

evaluated_findings = []


# ============================================================
# EVALUATE EACH FINDING
# ============================================================

for finding_number, group in enumerate(
    candidate_groups,
    start=1
):

    finding = group.get(
        "finding",
        {}
    )

    finding_id = group.get(
        "finding_id",
        f"finding_{finding_number}"
    )

    label = finding.get(
        "label",
        "Unknown"
    )

    classification = finding.get(
        "classification",
        "Unknown"
    )

    candidates = group.get(
        "candidates",
        []
    )

    retrieval_evidence = group.get(
        "retrieval_evidence",
        {}
    )

    print("\n" + "-" * 70)

    print(
        f"Evaluating: {label}"
    )

    print(
        f"Classification: {classification}"
    )

    print(
        f"Candidates: {len(candidates)}"
    )


    if not candidates:

        print(
            "No candidates available."
        )

        evaluated_findings.append(
            {
                "finding_id": finding_id,
                "finding": finding,
                "evaluations": [],
                "validation_summary": {
                    "status": "NO_CANDIDATES"
                }
            }
        )

        continue


    # ========================================================
    # BUILD AI EVALUATION PROMPT
    # ========================================================

    prompt = f"""
You are an experienced SOC analyst and MITRE ATT&CK analyst.

Your task is to independently validate MITRE ATT&CK technique
candidates against security evidence.

You MUST NOT assume that a candidate technique is correct just
because it has a high semantic similarity score.

You MUST NOT use a dataset label as proof of a technique.

You MUST NOT invent evidence that is not present.

You MUST distinguish between:

1. OBSERVED
   Directly supported by the telemetry.

2. INFERRED
   A reasonable interpretation of observed behaviour, but not
   directly demonstrated.

3. NOT_ESTABLISHED
   The available telemetry does not establish the behaviour.

A technique can only be:

SUPPORTED
- Strongly supported by the available evidence.

POSSIBLE
- Plausible based on the available evidence, but important
  evidence is missing.

NOT_SUPPORTED
- The available evidence does not support the technique.

IMPORTANT:

A network-flow dataset may show traffic patterns but may not
show authentication attempts, usernames, passwords, commands,
processes, source IP addresses, destination IP addresses,
successful logins, failed logins, or application-level events.

Do not assume those things occurred unless the evidence actually
shows them.

The finding label is contextual information only.

------------------------------------------------------------
DATASET
------------------------------------------------------------

Dataset mode:
{dataset_mode}

Dataset type:
{dataset_type}

------------------------------------------------------------
FINDING
------------------------------------------------------------

{json.dumps(
    finding,
    indent=2,
    ensure_ascii=False
)}

------------------------------------------------------------
STRUCTURED SECURITY EVIDENCE
------------------------------------------------------------

{json.dumps(
    retrieval_evidence,
    indent=2,
    ensure_ascii=False
)}

------------------------------------------------------------
MITRE CANDIDATES
------------------------------------------------------------

{json.dumps(
    candidates,
    indent=2,
    ensure_ascii=False
)}

------------------------------------------------------------
TASK
------------------------------------------------------------

Evaluate EVERY candidate.

For every candidate provide:

- technique_id
- technique_name
- status
- confidence
- observed_evidence
- inferred_behaviour
- missing_evidence
- reasoning

Allowed status values:

SUPPORTED
POSSIBLE
NOT_SUPPORTED

Allowed confidence values:

HIGH
MEDIUM
LOW

Be conservative.

If the evidence is insufficient, use POSSIBLE or
NOT_SUPPORTED rather than forcing a mapping.

For example, repeated network connections to SSH port 22 may
be consistent with password guessing, but network-flow telemetry
alone may not establish that authentication attempts actually
occurred.

Likewise, traffic to FTP port 21 does not automatically prove
the use of FTP commands, file transfers, credential attacks, or
other application-layer behaviour.

Return ONLY valid JSON.

Use exactly this structure:

{{
  "evaluations": [
    {{
      "technique_id": "T0000",
      "technique_name": "Example",
      "status": "NOT_SUPPORTED",
      "confidence": "LOW",
      "observed_evidence": [],
      "inferred_behaviour": [],
      "missing_evidence": [],
      "reasoning": "..."
    }}
  ],
  "finding_assessment": {{
    "overall_assessment": "...",
    "observed_behaviour": [],
    "inferred_behaviour": [],
    "important_evidence_gaps": [],
    "overall_confidence": "LOW"
  }}
}}
"""


    # ========================================================
    # CALL GPT-5.6
    # ========================================================

    try:

        response = client.responses.create(
            model=MODEL,
            input=prompt
        )

        raw_output = response.output_text

        cleaned_output = clean_json_response(
            raw_output
        )

        evaluation = json.loads(
            cleaned_output
        )

    except Exception as exc:

        print(
            f"\nERROR evaluating {label}:"
        )

        print(exc)

        evaluated_findings.append(
            {
                "finding_id": finding_id,
                "finding": finding,
                "retrieval_evidence": retrieval_evidence,
                "evaluations": [],
                "validation_summary": {
                    "status": "ERROR",
                    "error": str(exc)
                }
            }
        )

        continue


    # ========================================================
    # EXTRACT RESULTS
    # ========================================================

    evaluations = evaluation.get(
        "evaluations",
        []
    )

    finding_assessment = evaluation.get(
        "finding_assessment",
        {}
    )


    # ========================================================
    # PRINT SUMMARY
    # ========================================================

    supported = 0
    possible = 0
    not_supported = 0

    for item in evaluations:

        status = str(
            item.get(
                "status",
                ""
            )
        ).upper()

        if status == "SUPPORTED":
            supported += 1

        elif status == "POSSIBLE":
            possible += 1

        elif status == "NOT_SUPPORTED":
            not_supported += 1


    print(
        "\nValidation summary:"
    )

    print(
        f"  SUPPORTED:     {supported}"
    )

    print(
        f"  POSSIBLE:      {possible}"
    )

    print(
        f"  NOT_SUPPORTED: {not_supported}"
    )


    print(
        "\nOverall assessment:"
    )

    print(
        finding_assessment.get(
            "overall_assessment",
            "No assessment returned."
        )
    )


    # ========================================================
    # SAVE FINDING RESULT
    # ========================================================

    evaluated_findings.append(
        {
            "finding_id": finding_id,

            "finding": finding,

            "retrieval_evidence": retrieval_evidence,

            "retrieval_metadata": {
                "candidate_count": len(
                    candidates
                ),
                "retrieval_method": group.get(
                    "retrieval_method",
                    {}
                )
            },

            "evaluations": evaluations,

            "finding_assessment": finding_assessment
        }
    )


# ============================================================
# BUILD FINAL OUTPUT
# ============================================================

output = {

    "version": "3.0",

    "dataset_mode": dataset_mode,

    "dataset_type": dataset_type,

    "candidate_groups": len(
        candidate_groups
    ),

    "validation_model": MODEL,

    "validation_methodology": [

        "MITRE candidates are treated as hypotheses rather than confirmed mappings.",

        "Semantic similarity is not treated as proof.",

        "Dataset labels are not treated as proof of ATT&CK techniques.",

        "Security telemetry is evaluated against each candidate independently.",

        "Observed evidence is distinguished from inferred behaviour.",

        "Missing telemetry is explicitly identified.",

        "The validator may reject all candidates.",

        "Network-flow telemetry is not assumed to contain application-layer authentication evidence.",

        "Final ATT&CK assessments are based on available evidence rather than forced mappings."
    ],

    "findings": evaluated_findings
}


# ============================================================
# SAVE RESULTS
# ============================================================

save_json(
    OUTPUT_FILE,
    output
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("MITRE ATT&CK EVIDENCE VALIDATION COMPLETE")
print("=" * 70)

print(
    f"Findings evaluated: "
    f"{len(evaluated_findings)}"
)

print(
    f"Output: {OUTPUT_FILE}"
)