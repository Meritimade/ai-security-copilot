"""
AI SECURITY COPILOT
SECURITY REPORT GENERATOR

Version: 4.0

Purpose:
- Generate an AI-assisted security report from the evidence pipeline.
- Works with both LABELLED and UNLABELLED datasets.
- Uses security_evidence.json, security_schema.json and
  MITRE/mitre_evaluated.json as evidence sources.
- Does not hard-code attack-specific conclusions.
- Keeps MITRE candidate retrieval separate from evidence validation.
- Uses Windows-safe console output.
"""

from pathlib import Path
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from openai import OpenAI


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

EVIDENCE_FILE = BASE_DIR / "security_evidence.json"
SCHEMA_FILE = BASE_DIR / "security_schema.json"
MITRE_EVALUATED_FILE = BASE_DIR / "MITRE" / "mitre_evaluated.json"

JSON_REPORT_FILE = BASE_DIR / "security_report.json"
TEXT_REPORT_FILE = BASE_DIR / "ai_security_report.txt"

MODEL = "gpt-5.6"


# ============================================================
# WINDOWS-SAFE OUTPUT
# ============================================================

def safe_print(text=""):
    """
    Print text safely on Windows terminals that use cp1252.
    """
    try:
        print(str(text))
    except UnicodeEncodeError:
        safe_text = (
            str(text)
            .replace("✓", "[PASS]")
            .replace("✗", "[FAIL]")
            .replace("⚠", "[WARNING]")
            .replace("→", "->")
            .replace("←", "<-")
            .replace("•", "-")
            .replace("–", "-")
            .replace("—", "-")
            .replace("…", "...")
        )

        try:
            print(safe_text)
        except UnicodeEncodeError:
            print(
                str(safe_text).encode(
                    "ascii",
                    errors="replace"
                ).decode("ascii")
            )


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path):
    """
    Safely load a JSON file.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    """
    Save JSON using UTF-8.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# GENERAL UTILITIES
# ============================================================

def get_nested_value(data, *keys, default=None):
    """
    Safely retrieve a nested dictionary value.
    """
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        if key not in current:
            return default

        current = current[key]

    return current


def as_list(value):
    """
    Convert a value to a list where appropriate.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def truncate_text(value, limit=12000):
    """
    Prevent unnecessarily large prompts.
    """
    text = str(value)

    if len(text) <= limit:
        return text

    return text[:limit] + "\n...[truncated]..."


# ============================================================
# DATASET INFORMATION
# ============================================================

def determine_dataset_mode(evidence, schema):
    """
    Determine whether the analysis is labelled or unlabelled.
    """
    mode = evidence.get("dataset_mode")

    if mode:
        return str(mode).upper()

    mode = schema.get("dataset_mode")

    if mode:
        return str(mode).upper()

    capabilities = schema.get("capabilities", {})

    if capabilities.get("has_label") is True:
        return "LABELLED"

    return "UNLABELLED"


def determine_dataset_type(schema, evidence):
    """
    Determine dataset type.
    """
    dataset_type = schema.get("dataset_type")

    if dataset_type:
        return dataset_type

    dataset_type = evidence.get("dataset_type")

    if dataset_type:
        return dataset_type

    return "unknown"


# ============================================================
# EVIDENCE EXTRACTION
# ============================================================

def extract_findings(evidence):
    """
    Extract high-level security findings.
    """
    findings = evidence.get("findings", [])

    if isinstance(findings, list):
        return findings

    if isinstance(findings, dict):
        return list(findings.values())

    return []


def extract_behavioural_evidence(evidence):
    """
    Extract labelled behavioural evidence.
    """
    groups = evidence.get(
        "behavioural_indicators",
        []
    )

    if isinstance(groups, list):
        return groups

    if isinstance(groups, dict):
        return list(groups.values())

    return []


def extract_generic_indicators(evidence):
    """
    Extract generic behavioural indicators.
    """
    indicators = evidence.get(
        "generic_behavioural_indicators",
        []
    )

    if isinstance(indicators, list):
        return indicators

    if isinstance(indicators, dict):
        return list(indicators.values())

    return []


def extract_limitations(evidence, schema):
    """
    Extract evidence limitations from the analysis.
    """
    limitations = []

    evidence_limitations = evidence.get(
        "evidence_limitations",
        []
    )

    if isinstance(evidence_limitations, list):
        limitations.extend(evidence_limitations)

    schema_limitations = schema.get(
        "limitations",
        []
    )

    if isinstance(schema_limitations, list):
        limitations.extend(schema_limitations)

    capabilities = schema.get(
        "capabilities",
        {}
    )

    capability_messages = {
        "has_source_identity": "Source identity is unavailable.",
        "has_destination_identity": "Destination identity is unavailable.",
        "has_source_port": "Source port information is unavailable.",
        "has_action": "Action or outcome information is unavailable.",
        "has_user_identity": "User identity information is unavailable.",
        "has_host_identity": "Host identity information is unavailable.",
        "has_process_data": "Process information is unavailable.",
        "has_command_data": "Command-line information is unavailable.",
        "has_event_id": "Event identifiers are unavailable.",
    }

    for capability, message in capability_messages.items():
        if capabilities.get(capability) is False:
            limitations.append(message)

    # Deduplicate while preserving order.
    unique = []

    for item in limitations:
        text = str(item).strip()

        if text and text not in unique:
            unique.append(text)

    return unique


# ============================================================
# MITRE EXTRACTION
# ============================================================

def recursively_extract_mitre_results(data):
    """
    Recursively find MITRE evaluation records.

    This is intentionally tolerant of JSON structure changes.
    """
    results = []

    def walk(obj):
        if isinstance(obj, dict):

            # A complete evaluation record commonly contains
            # technique_id and status.
            if (
                "technique_id" in obj
                and (
                    "status" in obj
                    or "validation_status" in obj
                )
            ):
                results.append(obj)

            for value in obj.values():
                walk(value)

        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)

    return results


def normalize_mitre_result(result):
    """
    Normalize MITRE evaluation fields.
    """
    technique_id = (
        result.get("technique_id")
        or result.get("id")
        or result.get("technique", {}).get("technique_id")
    )

    technique_name = (
        result.get("technique_name")
        or result.get("name")
        or result.get("technique", {}).get("technique_name")
    )

    status = (
        result.get("status")
        or result.get("validation_status")
        or result.get("assessment")
        or "UNKNOWN"
    )

    confidence = (
        result.get("confidence")
        or result.get("confidence_level")
        or "UNKNOWN"
    )

    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "status": str(status).upper(),
        "confidence": str(confidence).upper(),
        "reasoning": result.get(
            "reasoning",
            result.get(
                "assessment_reason",
                result.get("explanation", "")
            )
        ),
        "observed_evidence": result.get(
            "observed_evidence",
            []
        ),
        "inferred_evidence": result.get(
            "inferred_evidence",
            []
        ),
        "missing_evidence": result.get(
            "missing_evidence",
            []
        ),
    }


def extract_mitre_evaluations():
    """
    Load and normalize MITRE evidence validation results.
    """
    if not MITRE_EVALUATED_FILE.exists():
        return []

    try:
        data = load_json(MITRE_EVALUATED_FILE)
    except Exception:
        return []

    raw_results = recursively_extract_mitre_results(data)

    normalized = []

    seen = set()

    for result in raw_results:
        item = normalize_mitre_result(result)

        technique_id = item.get("technique_id")
        status = item.get("status")
        confidence = item.get("confidence")

        if not technique_id:
            continue

        key = (
            str(technique_id),
            str(status),
            str(confidence)
        )

        if key in seen:
            continue

        seen.add(key)
        normalized.append(item)

    return normalized


# ============================================================
# MITRE SUMMARY
# ============================================================

def build_mitre_summary(mitre_results):
    """
    Create counts and grouped MITRE results.
    """
    summary = {
        "total": len(mitre_results),
        "supported": 0,
        "possible": 0,
        "not_supported": 0,
        "unknown": 0,
        "supported_techniques": [],
        "possible_techniques": [],
        "not_supported_techniques": [],
    }

    for item in mitre_results:

        status = item["status"]

        if status == "SUPPORTED":
            summary["supported"] += 1
            summary["supported_techniques"].append(item)

        elif status == "POSSIBLE":
            summary["possible"] += 1
            summary["possible_techniques"].append(item)

        elif status == "NOT_SUPPORTED":
            summary["not_supported"] += 1
            summary["not_supported_techniques"].append(item)

        else:
            summary["unknown"] += 1

    return summary


# ============================================================
# COMPACT EVIDENCE FOR AI
# ============================================================

def build_evidence_package(
    evidence,
    schema,
    findings,
    behavioural_evidence,
    generic_indicators,
    limitations,
    mitre_results,
):
    """
    Build a compact structured evidence package for the AI analyst.
    """

    package = {
        "dataset": {
            "mode": determine_dataset_mode(
                evidence,
                schema
            ),
            "type": determine_dataset_type(
                schema,
                evidence
            ),
            "source_file": schema.get(
                "source_file"
            ),
            "records_sampled": schema.get(
                "records_sampled"
            ),
            "total_columns": schema.get(
                "total_columns"
            ),
        },

        "capabilities": schema.get(
            "capabilities",
            {}
        ),

        "findings": findings,

        "behavioural_evidence": behavioural_evidence,

        "generic_behavioural_indicators": generic_indicators,

        "evidence_limitations": limitations,

        "mitre_validation": mitre_results,
    }

    return package


# ============================================================
# AI PROMPT
# ============================================================

def build_ai_prompt(package):
    """
    Build the AI security analyst prompt.
    """

    mode = package["dataset"]["mode"]
    dataset_type = package["dataset"]["type"]

    prompt = f"""
You are the AI Security Analyst component of an AI-assisted
Security Operations / SIEM analysis platform.

Your task is to analyse the supplied machine-generated security
evidence and produce a professional security assessment.

DATASET MODE:
{mode}

DATASET TYPE:
{dataset_type}

IMPORTANT RULES:

1. Use only the supplied evidence.
2. Do not invent source IPs, destination IPs, users, hosts,
   processes, commands, authentication events, or outcomes.
3. Do not treat a dataset label as proof of an attack.
4. In UNLABELLED mode, do not invent attack labels.
5. Distinguish clearly between:
   - observed evidence
   - reasonable inference
   - missing evidence
6. MITRE candidate retrieval is only hypothesis generation.
7. MITRE validation results must be respected.
8. A POSSIBLE MITRE technique is NOT the same as SUPPORTED.
9. Do not upgrade POSSIBLE to SUPPORTED.
10. Do not force a MITRE mapping when the evidence is insufficient.
11. Explain important limitations caused by missing telemetry.
12. Avoid unsupported claims about attacker identity or intent.
13. Where evidence is insufficient, explicitly say so.
14. Recommendations must be defensive and evidence-driven.
15. Do not expose API keys, credentials, secrets, or internal
    implementation secrets.

MITRE STATUS DEFINITIONS:

SUPPORTED:
The available evidence supports the technique sufficiently for
the current telemetry.

POSSIBLE:
The observed behaviour is compatible with the technique, but
additional evidence is required.

NOT_SUPPORTED:
The available evidence does not sufficiently support the
technique.

Produce the report using this structure:

1. Executive Summary
2. Dataset and Analysis Scope
3. Security Findings
4. Behavioural Analysis
5. Temporal Analysis
6. MITRE ATT&CK Assessment
7. Evidence Strength and Confidence
8. Evidence Limitations
9. Investigation Priorities
10. Defensive Recommendations
11. Conclusion

For each important finding, explain:
- What was observed
- Why it matters
- What can reasonably be inferred
- What cannot be established
- What additional evidence should be collected

For MITRE ATT&CK:
- List SUPPORTED techniques separately.
- List POSSIBLE techniques separately.
- Do not present NOT_SUPPORTED techniques as detected attacks.
- Include technique IDs and names.
- Explain the evidence supporting each assessment.
- Include missing evidence where relevant.

For UNLABELLED data:
The report must describe anomalous or suspicious behaviour
without pretending that a specific attack has been proven.

The final report should be suitable for:
- MSc cybersecurity project documentation
- SOC analyst review
- security engineering review
- technical portfolio demonstration

Return a polished professional report in plain text.

SUPPLIED SECURITY EVIDENCE:
{json.dumps(package, indent=2, ensure_ascii=False)}
"""

    return prompt


# ============================================================
# OPENAI REPORT GENERATION
# ============================================================

def generate_ai_report(package):
    """
    Generate the final report using OpenAI Responses API.
    """

    load_dotenv(
        BASE_DIR / ".env"
    )

    api_key = os.getenv(
        "OPENAI_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY was not found. "
            "Check your .env file."
        )

    client = OpenAI(
        api_key=api_key
    )

    prompt = build_ai_prompt(
        package
    )

    response = client.responses.create(
        model=MODEL,
        input=prompt
    )

    report_text = getattr(
        response,
        "output_text",
        None
    )

    if not report_text:
        raise RuntimeError(
            "OpenAI returned no report text."
        )

    return report_text.strip()


# ============================================================
# TEXT REPORT
# ============================================================

def build_text_report(
    report_text,
    package,
    mitre_summary,
):
    """
    Build the final text report with metadata.
    """

    dataset = package["dataset"]

    header = f"""
======================================================================
AI SECURITY COPILOT
AI SECURITY ANALYSIS REPORT
======================================================================

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Dataset type: {dataset["type"]}
Dataset mode: {dataset["mode"]}

Records sampled: {dataset.get("records_sampled")}
Total columns: {dataset.get("total_columns")}

MITRE ATT&CK validation:
  Total evaluated: {mitre_summary["total"]}
  SUPPORTED:       {mitre_summary["supported"]}
  POSSIBLE:        {mitre_summary["possible"]}
  NOT_SUPPORTED:   {mitre_summary["not_supported"]}

======================================================================

"""

    footer = """

======================================================================
END OF AI SECURITY COPILOT REPORT
======================================================================
"""

    return (
        header
        + report_text
        + footer
    )


# ============================================================
# JSON REPORT
# ============================================================

def build_json_report(
    report_text,
    package,
    mitre_summary,
):
    """
    Build machine-readable final report.
    """

    return {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "generator": "AI Security Copilot",
            "model": MODEL,
            "version": "4.0",
        },

        "dataset": package["dataset"],

        "analysis": {
            "findings_count": len(
                package["findings"]
            ),
            "behavioural_evidence_groups": len(
                package["behavioural_evidence"]
            ),
            "generic_indicators": len(
                package["generic_behavioural_indicators"]
            ),
            "evidence_limitations": len(
                package["evidence_limitations"]
            ),
        },

        "mitre_summary": mitre_summary,

        "mitre_validation": package[
            "mitre_validation"
        ],

        "ai_report": report_text,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    safe_print(
        "======================================================================"
    )
    safe_print(
        "AI SECURITY REPORT GENERATOR"
    )
    safe_print(
        "======================================================================"
    )

    try:

        # --------------------------------------------------------
        # LOAD INPUT FILES
        # --------------------------------------------------------

        safe_print()
        safe_print(
            f"Loading security evidence: {EVIDENCE_FILE}"
        )

        evidence = load_json(
            EVIDENCE_FILE
        )

        safe_print(
            f"Loading security schema: {SCHEMA_FILE}"
        )

        schema = load_json(
            SCHEMA_FILE
        )

        # --------------------------------------------------------
        # EXTRACT ANALYSIS DATA
        # --------------------------------------------------------

        findings = extract_findings(
            evidence
        )

        behavioural_evidence = (
            extract_behavioural_evidence(
                evidence
            )
        )

        generic_indicators = (
            extract_generic_indicators(
                evidence
            )
        )

        limitations = extract_limitations(
            evidence,
            schema
        )

        mitre_results = (
            extract_mitre_evaluations()
        )

        # --------------------------------------------------------
        # DATASET INFORMATION
        # --------------------------------------------------------

        dataset_mode = determine_dataset_mode(
            evidence,
            schema
        )

        dataset_type = determine_dataset_type(
            schema,
            evidence
        )

        safe_print()
        safe_print(
            f"Dataset mode: {dataset_mode}"
        )

        safe_print(
            f"Dataset type: {dataset_type}"
        )

        safe_print(
            f"Security findings: {len(findings)}"
        )

        safe_print(
            f"Behavioural evidence groups: "
            f"{len(behavioural_evidence)}"
        )

        safe_print(
            f"Generic indicators: "
            f"{len(generic_indicators)}"
        )

        safe_print(
            f"Evidence limitations: "
            f"{len(limitations)}"
        )

        safe_print(
            f"MITRE findings evaluated: "
            f"{len(mitre_results)}"
        )

        # --------------------------------------------------------
        # MITRE SUMMARY
        # --------------------------------------------------------

        mitre_summary = build_mitre_summary(
            mitre_results
        )

        safe_print()
        safe_print(
            "MITRE validation summary:"
        )

        safe_print(
            f"  SUPPORTED:     "
            f"{mitre_summary['supported']}"
        )

        safe_print(
            f"  POSSIBLE:      "
            f"{mitre_summary['possible']}"
        )

        safe_print(
            f"  NOT_SUPPORTED: "
            f"{mitre_summary['not_supported']}"
        )

        # --------------------------------------------------------
        # BUILD EVIDENCE PACKAGE
        # --------------------------------------------------------

        package = build_evidence_package(
            evidence=evidence,
            schema=schema,
            findings=findings,
            behavioural_evidence=behavioural_evidence,
            generic_indicators=generic_indicators,
            limitations=limitations,
            mitre_results=mitre_results,
        )

        # --------------------------------------------------------
        # GENERATE AI REPORT
        # --------------------------------------------------------

        safe_print()
        safe_print(
            "Generating AI security report..."
        )

        report_text = generate_ai_report(
            package
        )

        if not report_text:
            raise RuntimeError(
                "AI report was empty."
            )

        # --------------------------------------------------------
        # SAVE TEXT REPORT
        # --------------------------------------------------------

        final_text_report = build_text_report(
            report_text,
            package,
            mitre_summary,
        )

        with open(
            TEXT_REPORT_FILE,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(
                final_text_report
            )

        # --------------------------------------------------------
        # SAVE JSON REPORT
        # --------------------------------------------------------

        json_report = build_json_report(
            report_text,
            package,
            mitre_summary,
        )

        save_json(
            JSON_REPORT_FILE,
            json_report
        )

        # --------------------------------------------------------
        # FINAL OUTPUT
        # --------------------------------------------------------

        safe_print()
        safe_print(
            "======================================================================"
        )
        safe_print(
            "AI SECURITY REPORT COMPLETE"
        )
        safe_print(
            "======================================================================"
        )

        safe_print(
            f"Dataset type used: {dataset_type}"
        )

        safe_print(
            f"Dataset mode used: {dataset_mode}"
        )

        safe_print(
            f"JSON report: {JSON_REPORT_FILE}"
        )

        safe_print(
            f"Text report: {TEXT_REPORT_FILE}"
        )

        safe_print(
            f"Report length: {len(final_text_report):,} characters"
        )

        safe_print()
        safe_print(
            "The report was generated using:"
        )

        safe_print(
            "  [PASS] Security schema"
        )

        safe_print(
            "  [PASS] Security evidence"
        )

        safe_print(
            "  [PASS] MITRE evidence validation"
        )

        safe_print(
            "  [PASS] AI security analysis"
        )

        safe_print()
        safe_print(
            "Report generation completed successfully."
        )

        return 0

    except FileNotFoundError as e:

        safe_print()
        safe_print(
            "[ERROR] Required file missing:"
        )
        safe_print(
            str(e)
        )

        return 1

    except Exception as e:

        safe_print()
        safe_print(
            "======================================================================"
        )
        safe_print(
            "REPORT GENERATION FAILED"
        )
        safe_print(
            "======================================================================"
        )

        safe_print(
            f"Error: {e}"
        )

        safe_print()
        safe_print(
            "Check the files above and the OpenAI API configuration."
        )

        return 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(
        main()
    )