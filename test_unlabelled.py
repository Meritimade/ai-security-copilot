import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RAW_DIR = BASE_DIR / "Data" / "raw"
PROCESSED_DIR = BASE_DIR / "Data" / "processed"

SCHEMA_FILE = BASE_DIR / "security_schema.json"
EVIDENCE_FILE = BASE_DIR / "security_evidence.json"

MITRE_DIR = BASE_DIR / "MITRE"

MITRE_CANDIDATES_FILE = (
    MITRE_DIR / "mitre_candidates.json"
)

MITRE_EVALUATED_FILE = (
    MITRE_DIR / "mitre_evaluated.json"
)

REPORT_JSON = BASE_DIR / "security_report.json"
REPORT_TEXT = BASE_DIR / "ai_security_report.txt"


# ============================================================
# TEMPORARY BACKUP
#
# IMPORTANT:
# The backup is created OUTSIDE OneDrive.
# This avoids Windows/OneDrive file-lock problems.
# ============================================================

TEMP_BACKUP_DIR = Path(
    tempfile.mkdtemp(
        prefix="ai_security_copilot_test_"
    )
)


# ============================================================
# BACKUP HELPERS
# ============================================================

def backup_file(path):

    if path.exists():

        destination = (
            TEMP_BACKUP_DIR / path.name
        )

        shutil.copy2(
            path,
            destination,
        )


def restore_file(path):

    source = (
        TEMP_BACKUP_DIR / path.name
    )

    if source.exists():

        shutil.copy2(
            source,
            path,
        )


# ============================================================
# RUN PIPELINE SCRIPT
# ============================================================

def run_script(script_name):

    print()
    print("=" * 60)
    print(
        f"RUNNING {script_name.upper()}"
    )
    print("=" * 60)

    result = subprocess.run(
        [
            "python",
            script_name,
        ],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
    )

    if result.stdout:

        print(
            result.stdout
        )

    if result.stderr:

        print(
            "ERROR / STDERR:"
        )

        print(
            result.stderr
        )

    if result.returncode != 0:

        raise RuntimeError(
            f"{script_name} failed "
            f"with exit code "
            f"{result.returncode}"
        )


# ============================================================
# CREATE UNLABELLED DATASET
# ============================================================

def create_unlabelled_dataset(
    source_file
):

    print()
    print(
        "Creating temporary unlabelled dataset..."
    )

    df = pd.read_csv(
        source_file,
        low_memory=False,
    )

    print(
        f"Original columns: "
        f"{len(df.columns)}"
    )

    print(
        f"Original records: "
        f"{len(df):,}"
    )

    # --------------------------------------------------------
    # Confirm Label exists
    # --------------------------------------------------------

    if "Label" not in df.columns:

        raise ValueError(
            "The source dataset does not "
            "contain a Label column."
        )

    # --------------------------------------------------------
    # Remove Label
    # --------------------------------------------------------

    df = df.drop(
        columns=["Label"]
    )

    print(
        f"Columns after removing Label: "
        f"{len(df.columns)}"
    )

    # --------------------------------------------------------
    # Existing pipeline expects this filename.
    # --------------------------------------------------------

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    unlabelled_file = (
        PROCESSED_DIR
        / "02-14-2018_clean.csv"
    )

    df.to_csv(
        unlabelled_file,
        index=False,
    )

    print()
    print(
        "Temporary unlabelled dataset created:"
    )

    print(
        unlabelled_file
    )

    return unlabelled_file


# ============================================================
# JSON HELPER
# ============================================================

def load_json(path):

    if not path.exists():

        return None

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    except Exception:

        return None


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print(
        "AI SECURITY COPILOT"
    )
    print(
        "FULL UNLABELLED PIPELINE TEST"
    )
    print("=" * 70)

    print()
    print(
        f"Temporary backup location:"
    )

    print(
        TEMP_BACKUP_DIR
    )

    # --------------------------------------------------------
    # Find original processed dataset
    # --------------------------------------------------------

    original_files = list(
        PROCESSED_DIR.glob(
            "*.csv"
        )
    )

    if not original_files:

        raise FileNotFoundError(
            "No processed CSV dataset was found."
        )

    source_file = None

    for file in original_files:

        if (
            file.name
            == "02-14-2018_clean.csv"
        ):

            source_file = file

            break

    if source_file is None:

        source_file = original_files[0]

    print()
    print(
        f"Source dataset: "
        f"{source_file.name}"
    )

    # --------------------------------------------------------
    # Backup current processed CSVs
    # --------------------------------------------------------

    print()
    print(
        "Backing up current project state..."
    )

    processed_backup_dir = (
        TEMP_BACKUP_DIR / "processed"
    )

    processed_backup_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for file in PROCESSED_DIR.glob(
        "*.csv"
    ):

        shutil.copy2(
            file,
            processed_backup_dir
            / file.name,
        )

    # --------------------------------------------------------
    # Backup generated outputs
    # --------------------------------------------------------

    files_to_backup = [

        SCHEMA_FILE,

        EVIDENCE_FILE,

        MITRE_CANDIDATES_FILE,

        MITRE_EVALUATED_FILE,

        REPORT_JSON,

        REPORT_TEXT,
    ]

    for file in files_to_backup:

        backup_file(file)

    try:

        # ====================================================
        # CREATE UNLABELLED DATASET
        # ====================================================

        create_unlabelled_dataset(
            source_file
        )

        # ====================================================
        # DATA VALIDATION
        # ====================================================

        run_script(
            "data_validation.py"
        )

        # ====================================================
        # SCHEMA DISCOVERY
        # ====================================================

        run_script(
            "schema_discovery.py"
        )

        # ====================================================
        # SECURITY ANALYSIS
        # ====================================================

        run_script(
            "security_analysis.py"
        )

        # ====================================================
        # MITRE RETRIEVAL
        # ====================================================

        run_script(
            "mitre_mapping.py"
        )

        # ====================================================
        # MITRE VALIDATION
        # ====================================================

        run_script(
            "mitre_evaluator.py"
        )

        # ====================================================
        # AI SECURITY REPORT
        # ====================================================

        run_script(
            "security_report.py"
        )

        # ====================================================
        # LOAD RESULTS
        # ====================================================

        schema = load_json(
            SCHEMA_FILE
        )

        evidence = load_json(
            EVIDENCE_FILE
        )

        mitre = load_json(
            MITRE_EVALUATED_FILE
        )

        report = load_json(
            REPORT_JSON
        )

        # ====================================================
        # FINAL TEST RESULTS
        # ====================================================

        print()
        print("=" * 70)
        print(
            "FULL UNLABELLED PIPELINE RESULT"
        )
        print("=" * 70)

        # ----------------------------------------------------
        # Schema result
        # ----------------------------------------------------

        if schema:

            capabilities = schema.get(
                "capabilities",
                {},
            )

            print()
            print(
                f"Dataset type: "
                f"{schema.get('dataset_type')}"
            )

            print(
                f"Has label: "
                f"{capabilities.get('has_label')}"
            )

        # ----------------------------------------------------
        # Security evidence
        # ----------------------------------------------------

        if evidence:

            print()

            print(
                f"Dataset mode: "
                f"{evidence.get('dataset_mode')}"
            )

            findings = evidence.get(
                "findings",
                [],
            )

            generic_indicators = (
                evidence.get(
                    "generic_behavioural_indicators",
                    [],
                )
            )

            print(
                f"Findings: "
                f"{len(findings)}"
            )

            print(
                f"Generic behavioural indicators: "
                f"{len(generic_indicators)}"
            )

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------

        if mitre:

            print()

            print(
                "MITRE candidate retrieval and "
                "validation completed."
            )

        else:

            print()
            print(
                "WARNING: MITRE evaluation output "
                "was not found."
            )

        # ----------------------------------------------------
        # AI report
        # ----------------------------------------------------

        if report:

            print()

            print(
                "AI security report generated."
            )

        else:

            print()
            print(
                "WARNING: AI security report "
                "was not found."
            )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print(
            "FULL UNLABELLED PIPELINE SUCCESSFUL"
        )
        print("=" * 70)

    finally:

        # ====================================================
        # RESTORE ORIGINAL PROJECT STATE
        # ====================================================

        print()
        print("=" * 70)
        print(
            "RESTORING ORIGINAL PROJECT STATE"
        )
        print("=" * 70)

        # ----------------------------------------------------
        # Remove temporary processed CSV
        # ----------------------------------------------------

        if PROCESSED_DIR.exists():

            for file in PROCESSED_DIR.glob(
                "*.csv"
            ):

                try:

                    file.unlink()

                except Exception as error:

                    print(
                        f"Could not remove "
                        f"{file.name}: {error}"
                    )

        # ----------------------------------------------------
        # Restore original processed CSVs
        # ----------------------------------------------------

        if processed_backup_dir.exists():

            for file in processed_backup_dir.glob(
                "*.csv"
            ):

                shutil.copy2(
                    file,
                    PROCESSED_DIR
                    / file.name,
                )

        # ----------------------------------------------------
        # Restore analysis outputs
        # ----------------------------------------------------

        for file in files_to_backup:

            restore_file(file)

        print()
        print(
            "Original project state restored."
        )

        # ----------------------------------------------------
        # Remove temporary backup outside OneDrive
        # ----------------------------------------------------

        try:

            shutil.rmtree(
                TEMP_BACKUP_DIR
            )

            print(
                "Temporary test backup removed."
            )

        except Exception as error:

            print(
                "Temporary backup could not "
                "be removed automatically:"
            )

            print(
                error
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()