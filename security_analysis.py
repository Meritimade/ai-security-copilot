import json
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROCESSED_DIR = Path("Data/processed")
SCHEMA_FILE = Path("security_schema.json")
OUTPUT_FILE = Path("security_evidence.json")


# ============================================================
# HELPERS
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )


def clean_value(value):
    """
    Convert NumPy/Pandas values into JSON-safe Python values.
    """

    if pd.isna(value):
        return None

    if isinstance(value, (np.integer,)):
        return int(value)

    if isinstance(value, (np.floating,)):
        return float(value)

    return value


def safe_percentage(part, total):
    if total == 0:
        return 0.0

    return round(
        (part / total) * 100,
        4
    )


# ============================================================
# DATA DISCOVERY
# ============================================================

def discover_csv_files():
    files = sorted(
        PROCESSED_DIR.glob("*.csv")
    )

    if not files:
        raise FileNotFoundError(
            "No processed CSV files were found in "
            f"{PROCESSED_DIR}"
        )

    return files


def load_all_data(csv_files):
    dataframes = []

    for file in csv_files:

        print(
            f"Loading: {file.name}"
        )

        df = pd.read_csv(
            file,
            low_memory=False
        )

        df["Source_File"] = file.name

        dataframes.append(df)

    combined = pd.concat(
        dataframes,
        ignore_index=True
    )

    return combined


# ============================================================
# DATASET MODE
# ============================================================

def determine_dataset_mode(df, schema):
    label_fields = schema.get(
        "detected_fields",
        {}
    ).get(
        "label",
        []
    )

    has_label = bool(
        label_fields
        and label_fields[0] in df.columns
    )

    if has_label:
        return "LABELLED"

    return "UNLABELLED"


# ============================================================
# STATISTICAL EVIDENCE
# ============================================================

def calculate_statistics(series):
    numeric = pd.to_numeric(
        series,
        errors="coerce"
    )

    numeric = numeric.replace(
        [np.inf, -np.inf],
        np.nan
    ).dropna()

    if numeric.empty:
        return None

    return {
        "mean": clean_value(numeric.mean()),
        "median": clean_value(numeric.median()),
        "minimum": clean_value(numeric.min()),
        "maximum": clean_value(numeric.max()),
        "p95": clean_value(
            numeric.quantile(0.95)
        ),
        "p99": clean_value(
            numeric.quantile(0.99)
        )
    }


# ============================================================
# PORT / PROTOCOL EVIDENCE
# ============================================================

def calculate_categorical_distribution(
    df,
    column
):

    if column not in df.columns:
        return {}

    values = (
        df[column]
        .value_counts(dropna=False)
    )

    result = {}

    for value, count in values.items():

        result[str(clean_value(value))] = int(
            count
        )

    return result


# ============================================================
# TEMPORAL EVIDENCE
# ============================================================

def calculate_temporal_evidence(
    df,
    timestamp_column
):

    if timestamp_column not in df.columns:
        return {}

    timestamps = pd.to_datetime(
        df[timestamp_column],
        errors="coerce",
        dayfirst=True
    )

    timestamps = timestamps.dropna()

    if timestamps.empty:
        return {
            "records_with_valid_timestamps": 0
        }

    start = timestamps.min()
    end = timestamps.max()

    duration_seconds = (
        end - start
    ).total_seconds()

    hourly = (
        timestamps
        .dt.hour
        .value_counts()
        .sort_index()
    )

    activity_by_hour = {
        str(int(hour)): int(count)
        for hour, count in hourly.items()
    }

    peak_hour = int(
        hourly.idxmax()
    )

    peak_count = int(
        hourly.max()
    )

    return {
        "records_with_valid_timestamps": int(
            len(timestamps)
        ),
        "observation_start": str(start),
        "observation_end": str(end),
        "observation_duration_seconds": (
            clean_value(duration_seconds)
        ),
        "observation_duration_minutes": (
            clean_value(
                duration_seconds / 60
            )
        ),
        "activity_by_hour": activity_by_hour,
        "peak_hour": peak_hour,
        "peak_hour_record_count": peak_count,
        "peak_hour_percentage": safe_percentage(
            peak_count,
            len(timestamps)
        )
    }


# ============================================================
# BEHAVIOURAL STATISTICS
# ============================================================

def calculate_behavioural_statistics(
    df,
    schema
):

    detected_fields = schema.get(
        "detected_fields",
        {}
    )

    semantic_fields = [
        "duration",
        "packets_forward",
        "packets_backward",
        "packets_total",
        "packets_per_second",
        "packets_per_second_forward",
        "packets_per_second_backward",
        "bytes_forward",
        "bytes_backward",
        "bytes_total",
        "bytes_per_second",
        "packet_length_forward_max",
        "packet_length_backward_max",
        "packet_length_max",
        "packet_length_forward_mean",
        "packet_length_backward_mean",
        "packet_length_mean",
        "syn_flags",
        "ack_flags",
        "rst_flags",
        "fin_flags"
    ]

    statistics = {}

    for semantic_field in semantic_fields:

        columns = detected_fields.get(
            semantic_field,
            []
        )

        if not columns:
            continue

        column = columns[0]

        if column not in df.columns:
            continue

        result = calculate_statistics(
            df[column]
        )

        if result is not None:
            statistics[column] = result

    return statistics


# ============================================================
# COMPARATIVE EVIDENCE
# ============================================================

def calculate_comparative_evidence(
    attack_df,
    baseline_df,
    schema
):

    if baseline_df.empty:
        return {
            "available": False,
            "reason": "No baseline records available."
        }

    attack_statistics = (
        calculate_behavioural_statistics(
            attack_df,
            schema
        )
    )

    baseline_statistics = (
        calculate_behavioural_statistics(
            baseline_df,
            schema
        )
    )

    comparison = {}

    for column, attack_values in attack_statistics.items():

        if column not in baseline_statistics:
            continue

        baseline_values = baseline_statistics[
            column
        ]

        attack_mean = attack_values.get(
            "mean"
        )

        baseline_mean = baseline_values.get(
            "mean"
        )

        if (
            attack_mean is None
            or baseline_mean is None
        ):
            continue

        difference = (
            attack_mean - baseline_mean
        )

        if baseline_mean != 0:

            percentage_difference = (
                difference
                / abs(baseline_mean)
            ) * 100

        else:
            percentage_difference = None

        comparison[column] = {
            "finding_mean": clean_value(
                attack_mean
            ),
            "baseline_mean": clean_value(
                baseline_mean
            ),
            "absolute_difference": clean_value(
                difference
            ),
            "percentage_difference": clean_value(
                percentage_difference
            )
        }

    return {
        "available": True,
        "comparison_baseline": "Benign",
        "features": comparison
    }


# ============================================================
# REPETITIVE DESTINATION ACTIVITY
# ============================================================

def calculate_repetitive_destination_activity(
    df,
    schema
):

    detected_fields = schema.get(
        "detected_fields",
        {}
    )

    timestamp_columns = detected_fields.get(
        "timestamp",
        []
    )

    if not timestamp_columns:
        return None

    timestamp_column = timestamp_columns[0]

    if timestamp_column not in df.columns:
        return None

    destination_columns = (
        detected_fields.get(
            "destination_ip",
            []
        )
        or detected_fields.get(
            "destination_port",
            []
        )
    )

    if not destination_columns:
        return None

    destination_column = destination_columns[0]

    if destination_column not in df.columns:
        return None

    timestamps = pd.to_datetime(
        df[timestamp_column],
        errors="coerce",
        dayfirst=True
    )

    working = df.copy()

    working["_timestamp"] = timestamps

    working = working.dropna(
        subset=["_timestamp"]
    )

    if working.empty:
        return None

    working["_time_window"] = (
        working["_timestamp"]
        .dt.floor("5min")
    )

    grouped = (
        working
        .groupby(
            [
                "_time_window",
                destination_column
            ],
            dropna=False
        )
        .size()
        .reset_index(
            name="record_count"
        )
    )

    if grouped.empty:
        return None

    largest = grouped.loc[
        grouped["record_count"].idxmax()
    ]

    record_count = int(
        largest["record_count"]
    )

    # Only report meaningful repetition.
    if record_count < 100:
        return None

    return {
        "destination_field": destination_column,
        "timestamp_field": timestamp_column,
        "time_window": str(
            largest["_time_window"]
        ),
        "destination_value": str(
            clean_value(
                largest[destination_column]
            )
        ),
        "record_count": record_count,
        "description": (
            "A destination value appears repeatedly "
            "within the same short time window."
        )
    }


# ============================================================
# LABELLED FINDING EVIDENCE
# ============================================================

def build_labelled_findings(
    df,
    schema
):

    detected_fields = schema.get(
        "detected_fields",
        {}
    )

    label_columns = detected_fields.get(
        "label",
        []
    )

    if not label_columns:
        return []

    label_column = label_columns[0]

    if label_column not in df.columns:
        return []

    total_records = len(df)

    labels = (
        df[label_column]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    # --------------------------------------------------------
    # Dynamically identify baseline.
    # --------------------------------------------------------

    baseline_label = None

    for label in labels:

        if label.lower() in {
            "benign",
            "normal",
            "legitimate",
            "clean"
        }:

            baseline_label = label
            break

    if baseline_label is None:
        baseline_label = (
            labels[0]
            if labels
            else None
        )

    baseline_df = df[
        df[label_column].astype(str)
        == str(baseline_label)
    ]

    findings = []

    for label in labels:

        label_df = df[
            df[label_column].astype(str)
            == str(label)
        ]

        record_count = len(
            label_df
        )

        classification = (
            "benign"
            if str(label) == str(baseline_label)
            else "attack"
        )

        # ----------------------------------------------------
        # Destination port distribution
        # ----------------------------------------------------

        destination_ports = {}

        destination_port_columns = (
            detected_fields.get(
                "destination_port",
                []
            )
        )

        if destination_port_columns:

            destination_port_column = (
                destination_port_columns[0]
            )

            destination_ports = (
                calculate_categorical_distribution(
                    label_df,
                    destination_port_column
                )
            )

        # ----------------------------------------------------
        # Protocol distribution
        # ----------------------------------------------------

        protocols = {}

        protocol_columns = (
            detected_fields.get(
                "protocol",
                []
            )
        )

        if protocol_columns:

            protocol_column = (
                protocol_columns[0]
            )

            protocols = (
                calculate_categorical_distribution(
                    label_df,
                    protocol_column
                )
            )

        # ----------------------------------------------------
        # Temporal evidence
        # ----------------------------------------------------

        temporal_evidence = {}

        timestamp_columns = (
            detected_fields.get(
                "timestamp",
                []
            )
        )

        if timestamp_columns:

            temporal_evidence = (
                calculate_temporal_evidence(
                    label_df,
                    timestamp_columns[0]
                )
            )

        # ----------------------------------------------------
        # Behavioural statistics
        # ----------------------------------------------------

        behavioural_statistics = (
            calculate_behavioural_statistics(
                label_df,
                schema
            )
        )

        # ----------------------------------------------------
        # Comparison against baseline
        # ----------------------------------------------------

        if (
            baseline_label is not None
            and str(label) != str(baseline_label)
        ):

            comparative_evidence = (
                calculate_comparative_evidence(
                    label_df,
                    baseline_df,
                    schema
                )
            )

        else:

            comparative_evidence = {
                "available": False,
                "reason": (
                    "Finding is the dataset baseline."
                )
            }

        # ----------------------------------------------------
        # Evidence limitations
        # ----------------------------------------------------

        capabilities = schema.get(
            "capabilities",
            {}
        )

        limitations = []

        limitation_map = {
            "has_source_identity":
                "Source identity information was not detected.",

            "has_destination_identity":
                "Destination identity information was not detected.",

            "has_source_port":
                "Source port information was not detected.",

            "has_action":
                "Action or outcome information was not detected.",

            "has_user_identity":
                "User identity information was not detected.",

            "has_host_identity":
                "Host identity information was not detected.",

            "has_process_data":
                "Process information was not detected.",

            "has_command_data":
                "Command-line information was not detected.",

            "has_event_id":
                "Event or alert identifiers were not detected."
        }

        for capability, message in limitation_map.items():

            if capabilities.get(capability) is False:
                limitations.append(message)

        # ----------------------------------------------------
        # Build finding
        # ----------------------------------------------------

        finding = {
            "finding": {
                "label": label,
                "classification": classification,
                "record_count": record_count,
                "percentage_of_dataset": safe_percentage(
                    record_count,
                    total_records
                ),
                "associated_destination_ports": (
                    destination_ports
                ),
                "associated_protocols": (
                    protocols
                ),
                "behavioural_statistics": (
                    behavioural_statistics
                ),
                "temporal_evidence": (
                    temporal_evidence
                ),
                "comparative_behavioural_evidence": (
                    comparative_evidence
                )
            },

            "evidence_limitations": limitations
        }

        findings.append(
            finding
        )

    return findings


# ============================================================
# GENERIC BEHAVIOURAL INDICATORS
# ============================================================

def build_behavioural_indicators(
    df,
    schema
):

    indicators = []

    detected_fields = schema.get(
        "detected_fields",
        {}
    )

    # --------------------------------------------------------
    # Numeric distribution indicators
    # --------------------------------------------------------

    numeric_fields = [
        "duration",
        "packets_forward",
        "packets_backward",
        "packets_per_second",
        "packets_per_second_forward",
        "packets_per_second_backward",
        "bytes_forward",
        "bytes_backward",
        "bytes_per_second"
    ]

    for semantic_field in numeric_fields:

        columns = detected_fields.get(
            semantic_field,
            []
        )

        if not columns:
            continue

        column = columns[0]

        if column not in df.columns:
            continue

        numeric = pd.to_numeric(
            df[column],
            errors="coerce"
        )

        numeric = numeric.replace(
            [np.inf, -np.inf],
            np.nan
        ).dropna()

        if numeric.empty:
            continue

        mean = numeric.mean()
        median = numeric.median()
        p95 = numeric.quantile(0.95)
        p99 = numeric.quantile(0.99)
        maximum = numeric.max()

        if median != 0:

            ratio = (
                mean / abs(median)
            )

        else:
            ratio = None

        if (
            ratio is not None
            and ratio >= 10
        ):

            indicators.append(
                {
                    "indicator_type":
                        "highly_skewed_numeric_distribution",

                    "field":
                        semantic_field,

                    "column":
                        column,

                    "mean":
                        clean_value(mean),

                    "median":
                        clean_value(median),

                    "mean_to_median_ratio":
                        clean_value(ratio),

                    "p95":
                        clean_value(p95),

                    "p99":
                        clean_value(p99),

                    "maximum":
                        clean_value(maximum),

                    "description":
                        (
                            f"The observed "
                            f"'{semantic_field}' measurement "
                            "has a mean substantially higher "
                            "than its median, indicating a "
                            "highly skewed distribution."
                        )
                }
            )

        if (
            p99 != 0
            and maximum >= p99 * 100
        ):

            indicators.append(
                {
                    "indicator_type":
                        "extreme_upper_tail",

                    "field":
                        semantic_field,

                    "column":
                        column,

                    "p99":
                        clean_value(p99),

                    "maximum":
                        clean_value(maximum),

                    "maximum_to_p99_ratio":
                        clean_value(
                            maximum / p99
                        ),

                    "description":
                        (
                            f"The '{semantic_field}' field "
                            "contains extreme upper-tail "
                            "values relative to its "
                            "99th percentile."
                        )
                }
            )

    # --------------------------------------------------------
    # Categorical concentration
    # --------------------------------------------------------

    categorical_fields = [
        "source_port",
        "destination_port",
        "protocol",
        "action"
    ]

    for semantic_field in categorical_fields:

        columns = detected_fields.get(
            semantic_field,
            []
        )

        if not columns:
            continue

        column = columns[0]

        if column not in df.columns:
            continue

        counts = (
            df[column]
            .value_counts(
                dropna=False
            )
        )

        if counts.empty:
            continue

        dominant_value = counts.index[0]
        dominant_count = int(
            counts.iloc[0]
        )

        percentage = safe_percentage(
            dominant_count,
            len(df)
        )

        if percentage >= 70:

            indicators.append(
                {
                    "indicator_type":
                        "destination_or_category_concentration",

                    "field":
                        semantic_field,

                    "column":
                        column,

                    "dominant_value":
                        str(
                            clean_value(
                                dominant_value
                            )
                        ),

                    "dominant_count":
                        dominant_count,

                    "dominant_percentage":
                        percentage,

                    "description":
                        (
                            f"The '{semantic_field}' field "
                            "is strongly concentrated "
                            "around a single observed value."
                        )
                }
            )

    # --------------------------------------------------------
    # Temporal burst
    # --------------------------------------------------------

    timestamp_columns = detected_fields.get(
        "timestamp",
        []
    )

    if timestamp_columns:

        timestamp_column = timestamp_columns[0]

        timestamps = pd.to_datetime(
            df[timestamp_column],
            errors="coerce",
            dayfirst=True
        ).dropna()

        if not timestamps.empty:

            hourly = (
                timestamps
                .dt.hour
                .value_counts()
            )

            peak_hour = int(
                hourly.idxmax()
            )

            peak_count = int(
                hourly.max()
            )

            peak_percentage = safe_percentage(
                peak_count,
                len(timestamps)
            )

            if peak_percentage >= 20:

                indicators.append(
                    {
                        "indicator_type":
                            "temporal_burst",

                        "field":
                            "timestamp",

                        "column":
                            timestamp_column,

                        "peak_hour":
                            peak_hour,

                        "peak_hour_record_count":
                            peak_count,

                        "peak_hour_percentage":
                            peak_percentage,

                        "observation_start":
                            str(
                                timestamps.min()
                            ),

                        "observation_end":
                            str(
                                timestamps.max()
                            ),

                        "description":
                            (
                                "Network activity is strongly "
                                "concentrated within one or more "
                                "time windows relative to the "
                                "overall observed activity."
                            )
                    }
                )

    # --------------------------------------------------------
    # Repetitive destination activity
    # --------------------------------------------------------

    repetitive = (
        calculate_repetitive_destination_activity(
            df,
            schema
        )
    )

    if repetitive:

        indicators.append(
            {
                "indicator_type":
                    "repetitive_destination_activity",

                **repetitive
            }
        )

    return indicators


# ============================================================
# MAIN ANALYSIS
# ============================================================

def main():

    print("=" * 70)
    print("AI SECURITY COPILOT - SECURITY EVIDENCE ANALYSIS")
    print("=" * 70)

    # --------------------------------------------------------
    # Load schema
    # --------------------------------------------------------

    schema = load_json(
        SCHEMA_FILE
    )

    # --------------------------------------------------------
    # Discover datasets
    # --------------------------------------------------------

    csv_files = discover_csv_files()

    print(
        f"\nCSV files discovered: "
        f"{len(csv_files)}"
    )

    for file in csv_files:
        print(
            f"  - {file.name}"
        )

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    df = load_all_data(
        csv_files
    )

    print(
        f"\nRecords: {len(df):,}"
    )

    print(
        f"Total columns: {len(df.columns)}"
    )

    # --------------------------------------------------------
    # Determine mode
    # --------------------------------------------------------

    dataset_mode = determine_dataset_mode(
        df,
        schema
    )

    print(
        f"Dataset mode: {dataset_mode}"
    )

    # --------------------------------------------------------
    # Labelled analysis
    # --------------------------------------------------------

    findings = []

    labelled_behavioural_evidence = []

    if dataset_mode == "LABELLED":

        labelled_behavioural_evidence = (
            build_labelled_findings(
                df,
                schema
            )
        )

        # ----------------------------------------------------
        # Create high-level findings.
        # ----------------------------------------------------

        label_column = schema[
            "detected_fields"
        ]["label"][0]

        labels = (
            df[label_column]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        baseline_label = None

        for label in labels:

            if label.lower() in {
                "benign",
                "normal",
                "legitimate",
                "clean"
            }:

                baseline_label = label
                break

        if baseline_label is None and labels:
            baseline_label = labels[0]

        for index, label in enumerate(
            labels,
            start=1
        ):

            count = int(
                (
                    df[label_column]
                    .astype(str)
                    == str(label)
                ).sum()
            )

            classification = (
                "benign"
                if str(label)
                == str(baseline_label)
                else "attack"
            )

            findings.append(
                {
                    "finding_id":
                        f"label_{index}",

                    "finding_type":
                        "classification_distribution",

                    "classification":
                        classification,

                    "label":
                        label,

                    "record_count":
                        count,

                    "percentage":
                        safe_percentage(
                            count,
                            len(df)
                        ),

                    "description":
                        (
                            f"The dataset contains "
                            f"{count:,} records classified "
                            f"as '{label}'."
                        )
                }
            )

    # --------------------------------------------------------
    # Unlabelled mode
    # --------------------------------------------------------

    behavioural_indicators = (
        build_behavioural_indicators(
            df,
            schema
        )
    )

    if dataset_mode == "UNLABELLED":

        for index, indicator in enumerate(
            behavioural_indicators,
            start=1
        ):

            findings.append(
                {
                    "finding_id":
                        f"anomaly_{index}",

                    "finding_type":
                        indicator.get(
                            "indicator_type"
                        ),

                    "classification":
                        "potential_anomaly",

                    "description":
                        indicator.get(
                            "description"
                        ),

                    "evidence":
                        indicator
                }
            )

    # --------------------------------------------------------
    # Evidence limitations
    # --------------------------------------------------------

    capabilities = schema.get(
        "capabilities",
        {}
    )

    evidence_limitations = []

    limitation_map = {
        "has_source_identity":
            "Source identity information was not detected.",

        "has_destination_identity":
            "Destination identity information was not detected.",

        "has_source_port":
            "Source port information was not detected.",

        "has_action":
            "Action or outcome information was not detected.",

        "has_user_identity":
            "User identity information was not detected.",

        "has_host_identity":
            "Host identity information was not detected.",

        "has_process_data":
            "Process information was not detected.",

        "has_command_data":
            "Command-line information was not detected.",

        "has_event_id":
            "Event or alert identifiers were not detected."
    }

    for capability, message in limitation_map.items():

        if capabilities.get(capability) is False:
            evidence_limitations.append(
                message
            )

    # --------------------------------------------------------
    # Build output
    # --------------------------------------------------------

    output = {
        "version": "3.0",

        "dataset_mode":
            dataset_mode,

        "dataset": {
            "files":
                [
                    file.name
                    for file in csv_files
                ],

            "records":
                len(df),

            "columns":
                len(df.columns)
        },

        "schema":
            schema,

        "findings":
            findings,

        "behavioural_indicators":
            (
                labelled_behavioural_evidence
                if dataset_mode == "LABELLED"
                else behavioural_indicators
            ),

        "generic_behavioural_indicators":
            behavioural_indicators,

        "evidence_limitations":
            evidence_limitations,

        "methodology": {
            "labelled_mode":
                (
                    "Labels are treated as observed "
                    "dataset classifications. Behavioural "
                    "statistics, temporal evidence and "
                    "comparative evidence are calculated "
                    "for each discovered label."
                ),

            "unlabelled_mode":
                (
                    "Potential anomalies are identified "
                    "using generic statistical, categorical, "
                    "temporal and repetitive-activity "
                    "indicators."
                ),

            "attack_specific_rules":
                False,

            "hard_coded_attack_mappings":
                False
        }
    }

    save_json(
        OUTPUT_FILE,
        output
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "\nAnalysis complete."
    )

    print(
        f"Dataset mode: {dataset_mode}"
    )

    print(
        f"Findings: {len(findings)}"
    )

    print(
        "Labelled behavioural evidence: "
        f"{len(labelled_behavioural_evidence)}"
    )

    print(
        "Generic behavioural indicators: "
        f"{len(behavioural_indicators)}"
    )

    print(
        "Evidence limitations: "
        f"{len(evidence_limitations)}"
    )

    print(
        f"\nSaved to: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()