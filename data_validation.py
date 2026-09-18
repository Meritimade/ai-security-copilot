import pandas as pd
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

PROCESSED_DIR = (
    BASE_DIR
    / "Data"
    / "processed"
)


# ============================================================
# HELPERS
# ============================================================

def print_section(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def discover_processed_datasets():
    """
    Discover every CSV dataset currently available in the
    processed data directory.

    No dataset filename is hard-coded.
    """

    if not PROCESSED_DIR.exists():
        return []

    datasets = sorted(
        PROCESSED_DIR.glob("*.csv")
    )

    return [
        path
        for path in datasets
        if path.is_file()
    ]


def detect_timestamp_column(df):
    """
    Detect a timestamp column using common security-log naming.
    """

    candidates = [
        "Timestamp",
        "timestamp",
        "Date",
        "date",
        "Datetime",
        "datetime",
        "Time",
        "time",
        "Event Time",
        "EventTime",
    ]

    for column in candidates:
        if column in df.columns:
            return column

    # Semantic fallback
    for column in df.columns:

        name = str(column).strip().lower()

        if (
            "timestamp" in name
            or "datetime" in name
            or name == "date"
            or name == "time"
        ):
            return column

    return None


def parse_timestamp_safely(series):
    """
    Parse timestamps while avoiding accidental interpretation
    of numeric-looking values as nanoseconds.
    """

    original = series.copy()

    text = original.astype("string").str.strip()

    result = pd.Series(
        pd.NaT,
        index=series.index,
        dtype="datetime64[ns]"
    )

    # --------------------------------------------------------
    # 1. Parse textual timestamps
    # --------------------------------------------------------

    textual_mask = (
        text.notna()
        & ~text.str.fullmatch(
            r"-?\d+(\.\d+)?",
            na=False
        )
    )

    if textual_mask.any():

        parsed_text = pd.to_datetime(
            text.loc[textual_mask],
            errors="coerce",
            format="mixed",
            dayfirst=True
        )

        result.loc[textual_mask] = parsed_text

    # --------------------------------------------------------
    # 2. Parse numeric timestamps
    # --------------------------------------------------------

    numeric_mask = (
        text.notna()
        & text.str.fullmatch(
            r"-?\d+(\.\d+)?",
            na=False
        )
    )

    if numeric_mask.any():

        numeric_values = pd.to_numeric(
            text.loc[numeric_mask],
            errors="coerce"
        )

        abs_values = numeric_values.abs()

        # Unix seconds
        seconds_mask = abs_values.between(
            1_000_000_000,
            10_000_000_000
        )

        # Unix milliseconds
        milliseconds_mask = abs_values.between(
            1_000_000_000_000,
            10_000_000_000_000
        )

        # Unix microseconds
        microseconds_mask = abs_values.between(
            1_000_000_000_000_000,
            10_000_000_000_000_000
        )

        # Unix nanoseconds
        nanoseconds_mask = abs_values.between(
            1_000_000_000_000_000_000,
            10_000_000_000_000_000_000
        )

        if seconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[seconds_mask],
                unit="s",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[seconds_mask].index
            ] = parsed

        if milliseconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[milliseconds_mask],
                unit="ms",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[milliseconds_mask].index
            ] = parsed

        if microseconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[microseconds_mask],
                unit="us",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[microseconds_mask].index
            ] = parsed

        if nanoseconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[nanoseconds_mask],
                unit="ns",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[nanoseconds_mask].index
            ] = parsed

    return result


def detect_label_columns(df):
    """
    Detect common security label fields dynamically.
    """

    label_names = {
        "label",
        "class",
        "attack",
        "attack_type",
        "category",
        "target"
    }

    return [
        column
        for column in df.columns
        if str(column).strip().lower() in label_names
    ]


def detect_field(df, candidates):
    """
    Return the first matching field from a list of possible
    column names.
    """

    for candidate in candidates:

        if candidate in df.columns:
            return candidate

    return None


# ============================================================
# START
# ============================================================

print("=" * 70)
print("SECURITY DATA VALIDATION")
print("=" * 70)


# ============================================================
# DISCOVER DATASETS
# ============================================================

print_section(
    "DATASET DISCOVERY"
)

datasets = discover_processed_datasets()


if not datasets:

    raise FileNotFoundError(
        "No processed CSV datasets were found in:\n"
        f"{PROCESSED_DIR}"
    )


print(
    f"Processed datasets discovered: "
    f"{len(datasets)}"
)

for dataset in datasets:

    print(
        f"  - {dataset.name}"
    )


# ============================================================
# LOAD ALL PROCESSED DATASETS
# ============================================================

frames = []

for dataset in datasets:

    print()
    print(
        f"Loading: {dataset.name}"
    )

    current_df = pd.read_csv(
        dataset,
        low_memory=False
    )

    # Keep track of the originating dataset.
    current_df["Source_File"] = dataset.name

    print(
        f"  Rows: {len(current_df):,}"
    )

    print(
        f"  Columns: {len(current_df.columns):,}"
    )

    frames.append(current_df)


if not frames:

    raise FileNotFoundError(
        "No readable processed datasets were found."
    )


# Combine datasets for validation.
df = pd.concat(
    frames,
    ignore_index=True,
    sort=False
)


print()
print(
    f"Combined rows: {len(df):,}"
)

print(
    f"Combined columns: {len(df.columns):,}"
)


# ============================================================
# COLUMN INVENTORY
# ============================================================

print_section(
    "COLUMN INVENTORY"
)

for column in df.columns:

    print(
        f"  - {column}"
    )


# ============================================================
# DUPLICATE RECORD CHECK
# ============================================================

print_section(
    "DUPLICATE RECORD CHECK"
)

# Exclude Source_File from duplicate detection because
# identical telemetry appearing in different files should
# still be considered duplicate telemetry.

duplicate_columns = [
    column
    for column in df.columns
    if column != "Source_File"
]

duplicate_count = int(
    df.duplicated(
        subset=duplicate_columns
    ).sum()
)

print(
    f"Duplicate records: "
    f"{duplicate_count:,}"
)


# ============================================================
# INFINITE VALUE CHECK
# ============================================================

print_section(
    "INFINITE VALUE CHECK"
)

numeric_columns = df.select_dtypes(
    include="number"
).columns

infinite_count = 0

for column in numeric_columns:

    count = int(
        df[column]
        .isin([
            float("inf"),
            float("-inf")
        ])
        .sum()
    )

    infinite_count += count


if infinite_count == 0:

    print(
        "No infinite values detected."
    )

else:

    print(
        f"Infinite values detected: "
        f"{infinite_count:,}"
    )


# ============================================================
# MISSING VALUE CHECK
# ============================================================

print_section(
    "MISSING VALUE CHECK"
)

missing = df.isna().sum()

missing = missing[
    missing > 0
].sort_values(
    ascending=False
)

if len(missing) == 0:

    print(
        "No missing values detected."
    )

else:

    print(
        missing
    )


# ============================================================
# SECURITY LABEL CHECK
# ============================================================

print_section(
    "SECURITY LABEL CHECK"
)

label_candidates = detect_label_columns(
    df
)


if label_candidates:

    print(
        "Security label column(s) detected:"
    )

    for label_column in label_candidates:

        print(
            f"  - {label_column}"
        )

    dataset_mode = "LABELLED"

    for label_column in label_candidates:

        print()
        print(
            f"Label distribution: "
            f"{label_column}"
        )

        print(
            df[label_column]
            .value_counts(
                dropna=False
            )
            .head(20)
        )

else:

    print(
        "No security label column detected."
    )

    print(
        "Dataset will be treated as UNLABELLED."
    )

    print(
        "Security findings must therefore be based "
        "on telemetry and behavioural evidence."
    )

    dataset_mode = "UNLABELLED"


# ============================================================
# TIMESTAMP CHECK
# ============================================================

print_section(
    "TIMESTAMP CHECK"
)

timestamp_column = detect_timestamp_column(
    df
)


if timestamp_column is None:

    print(
        "No timestamp column detected."
    )

else:

    print(
        f"Timestamp column detected: "
        f"{timestamp_column}"
    )

    parsed_timestamps = parse_timestamp_safely(
        df[timestamp_column]
    )

    valid_count = int(
        parsed_timestamps.notna().sum()
    )

    invalid_count = int(
        parsed_timestamps.isna().sum()
    )

    print()
    print(
        f"{timestamp_column}:"
    )

    print(
        f"  Valid timestamps: "
        f"{valid_count:,}"
    )

    print(
        f"  Invalid timestamps: "
        f"{invalid_count:,}"
    )

    if valid_count > 0:

        earliest = parsed_timestamps.min()
        latest = parsed_timestamps.max()

        print(
            f"  Earliest: {earliest}"
        )

        print(
            f"  Latest: {latest}"
        )

        suspicious_cutoff = pd.Timestamp(
            "2000-01-01"
        )

        suspicious_count = int(
            (
                parsed_timestamps
                < suspicious_cutoff
            ).sum()
        )

        if suspicious_count > 0:

            print(
                f"  Pre-2000 timestamps: "
                f"{suspicious_count:,}"
            )

            print(
                "  Status: REVIEW - "
                "some timestamps are unexpectedly old."
            )

            print()
            print(
                "  Example raw timestamp values:"
            )

            examples = df.loc[
                parsed_timestamps
                < suspicious_cutoff,
                timestamp_column
            ].head(10)

            for value in examples:

                print(
                    f"    {repr(value)}"
                )

        else:

            print(
                "  Status: PASS"
            )

    else:

        print(
            "  Status: FAIL - "
            "no valid timestamps could be parsed."
        )


# ============================================================
# FLOW DURATION CHECK
# ============================================================

print_section(
    "FLOW DURATION CHECK"
)

duration_candidates = [
    column
    for column in df.columns
    if str(column).strip().lower()
    in {
        "flow duration",
        "duration",
        "flow_duration"
    }
]


if duration_candidates:

    duration_column = duration_candidates[0]

    duration_numeric = pd.to_numeric(
        df[duration_column],
        errors="coerce"
    )

    negative_count = int(
        (
            duration_numeric < 0
        ).sum()
    )

    print(
        f"{duration_column}:"
    )

    print(
        f"  Negative values: "
        f"{negative_count:,}"
    )

    if negative_count == 0:

        print(
            "  Status: PASS"
        )

    else:

        print(
            "  Status: REVIEW"
        )

else:

    print(
        "Flow Duration field not detected."
    )


# ============================================================
# NETWORK TELEMETRY CHECK
# ============================================================

print_section(
    "NETWORK TELEMETRY CHECK"
)

network_fields = {

    "Destination Port": [
        "Dst Port",
        "Destination Port",
        "destination_port"
    ],

    "Protocol": [
        "Protocol",
        "protocol"
    ],

    "Timestamp": [
        "Timestamp",
        "timestamp"
    ],

    "Flow Duration": [
        "Flow Duration",
        "Duration",
        "flow_duration"
    ],

    "Forward Packets": [
        "Tot Fwd Pkts",
        "Total Fwd Packets",
        "Forward Packets"
    ],

    "Backward Packets": [
        "Tot Bwd Pkts",
        "Total Bwd Packets",
        "Backward Packets"
    ]
}


for display_name, candidates in network_fields.items():

    detected = detect_field(
        df,
        candidates
    )

    if detected:

        print(
            f"[PASS] {display_name}: "
            f"{detected}"
        )

    else:

        print(
            f"[MISSING] {display_name}"
        )


# ============================================================
# DATASET SUMMARY
# ============================================================

print_section(
    "DATASET SUMMARY"
)

print(
    f"Datasets validated: "
    f"{len(datasets)}"
)

print(
    f"Dataset mode: "
    f"{dataset_mode}"
)

print(
    f"Rows validated: "
    f"{len(df):,}"
)

print(
    f"Columns validated: "
    f"{len(df.columns):,}"
)

print(
    f"Duplicate records: "
    f"{duplicate_count:,}"
)

print(
    f"Infinite values: "
    f"{infinite_count:,}"
)


# ============================================================
# PER-FILE SUMMARY
# ============================================================

print_section(
    "PER-DATASET SUMMARY"
)

for dataset in datasets:

    dataset_rows = int(
        (
            df["Source_File"]
            == dataset.name
        ).sum()
    )

    print(
        f"{dataset.name}: "
        f"{dataset_rows:,} rows"
    )


# ============================================================
# COMPLETION
# ============================================================

print_section(
    "VALIDATION COMPLETE"
)

print(
    "All discovered processed datasets were validated."
)

print(
    "The datasets are ready for schema discovery "
    "and behavioural security analysis."
)