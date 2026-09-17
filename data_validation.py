import pandas as pd
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_FILE = (
    BASE_DIR
    / "Data"
    / "processed"
    / "02-14-2018_clean.csv"
)


# ============================================================
# HELPERS
# ============================================================

def print_section(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


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

    # Fallback: semantic search
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
    of numeric-looking values as nanoseconds from Unix epoch.

    Strategy:
    1. Convert everything to strings.
    2. Parse normal textual timestamps first.
    3. Separately inspect numeric-looking values.
    4. Try common Unix timestamp units only when appropriate.
    """

    original = series.copy()

    # Convert to pandas string representation.
    text = original.astype("string").str.strip()

    result = pd.Series(
        pd.NaT,
        index=series.index,
        dtype="datetime64[ns]"
    )

    # --------------------------------------------------------
    # 1. Parse textual date/time values
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
    # 2. Parse numeric timestamps separately
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

        # Determine likely unit based on magnitude.
        #
        # Seconds:
        # approximately 10 digits for modern Unix timestamps.
        #
        # Milliseconds:
        # approximately 13 digits.
        #
        # Microseconds:
        # approximately 16 digits.
        #
        # Nanoseconds:
        # approximately 19 digits.

        abs_values = numeric_values.abs()

        seconds_mask = (
            abs_values.between(
                1_000_000_000,
                10_000_000_000
            )
        )

        milliseconds_mask = (
            abs_values.between(
                1_000_000_000_000,
                10_000_000_000_000
            )
        )

        microseconds_mask = (
            abs_values.between(
                1_000_000_000_000_000,
                10_000_000_000_000_000
            )
        )

        nanoseconds_mask = (
            abs_values.between(
                1_000_000_000_000_000_000,
                10_000_000_000_000_000_000
            )
        )

        # Seconds
        if seconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[seconds_mask],
                unit="s",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[seconds_mask].index
            ] = parsed

        # Milliseconds
        if milliseconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[milliseconds_mask],
                unit="ms",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[milliseconds_mask].index
            ] = parsed

        # Microseconds
        if microseconds_mask.any():

            parsed = pd.to_datetime(
                numeric_values.loc[microseconds_mask],
                unit="us",
                errors="coerce"
            )

            result.loc[
                numeric_values.loc[microseconds_mask].index
            ] = parsed

        # Nanoseconds
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


# ============================================================
# START
# ============================================================

print("=" * 70)
print("SECURITY DATA VALIDATION")
print("=" * 70)

print()
print(f"Loading: {DATA_FILE}")


if not DATA_FILE.exists():

    raise FileNotFoundError(
        f"Dataset not found:\n{DATA_FILE}"
    )


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(
    DATA_FILE,
    low_memory=False
)


print()
print(f"Rows: {len(df):,}")
print(f"Columns: {len(df.columns)}")


# ============================================================
# COLUMN INVENTORY
# ============================================================

print_section(
    "COLUMN INVENTORY"
)

for column in df.columns:
    print(f"  - {column}")


# ============================================================
# DUPLICATE RECORD CHECK
# ============================================================

print_section(
    "DUPLICATE RECORD CHECK"
)

duplicate_count = int(
    df.duplicated().sum()
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
        .isin([float("inf"), float("-inf")])
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

    print(missing)


# ============================================================
# SECURITY LABEL CHECK
# ============================================================

print_section(
    "SECURITY LABEL CHECK"
)

label_candidates = [
    column
    for column in df.columns
    if str(column).strip().lower()
    in {
        "label",
        "class",
        "attack",
        "attack_type",
        "category",
        "target"
    }
]


if label_candidates:

    print(
        f"Security label column(s) detected: "
        f"{label_candidates}"
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
            .value_counts(dropna=False)
            .head(20)
        )

else:

    print(
        "No Label column detected."
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
        f"Timestamp candidate(s): "
        f"['{timestamp_column}']"
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

        # ----------------------------------------------------
        # Detect suspiciously old timestamps
        # ----------------------------------------------------

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

            # Show examples to help diagnose the source.
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

    detected = None

    for candidate in candidates:

        if candidate in df.columns:
            detected = candidate
            break

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
# VALIDATION SUMMARY
# ============================================================

print_section(
    "VALIDATION SUMMARY"
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
    f"{len(df.columns)}"
)

print(
    f"Duplicate records: "
    f"{duplicate_count:,}"
)

print()

print(
    "Validation complete."
)

print(
    "The dataset is ready for schema discovery "
    "and behavioural security analysis."
)