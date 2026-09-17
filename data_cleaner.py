import pandas as pd
from pathlib import Path


# ============================================================
# AI SECURITY COPILOT
# DATA CLEANER
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RAW_DIR = BASE_DIR / "Data" / "raw"
PROCESSED_DIR = BASE_DIR / "Data" / "processed"

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# HELPERS
# ============================================================

def detect_timestamp_column(df):
    """
    Detect a timestamp column using common security-data names.
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


def parse_timestamp(series):
    """
    Parse timestamp values without interpreting ordinary
    date strings as Unix epoch timestamps.
    """

    text = (
        series
        .astype("string")
        .str.strip()
    )

    result = pd.Series(
        pd.NaT,
        index=series.index,
        dtype="datetime64[ns]"
    )

    # --------------------------------------------------------
    # Text timestamps
    # --------------------------------------------------------

    textual_mask = (
        text.notna()
        & ~text.str.fullmatch(
            r"-?\d+(\.\d+)?",
            na=False
        )
    )

    if textual_mask.any():

        parsed = pd.to_datetime(
            text.loc[textual_mask],
            errors="coerce",
            format="mixed",
            dayfirst=True
        )

        result.loc[textual_mask] = parsed

    # --------------------------------------------------------
    # Numeric timestamps
    # --------------------------------------------------------

    numeric_mask = (
        text.notna()
        & text.str.fullmatch(
            r"-?\d+(\.\d+)?",
            na=False
        )
    )

    if numeric_mask.any():

        numeric = pd.to_numeric(
            text.loc[numeric_mask],
            errors="coerce"
        )

        absolute = numeric.abs()

        # Seconds
        mask_seconds = absolute.between(
            1_000_000_000,
            10_000_000_000
        )

        if mask_seconds.any():

            parsed = pd.to_datetime(
                numeric.loc[mask_seconds],
                unit="s",
                errors="coerce"
            )

            result.loc[
                numeric.loc[mask_seconds].index
            ] = parsed

        # Milliseconds
        mask_ms = absolute.between(
            1_000_000_000_000,
            10_000_000_000_000
        )

        if mask_ms.any():

            parsed = pd.to_datetime(
                numeric.loc[mask_ms],
                unit="ms",
                errors="coerce"
            )

            result.loc[
                numeric.loc[mask_ms].index
            ] = parsed

        # Microseconds
        mask_us = absolute.between(
            1_000_000_000_000_000,
            10_000_000_000_000_000
        )

        if mask_us.any():

            parsed = pd.to_datetime(
                numeric.loc[mask_us],
                unit="us",
                errors="coerce"
            )

            result.loc[
                numeric.loc[mask_us].index
            ] = parsed

        # Nanoseconds
        mask_ns = absolute.between(
            1_000_000_000_000_000_000,
            10_000_000_000_000_000_000
        )

        if mask_ns.any():

            parsed = pd.to_datetime(
                numeric.loc[mask_ns],
                unit="ns",
                errors="coerce"
            )

            result.loc[
                numeric.loc[mask_ns].index
            ] = parsed

    return result


# ============================================================
# PROCESS ONE CSV
# ============================================================

def clean_file(input_file):
    """
    Clean one CSV file and save it to Data/processed.
    """

    print()
    print("=" * 70)
    print(
        f"PROCESSING: {input_file.name}"
    )
    print("=" * 70)

    print(
        f"Loading: {input_file}"
    )

    df = pd.read_csv(
        input_file,
        low_memory=False
    )

    original_rows = len(df)

    print(
        f"Original records: "
        f"{original_rows:,}"
    )

    print(
        f"Original columns: "
        f"{len(df.columns)}"
    )

    # ========================================================
    # REMOVE WHITESPACE FROM COLUMN NAMES
    # ========================================================

    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    # ========================================================
    # NUMERIC CLEANING
    # ========================================================

    numeric_columns = df.select_dtypes(
        include="number"
    ).columns

    for column in numeric_columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    # ========================================================
    # INFINITE VALUES
    # ========================================================

    infinite_counts = {}

    for column in numeric_columns:

        count = int(
            df[column]
            .isin(
                [
                    float("inf"),
                    float("-inf")
                ]
            )
            .sum()
        )

        if count > 0:

            infinite_counts[column] = count

            df.loc[
                df[column].isin(
                    [
                        float("inf"),
                        float("-inf")
                    ]
                ),
                column
            ] = pd.NA

    if infinite_counts:

        print()
        print(
            "Infinite values replaced with missing:"
        )

        for column, count in infinite_counts.items():

            print(
                f"  {column}: {count:,}"
            )

    else:

        print()
        print(
            "No infinite values detected."
        )

    # ========================================================
    # NEGATIVE FLOW DURATION
    # ========================================================

    duration_column = None

    duration_candidates = [
        "Flow Duration",
        "Duration",
        "flow_duration"
    ]

    for candidate in duration_candidates:

        if candidate in df.columns:

            duration_column = candidate
            break

    negative_duration_count = 0

    negative_duration_mask = pd.Series(
        False,
        index=df.index
    )

    if duration_column:

        duration = pd.to_numeric(
            df[duration_column],
            errors="coerce"
        )

        negative_duration_mask = (
            duration < 0
        )

        negative_duration_count = int(
            negative_duration_mask.sum()
        )

        print()
        print(
            f"Negative {duration_column} records: "
            f"{negative_duration_count:,}"
        )

    # ========================================================
    # TIMESTAMP VALIDATION
    # ========================================================

    timestamp_column = detect_timestamp_column(
        df
    )

    invalid_timestamp_count = 0
    suspicious_timestamp_count = 0

    invalid_timestamp_mask = pd.Series(
        False,
        index=df.index
    )

    suspicious_timestamp_mask = pd.Series(
        False,
        index=df.index
    )

    if timestamp_column:

        print()
        print(
            f"Timestamp column detected: "
            f"{timestamp_column}"
        )

        parsed_timestamps = parse_timestamp(
            df[timestamp_column]
        )

        invalid_timestamp_mask = (
            parsed_timestamps.isna()
            & df[timestamp_column].notna()
        )

        invalid_timestamp_count = int(
            invalid_timestamp_mask.sum()
        )

        # A security dataset from a modern capture should not
        # contain dates centuries earlier than the surrounding
        # data. We flag these for review rather than blindly
        # deleting them.

        suspicious_timestamp_mask = (
            parsed_timestamps
            < pd.Timestamp("2000-01-01")
        )

        suspicious_timestamp_count = int(
            suspicious_timestamp_mask.sum()
        )

        print(
            f"Invalid timestamps: "
            f"{invalid_timestamp_count:,}"
        )

        print(
            f"Pre-2000 timestamps: "
            f"{suspicious_timestamp_count:,}"
        )

        if suspicious_timestamp_count > 0:

            print()
            print(
                "Suspicious timestamp examples:"
            )

            examples = df.loc[
                suspicious_timestamp_mask,
                timestamp_column
            ].head(10)

            for value in examples:

                print(
                    f"  {repr(value)}"
                )

    else:

        parsed_timestamps = None

        print(
            "No timestamp column detected."
        )

    # ========================================================
    # REMOVE CORRUPTED RECORDS
    # ========================================================
    #
    # We remove records when BOTH conditions indicate that
    # the record is corrupted:
    #
    #   1. Timestamp is before 2000
    #   2. Flow Duration is negative
    #
    # This avoids deleting a legitimate historical timestamp
    # from another type of dataset merely because it is old.
    #
    # In this CSE-CIC-IDS2018 file, the five problematic records
    # satisfy both conditions.
    #
    # ========================================================

    corrupted_record_mask = (
        suspicious_timestamp_mask
        & negative_duration_mask
    )

    corrupted_record_count = int(
        corrupted_record_mask.sum()
    )

    if corrupted_record_count > 0:

        print()
        print(
            "Corrupted records identified: "
            f"{corrupted_record_count:,}"
        )

        print(
            "Reason:"
        )

        print(
            "  - Suspicious pre-2000 timestamp"
        )

        print(
            "  - Negative flow duration"
        )

        print()
        print(
            "Removing corrupted records "
            "from processed analysis data..."
        )

        df = df.loc[
            ~corrupted_record_mask
        ].copy()

    else:

        print()
        print(
            "No records met the combined "
            "corruption criteria."
        )

    # ========================================================
    # NEGATIVE FLOW DURATION CLEANUP
    # ========================================================
    #
    # Any remaining negative duration values are converted
    # to missing rather than silently changing them.
    #
    # ========================================================

    if duration_column:

        remaining_duration = pd.to_numeric(
            df[duration_column],
            errors="coerce"
        )

        remaining_negative_mask = (
            remaining_duration < 0
        )

        remaining_negative_count = int(
            remaining_negative_mask.sum()
        )

        if remaining_negative_count > 0:

            print()
            print(
                "Remaining negative duration records: "
                f"{remaining_negative_count:,}"
            )

            df.loc[
                remaining_negative_mask,
                duration_column
            ] = pd.NA

    # ========================================================
    # FINAL INFINITE VALUE CHECK
    # ========================================================

    for column in df.select_dtypes(
        include="number"
    ).columns:

        df[column] = df[column].replace(
            [
                float("inf"),
                float("-inf")
            ],
            pd.NA
        )

    # ========================================================
    # SAVE
    # ========================================================

    output_file = (
        PROCESSED_DIR
        / f"{input_file.stem}_clean.csv"
    )

    df.to_csv(
        output_file,
        index=False
    )

    final_rows = len(df)

    removed_rows = (
        original_rows
        - final_rows
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("CLEANING SUMMARY")
    print("=" * 70)

    print(
        f"Original records: "
        f"{original_rows:,}"
    )

    print(
        f"Records removed: "
        f"{removed_rows:,}"
    )

    print(
        f"Final records: "
        f"{final_rows:,}"
    )

    print(
        f"Columns: "
        f"{len(df.columns)}"
    )

    if timestamp_column:

        final_timestamps = parse_timestamp(
            df[timestamp_column]
        )

        valid_final_timestamps = (
            final_timestamps.dropna()
        )

        if len(valid_final_timestamps) > 0:

            print(
                f"Final earliest timestamp: "
                f"{valid_final_timestamps.min()}"
            )

            print(
                f"Final latest timestamp: "
                f"{valid_final_timestamps.max()}"
            )

    print()
    print(
        f"Saved cleaned dataset:"
    )

    print(
        output_file
    )

    return output_file


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("AI SECURITY COPILOT")
    print("DATA CLEANING PIPELINE")
    print("=" * 70)

    print()
    print(
        f"Raw data directory: "
        f"{RAW_DIR}"
    )

    print(
        f"Processed data directory: "
        f"{PROCESSED_DIR}"
    )

    if not RAW_DIR.exists():

        raise FileNotFoundError(
            f"Raw data directory not found:\n"
            f"{RAW_DIR}"
        )

    csv_files = sorted(
        RAW_DIR.glob("*.csv")
    )

    if not csv_files:

        raise FileNotFoundError(
            f"No CSV files found in:\n"
            f"{RAW_DIR}"
        )

    print()
    print(
        f"CSV files discovered: "
        f"{len(csv_files)}"
    )

    for file in csv_files:

        print(
            f"  - {file.name}"
        )

    processed_files = []

    for input_file in csv_files:

        output_file = clean_file(
            input_file
        )

        processed_files.append(
            output_file
        )

    # ========================================================
    # FINAL
    # ========================================================

    print()
    print("=" * 70)
    print("DATA CLEANING COMPLETE")
    print("=" * 70)

    print(
        f"Files processed: "
        f"{len(processed_files)}"
    )

    for file in processed_files:

        print(
            f"  [PASS] {file.name}"
        )

    print()
    print(
        "Original raw datasets were not modified."
    )


if __name__ == "__main__":
    main()