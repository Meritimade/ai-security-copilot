from pathlib import Path

import pandas as pd


# ============================================================
# AI SECURITY COPILOT
# Generic Network Security Log Analyser
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
RAW_DIR = BASE_DIR / "Data" / "raw"


def discover_csv_files():
    """Discover all CSV datasets in the raw data directory."""
    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"Raw dataset directory not found: {RAW_DIR}"
        )

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV datasets found in: {RAW_DIR}"
        )

    return csv_files


def find_label_column(df):
    """Find a likely security label/classification column dynamically."""
    candidates = [
        "Label",
        "label",
        "Class",
        "class",
        "Classification",
        "classification",
        "Attack",
        "attack",
        "Category",
        "category",
    ]

    for column in candidates:
        if column in df.columns:
            return column

    return None


def find_column(df, candidates):
    """Find the first matching column from a list of possible names."""
    for column in candidates:
        if column in df.columns:
            return column

    return None


def analyse_dataset(file_path):
    """Perform generic exploratory security analysis."""
    print("\n" + "=" * 70)
    print("SECURITY DATASET ANALYSIS")
    print("=" * 70)

    print(f"\nDataset: {file_path.name}")

    df = pd.read_csv(file_path, low_memory=False)

    print("\nDataset statistics:")
    print("Number of rows:", len(df))
    print("Number of columns:", len(df.columns))

    print("\nColumns:")
    print(df.columns.tolist())

    # --------------------------------------------------------
    # Discover important fields dynamically
    # --------------------------------------------------------

    label_column = find_label_column(df)

    destination_port = find_column(
        df,
        [
            "Dst Port",
            "Destination Port",
            "destination_port",
            "Dest Port",
        ],
    )

    protocol = find_column(
        df,
        [
            "Protocol",
            "protocol",
        ],
    )

    timestamp = find_column(
        df,
        [
            "Timestamp",
            "timestamp",
            "Time",
            "time",
        ],
    )

    flow_duration = find_column(
        df,
        [
            "Flow Duration",
            "flow_duration",
            "Duration",
            "duration",
        ],
    )

    forward_packets = find_column(
        df,
        [
            "Tot Fwd Pkts",
            "Total Fwd Packets",
            "Fwd Packets",
            "packets_forward",
        ],
    )

    backward_packets = find_column(
        df,
        [
            "Tot Bwd Pkts",
            "Total Bwd Packets",
            "Bwd Packets",
            "packets_backward",
        ],
    )

    flow_bytes_per_second = find_column(
        df,
        [
            "Flow Byts/s",
            "Flow Bytes/s",
            "Bytes/s",
            "flow_bytes_per_second",
        ],
    )

    flow_packets_per_second = find_column(
        df,
        [
            "Flow Pkts/s",
            "Flow Packets/s",
            "Packets/s",
            "flow_packets_per_second",
        ],
    )

    syn_flags = find_column(
        df,
        [
            "SYN Flag Cnt",
            "SYN Flags",
            "syn_flags",
        ],
    )

    rst_flags = find_column(
        df,
        [
            "RST Flag Cnt",
            "RST Flags",
            "rst_flags",
        ],
    )

    # --------------------------------------------------------
    # Dataset classification
    # --------------------------------------------------------

    print("\nDataset mode:")

    if label_column:
        print("LABELLED")
        print(f"Label column discovered: {label_column}")
    else:
        print("UNLABELLED")
        print("No security label column detected.")

    # --------------------------------------------------------
    # Security labels
    # --------------------------------------------------------

    if label_column:
        print("\nSecurity classifications:")

        label_counts = df[label_column].value_counts(dropna=False)

        print(label_counts)

        print("\nClassification percentages:")

        percentages = (
            df[label_column]
            .value_counts(normalize=True, dropna=False)
            .mul(100)
            .round(4)
        )

        print(percentages)

    # --------------------------------------------------------
    # Destination port analysis
    # --------------------------------------------------------

    if destination_port:
        print("\nTop destination ports:")

        print(
            df[destination_port]
            .value_counts(dropna=False)
            .head(20)
        )

    else:
        print("\nDestination port:")
        print("Not available in this dataset.")

    # --------------------------------------------------------
    # Protocol analysis
    # --------------------------------------------------------

    if protocol:
        print("\nProtocols:")

        print(
            df[protocol]
            .value_counts(dropna=False)
            .head(20)
        )

    else:
        print("\nProtocol:")
        print("Not available in this dataset.")

    # --------------------------------------------------------
    # Timestamp analysis
    # --------------------------------------------------------

    if timestamp:
        print("\nTimestamp analysis:")

        timestamps = pd.to_datetime(
            df[timestamp],
            errors="coerce"
        )

        valid_timestamps = timestamps.dropna()

        print("Valid timestamps:", len(valid_timestamps))

        if not valid_timestamps.empty:
            print("Earliest:", valid_timestamps.min())
            print("Latest:", valid_timestamps.max())

    else:
        print("\nTimestamp:")
        print("Not available in this dataset.")

    # --------------------------------------------------------
    # Flow duration
    # --------------------------------------------------------

    if flow_duration:
        numeric_duration = pd.to_numeric(
            df[flow_duration],
            errors="coerce"
        )

        print("\nFlow duration statistics:")

        print(
            numeric_duration.describe()
        )

        print(
            "\nNegative duration records:",
            (numeric_duration < 0).sum()
        )

        print(
            "Zero-duration records:",
            (numeric_duration == 0).sum()
        )

    # --------------------------------------------------------
    # Packet analysis
    # --------------------------------------------------------

    if forward_packets:
        numeric_forward = pd.to_numeric(
            df[forward_packets],
            errors="coerce"
        )

        print("\nForward packet statistics:")
        print(numeric_forward.describe())

    if backward_packets:
        numeric_backward = pd.to_numeric(
            df[backward_packets],
            errors="coerce"
        )

        print("\nBackward packet statistics:")
        print(numeric_backward.describe())

    # --------------------------------------------------------
    # Flow rate analysis
    # --------------------------------------------------------

    if flow_bytes_per_second:
        numeric_bytes_rate = pd.to_numeric(
            df[flow_bytes_per_second],
            errors="coerce"
        )

        print("\nFlow bytes/second:")

        print(
            numeric_bytes_rate.describe()
        )

        infinite_bytes = numeric_bytes_rate.isin(
            [float("inf"), float("-inf")]
        ).sum()

        print(
            "Infinite values:",
            infinite_bytes
        )

        print(
            "Missing values:",
            numeric_bytes_rate.isna().sum()
        )

    if flow_packets_per_second:
        numeric_packets_rate = pd.to_numeric(
            df[flow_packets_per_second],
            errors="coerce"
        )

        print("\nFlow packets/second:")

        print(
            numeric_packets_rate.describe()
        )

        infinite_packets = numeric_packets_rate.isin(
            [float("inf"), float("-inf")]
        ).sum()

        print(
            "Infinite values:",
            infinite_packets
        )

        print(
            "Missing values:",
            numeric_packets_rate.isna().sum()
        )

    # --------------------------------------------------------
    # TCP flag analysis
    # --------------------------------------------------------

    if syn_flags:
        numeric_syn = pd.to_numeric(
            df[syn_flags],
            errors="coerce"
        )

        print("\nSYN flag statistics:")
        print(numeric_syn.describe())

    if rst_flags:
        numeric_rst = pd.to_numeric(
            df[rst_flags],
            errors="coerce"
        )

        print("\nRST flag statistics:")
        print(numeric_rst.describe())

    # --------------------------------------------------------
    # Missing-value overview
    # --------------------------------------------------------

    print("\nMissing values by column:")

    missing = df.isna().sum()

    missing = missing[missing > 0].sort_values(
        ascending=False
    )

    if missing.empty:
        print("No missing values detected.")
    else:
        print(missing.head(20))

    # --------------------------------------------------------
    # Security interpretation boundary
    # --------------------------------------------------------

    print("\nAnalysis boundary:")
    print(
        "This analyser reports observed telemetry and "
        "dataset classifications only."
    )

    print(
        "It does not hard-code attack types, ports, "
        "protocols, or MITRE ATT&CK mappings."
    )

    print(
        "Security findings and ATT&CK assessments are "
        "generated by the downstream evidence-based pipeline."
    )

    print("\n" + "=" * 70)
    print("DATASET ANALYSIS COMPLETE")
    print("=" * 70)


def main():
    print("=" * 70)
    print("AI SECURITY COPILOT - GENERIC LOG ANALYSER")
    print("=" * 70)

    csv_files = discover_csv_files()

    print(f"\nCSV files discovered: {len(csv_files)}")

    for file_path in csv_files:
        print(f" - {file_path.name}")

    # Analyse every discovered CSV.
    for file_path in csv_files:
        analyse_dataset(file_path)


if __name__ == "__main__":
    main()