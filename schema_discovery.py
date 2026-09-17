from pathlib import Path
import json
import re
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROCESSED_DIR = Path("Data/processed")
OUTPUT_FILE = Path("security_schema.json")


# ============================================================
# FIELD PATTERNS
# ============================================================
# These patterns describe generic telemetry concepts.
#
# They do NOT identify specific attacks.
#
# The purpose is to understand what a column represents so
# that later analysis can use the correct security evidence.
# ============================================================

FIELD_PATTERNS = {

    # --------------------------------------------------------
    # TIME
    # --------------------------------------------------------

    "timestamp": [
        r"^timestamp$",
        r"timestamp",
        r"date time",
        r"datetime",
        r"event time",
        r"log time"
    ],


    # --------------------------------------------------------
    # NETWORK IDENTITY
    # --------------------------------------------------------

    "source_ip": [
        r"^src ip$",
        r"^source ip$",
        r"source address",
        r"client ip",
        r"origin ip"
    ],

    "destination_ip": [
        r"^dst ip$",
        r"^dest ip$",
        r"^destination ip$",
        r"destination address",
        r"server ip"
    ],

    "source_port": [
        r"^src port$",
        r"^source port$",
        r"client port"
    ],

    "destination_port": [
        r"^dst port$",
        r"^dest port$",
        r"^destination port$",
        r"server port"
    ],

    "protocol": [
        r"^protocol$",
        r"^proto$",
        r"network protocol"
    ],


    # --------------------------------------------------------
    # CLASSIFICATION / EVENT INFORMATION
    # --------------------------------------------------------

    "label": [
        r"^label$",
        r"^class$",
        r"^classification$",
        r"category",
        r"attack type"
    ],

    "action": [
        r"^action$",
        r"event action",
        r"response action",
        r"decision"
    ],

    "event_id": [
        r"^event id$",
        r"eventid",
        r"alert id",
        r"incident id"
    ],


    # --------------------------------------------------------
    # IDENTITY / HOST / PROCESS
    # --------------------------------------------------------

    "username": [
        r"^user$",
        r"^username$",
        r"user name",
        r"account",
        r"account name"
    ],

    "hostname": [
        r"^host$",
        r"^hostname$",
        r"host name",
        r"computer name",
        r"device name"
    ],

    "process": [
        r"^process$",
        r"process name",
        r"process id",
        r"parent process"
    ],

    "command": [
        r"^command$",
        r"command line",
        r"cmdline",
        r"shell command"
    ],


    # --------------------------------------------------------
    # DURATION
    # --------------------------------------------------------

    "duration": [
        r"^duration$",
        r"flow duration",
        r"session duration",
        r"connection duration"
    ],


    # --------------------------------------------------------
    # PACKET COUNTS
    # --------------------------------------------------------

    "packets_forward": [
        r"^tot fwd pkts$",
        r"^fwd packets$",
        r"^forward packets$",
        r"forward packet count",
        r"packets forward"
    ],

    "packets_backward": [
        r"^tot bwd pkts$",
        r"^bwd packets$",
        r"^backward packets$",
        r"backward packet count",
        r"packets backward"
    ],

    "packets_total": [
        r"^total packets$",
        r"^packet count$",
        r"packets total"
    ],


    # --------------------------------------------------------
    # PACKET RATES
    # --------------------------------------------------------

    "packets_per_second": [
        r"^flow pkts/s$",
        r"^packets per second$",
        r"^packet rate$",
        r"^packet rate per second$"
    ],

    "packets_per_second_forward": [
        r"^fwd pkts/s$",
        r"^forward packets/s$",
        r"^forward packets per second$",
        r"forward packet rate"
    ],

    "packets_per_second_backward": [
        r"^bwd pkts/s$",
        r"^backward packets/s$",
        r"^backward packets per second$",
        r"backward packet rate"
    ],


    # --------------------------------------------------------
    # BYTE / FLOW VOLUME
    # --------------------------------------------------------

    "bytes_forward": [
        r"^totlen fwd pkts$",
        r"^total forward bytes$",
        r"^forward bytes$",
        r"forward byte count"
    ],

    "bytes_backward": [
        r"^totlen bwd pkts$",
        r"^total backward bytes$",
        r"^backward bytes$",
        r"backward byte count"
    ],

    "bytes_total": [
        r"^total bytes$",
        r"^flow bytes$",
        r"^byte count$"
    ],

    "bytes_per_second": [
        r"^flow byts/s$",
        r"^bytes per second$",
        r"^byte rate$",
        r"^bytes rate$"
    ],


    # --------------------------------------------------------
    # PACKET LENGTH
    # --------------------------------------------------------

    "packet_length_forward_max": [
        r"^fwd pkt len max$",
        r"^forward packet length max$",
        r"forward packet maximum length"
    ],

    "packet_length_backward_max": [
        r"^bwd pkt len max$",
        r"^backward packet length max$",
        r"backward packet maximum length"
    ],

    "packet_length_max": [
        r"^pkt len max$",
        r"^packet length max$",
        r"maximum packet length"
    ],

    "packet_length_forward_mean": [
        r"^fwd pkt len mean$",
        r"^forward packet length mean$",
        r"average forward packet length"
    ],

    "packet_length_backward_mean": [
        r"^bwd pkt len mean$",
        r"^backward packet length mean$",
        r"average backward packet length"
    ],

    "packet_length_mean": [
        r"^pkt len mean$",
        r"^packet length mean$",
        r"average packet length"
    ],


    # --------------------------------------------------------
    # TCP FLAGS
    # --------------------------------------------------------

    "syn_flags": [
        r"^syn flag cnt$",
        r"^syn flag count$",
        r"syn flags"
    ],

    "ack_flags": [
        r"^ack flag cnt$",
        r"^ack flag count$",
        r"ack flags"
    ],

    "rst_flags": [
        r"^rst flag cnt$",
        r"^rst flag count$",
        r"rst flags"
    ],

    "fin_flags": [
        r"^fin flag cnt$",
        r"^fin flag count$",
        r"fin flags"
    ]
}


# ============================================================
# NORMALISE COLUMN NAME
# ============================================================

def normalise_column_name(column):

    value = str(column).strip().lower()

    # Convert separators to spaces
    value = value.replace("_", " ")
    value = value.replace("-", " ")
    value = value.replace("/", "/")

    # Remove repeated whitespace
    value = re.sub(r"\s+", " ", value)

    return value


# ============================================================
# DETECT FIELD
# ============================================================

def detect_field(column):

    normalised = normalise_column_name(column)

    for field_type, patterns in FIELD_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, normalised):
                return field_type

    return None


# ============================================================
# DATASET TYPE ESTIMATION
# ============================================================

def estimate_dataset_type(detected_fields):

    network_fields = {
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
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
        "bytes_per_second"
    }

    endpoint_fields = {
        "hostname",
        "process",
        "command",
        "username"
    }

    event_fields = {
        "event_id",
        "action",
        "username",
        "hostname",
        "timestamp"
    }

    network_score = len(
        set(detected_fields) & network_fields
    )

    endpoint_score = len(
        set(detected_fields) & endpoint_fields
    )

    event_score = len(
        set(detected_fields) & event_fields
    )

    scores = {
        "network_flow": network_score,
        "endpoint": endpoint_score,
        "security_event": event_score
    }

    best_type = max(
        scores,
        key=scores.get
    )

    if scores[best_type] == 0:
        return "unknown"

    return best_type


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n" + "=" * 70)
    print("SECURITY DATASET SCHEMA DISCOVERY")
    print("=" * 70)

    csv_files = sorted(
        PROCESSED_DIR.glob("*.csv")
    )

    if not csv_files:

        raise FileNotFoundError(
            f"No CSV files found in {PROCESSED_DIR}"
        )

    csv_file = csv_files[0]

    print(
        f"\nLoading: {csv_file.resolve()}"
    )

    # Only inspect a sample.
    # We don't need to load the entire dataset just to
    # understand its column structure.

    df = pd.read_csv(
        csv_file,
        nrows=10000,
        low_memory=False
    )

    print(
        f"Sample records inspected: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )


    # --------------------------------------------------------
    # Discover fields
    # --------------------------------------------------------

    detected_fields = {}

    field_detection_method = {}

    classified_columns = set()


    for column in df.columns:

        detected_type = detect_field(column)

        if detected_type is None:
            continue

        detected_fields.setdefault(
            detected_type,
            []
        ).append(column)

        field_detection_method[
            column
        ] = "generic_pattern_match"

        classified_columns.add(column)


    # --------------------------------------------------------
    # Unknown columns
    # --------------------------------------------------------

    unknown_columns = [
        column
        for column in df.columns
        if column not in classified_columns
    ]


    # --------------------------------------------------------
    # Estimate dataset type
    # --------------------------------------------------------

    dataset_type = estimate_dataset_type(
        detected_fields
    )


    # --------------------------------------------------------
    # Capabilities
    # --------------------------------------------------------

    capabilities = {

        "has_timestamp":
            "timestamp" in detected_fields,

        "has_source_identity":
            "source_ip" in detected_fields,

        "has_destination_identity":
            "destination_ip" in detected_fields,

        "has_source_port":
            "source_port" in detected_fields,

        "has_destination_port":
            "destination_port" in detected_fields,

        "has_protocol":
            "protocol" in detected_fields,

        "has_label":
            "label" in detected_fields,

        "has_action":
            "action" in detected_fields,

        "has_event_id":
            "event_id" in detected_fields,

        "has_user_identity":
            "username" in detected_fields,

        "has_host_identity":
            "hostname" in detected_fields,

        "has_process_data":
            "process" in detected_fields,

        "has_command_data":
            "command" in detected_fields,

        "has_byte_data":
            any(
                field in detected_fields
                for field in [
                    "bytes_forward",
                    "bytes_backward",
                    "bytes_total",
                    "bytes_per_second"
                ]
            ),

        "has_packet_data":
            any(
                field in detected_fields
                for field in [
                    "packets_forward",
                    "packets_backward",
                    "packets_total",
                    "packets_per_second",
                    "packets_per_second_forward",
                    "packets_per_second_backward"
                ]
            ),

        "has_duration_data":
            "duration" in detected_fields,

        "has_tcp_flag_data":
            any(
                field in detected_fields
                for field in [
                    "syn_flags",
                    "ack_flags",
                    "rst_flags",
                    "fin_flags"
                ]
            )
    }


    # --------------------------------------------------------
    # Schema object
    # --------------------------------------------------------

    schema = {

        "schema_version": "3.0",

        "source_file":
            str(csv_file),

        "records_sampled":
            len(df),

        "total_columns":
            len(df.columns),

        "dataset_type":
            dataset_type,

        "detected_fields":
            detected_fields,

        "field_detection_method":
            field_detection_method,

        "capabilities":
            capabilities,

        "unknown_columns":
            unknown_columns,

        "methodology": {

            "dataset_agnostic":
                True,

            "attack_specific_rules":
                False,

            "label_required":
                False,

            "field_detection":
                "Generic semantic column-name pattern matching",

            "purpose":
                "Identify security telemetry concepts without "
                "assuming a specific dataset or attack type."
        }
    }


    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            schema,
            file,
            indent=2,
            ensure_ascii=False
        )


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\nEstimated dataset type:")
    print(dataset_type)

    print("\nDiscovered fields:")

    for field, columns in detected_fields.items():

        for column in columns:

            print(
                f"- {field}: {column}"
            )


    print("\nCapabilities:")

    for capability, value in capabilities.items():

        print(
            f"- {capability}: {value}"
        )


    print("\nUnknown/unclassified columns:")
    print(len(unknown_columns))


    print(
        f"\nSchema saved: "
        f"{OUTPUT_FILE.resolve()}"
    )

    print("\nSchema discovery complete.\n")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()