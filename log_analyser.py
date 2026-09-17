import pandas as pd

file_path = "Data/raw/02-14-2018.csv"

df = pd.read_csv(file_path)

print("Number of rows:", len(df))
print("Number of columns:", len(df.columns))

print("\nColumns:")
print(df.columns.tolist())

print("\nSecurity labels:")
print(df["Label"].value_counts())

ftp_attacks = df[df["Label"] == "FTP-BruteForce"]

print("\nFTP-BruteForce records:")
print(ftp_attacks.head())

important_columns = [
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "Label"
]

print("\nImportant FTP-BruteForce fields:")
print(ftp_attacks[important_columns].head(10).to_string(index=False))

benign = df[df["Label"] == "Benign"]

print("\nAverage values - FTP-BruteForce:")
print(ftp_attacks[important_columns[:-1]].mean(numeric_only=True))

print("\nAverage values - Benign:")
print(benign[important_columns[:-1]].mean(numeric_only=True))

print("\nInfinite values:")
print(df[["Flow Byts/s", "Flow Pkts/s"]].isin([float("inf"), float("-inf")]).sum())

print("\nMissing values:")
print(df[["Flow Byts/s", "Flow Pkts/s"]].isna().sum())

print("\nRecords with infinite Flow Pkts/s:")
print(
    df[df["Flow Pkts/s"].isin([float("inf"), float("-inf")])]
    [["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts",
      "Tot Bwd Pkts", "Flow Pkts/s", "Label"]]
    .head(10)
)

print("\nZero-duration flows by label:")
print(
    df[df["Flow Duration"] == 0]["Label"]
    .value_counts()
)

print("\nInfinite Flow Pkts/s by label:")
print(
    df[df["Flow Pkts/s"].isin([float("inf"), float("-inf")])]["Label"]
    .value_counts()
)