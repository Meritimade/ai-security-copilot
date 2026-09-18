# AI Security Copilot

AI-assisted security analytics and investigation platform for analysing security telemetry, identifying behavioural findings, validating MITRE ATT&CK candidates, generating AI-assisted security reports, and prioritising alerts for SOC investigation.

## Project Overview

AI Security Copilot is a project designed to demonstrate how security analytics, behavioural analysis, MITRE ATT&CK knowledge, evidence validation and generative AI can be combined into a practical security investigation workflow.

The system is designed to analyse security data without relying on fixed attack-specific mappings.

Instead, it follows an evidence-driven pipeline:

```text
Security Dataset
       ↓
Data Cleaning
       ↓
Data Validation
       ↓
Schema Discovery
       ↓
Behavioural Analysis
       ↓
Security Findings
       ↓
Risk & Alert Engine
       ↓
MITRE ATT&CK Candidate Retrieval
       ↓
Evidence-Based MITRE Validation
       ↓
AI Security Analyst
       ↓
SOC Dashboard & Reports
The project supports both labelled and unlabelled security data.

For labelled datasets, labels are treated as supporting evaluation context rather than independent proof of an attack.

For unlabelled datasets, the system relies on observable behavioural characteristics in the available telemetry.

Key Capabilities
Security Data Processing
Automatic discovery of CSV security datasets
Data cleaning and normalisation
Numeric conversion and invalid-value handling
Timestamp parsing
Detection of corrupted records
Validation of network-flow telemetry
Duplicate and missing-value analysis
Schema Discovery

The system automatically examines incoming data and attempts to identify security-relevant fields such as:

Source IP
Destination IP
Source port
Destination port
Protocol
Timestamp
Flow duration
Packet statistics
Byte statistics
TCP flags
Labels
User identity
Host identity
Process information
Command information
Authentication-related fields
Security event fields

The detected schema is used to determine what the dataset can and cannot support.

The system does not invent unavailable telemetry.

Behavioural Security Analysis

The behavioural analysis layer examines available security telemetry and produces evidence-based findings.

Depending on the dataset, analysis can include:

Traffic volume
Destination-port concentration
Protocol distribution
Temporal concentration
Flow duration
Packet behaviour
Byte behaviour
TCP flag characteristics
Label distribution
Repeated connection patterns
High-rate or anomalous flow behaviour

For labelled datasets, the system dynamically discovers the labels present in the data.

Attack types are not hard-coded into the analysis engine.

MITRE ATT&CK Integration

The project integrates the MITRE ATT&CK Enterprise knowledge base.

The MITRE pipeline consists of two separate stages:

1. Candidate Retrieval

Security findings are compared against the MITRE ATT&CK technique knowledge base to retrieve candidate techniques.

Semantic similarity is used as the primary retrieval signal, with structured evidence used as a secondary signal.

Candidate retrieval does not mean that a technique has been confirmed.

2. Evidence-Based Validation

Retrieved candidates are then evaluated against the actual security evidence.

Each candidate can be classified as:

SUPPORTED
POSSIBLE
NOT_SUPPORTED

The validation process considers:

Observed evidence
Inferred behaviour
Missing telemetry
Dataset context
Behavioural compatibility
Whether the available evidence actually supports the technique

The system can reject all retrieved candidates when the evidence is insufficient.

This prevents semantic similarity from being treated as proof of an ATT&CK technique.

AI Security Analyst

The project uses the OpenAI API to generate an AI-assisted security analysis.

The AI layer receives structured security evidence rather than raw assumptions.

The generated analysis can include:

Executive summary
Dataset scope
Finding summaries
Detailed findings
MITRE ATT&CK assessment
Evidence gaps
SOC investigation recommendations
Defensive recommendations
Overall severity
Overall confidence
Methodology and limitations

The AI is instructed to distinguish between:

Observation
Inference
Possibility
Evidence gap

The system does not treat AI output as independent proof of malicious activity.

Risk & Alert Engine

The risk engine converts behavioural evidence and validated MITRE results into analytical prioritisation scores.

The current scoring model uses separate evidence components:

Component	Maximum Contribution
Prevalence	15
Destination-port concentration	15
Protocol concentration	10
Temporal concentration	10
MITRE validation	25

The current implementation deliberately keeps risk scoring separate from confidence.

For example:

Risk score = analytical prioritisation
Confidence = confidence in the assessment

A finding can therefore have a relatively high prioritisation score while still having low confidence if important telemetry is unavailable.

The risk score is not a probability of compromise and should not be interpreted as one.

SOC Dashboard

The Streamlit dashboard provides a SOC-style interface for reviewing analysis results.

Available areas include:

Overview
Alerts
Security Findings
Timeline
MITRE ATT&CK
AI Analyst
Evidence
Reports
Settings

The dashboard provides visibility into:

Active alerts
Alert severity
Risk scores
Findings
Dataset information
Analysis history
Pipeline progress
MITRE validation results
Evidence
Investigation recommendations
Exportable reports
Supported Security Material

The application supports multiple security-data and security-material formats through its analysis pipeline.

Supported formats include:

CSV
Excel
JSON
Parquet
TXT
LOG
RTF
PDF
DOCX
PNG
JPG
JPEG

Structured security telemetry follows the security-data analysis pipeline.

Documents and images are analysed separately and are not treated as network-flow telemetry.

Current Dataset Testing

The project has been tested using security datasets containing network-flow telemetry, including datasets representing:

Benign traffic
FTP brute-force activity
SSH brute-force activity
DDoS traffic
Infiltration-related traffic

Testing has included both labelled analysis and an unlabelled-data pipeline.

The unlabelled pipeline has demonstrated that the system can produce behavioural findings without requiring an attack label.

MITRE candidate retrieval and evidence validation are performed after behavioural analysis.

Example Evidence-Based Reasoning

The system intentionally avoids reasoning such as:

Label = DDoS
Therefore:
MITRE = T1498
Risk = Critical

Instead, the workflow is:

Observed telemetry
       ↓
Behavioural evidence
       ↓
Security finding
       ↓
MITRE candidate retrieval
       ↓
Evidence validation
       ↓
Supported / Possible / Not Supported
       ↓
Risk prioritisation
       ↓
AI-assisted investigation

This distinction is important because security datasets can contain incomplete telemetry, misleading labels, or behaviours that are compatible with multiple explanations.

Telemetry Limitations

The system reports telemetry limitations rather than silently assuming unavailable information.

For example, a network-flow dataset may contain:

Destination port
Protocol
Timestamp
Flow duration
Packet statistics

while not containing:

Source identity
Destination identity
Username
Hostname
Process information
Command-line information
Authentication outcome
Application-layer events

When these fields are unavailable, the system identifies them as evidence gaps.

This prevents unsupported conclusions about attacker identity, compromised hosts, accounts or processes.

Project Architecture
ai-security-copilot/
│
├── app.py
│
├── ai_basics.py
├── log_analyser.py
├── multi_format_analyser.py
│
├── data_cleaner.py
├── data_validation.py
├── schema_discovery.py
├── security_analysis.py
│
├── mitre_mapping.py
├── mitre_evaluator.py
│
├── risk_alert_engine.py
├── security_report.py
├── report_export.py
│
├── test_unlabelled.py
│
├── Data/
│   ├── raw/
│   └── processed/
│
├── MITRE/
│   ├── enterprise-attack.json
│   ├── mitre_technique_index.json
│   └── mitre_embeddings.npz
│
├── screenshots/
│
├── .env
├── .gitignore
├── requirements.txt
└── README.md

Generated analysis outputs are intentionally excluded from version control where appropriate.

Pipeline Components
data_cleaner.py

Cleans and prepares raw security datasets.

Functions include:

Numeric conversion
Missing-value handling
Infinite-value handling
Timestamp parsing
Corruption detection
Processed dataset generation

The original raw dataset is preserved.

data_validation.py

Validates the processed security dataset.

Checks include:

Row and column counts
Missing values
Infinite values
Duplicate records
Security labels
Timestamp validity
Negative flow duration
Network telemetry availability
schema_discovery.py

Automatically identifies security-relevant fields and estimates the dataset type.

Current dataset types include:

network_flow
endpoint
security_event
unknown
security_analysis.py

Builds structured security evidence from the available telemetry.

It supports:

LABELLED
UNLABELLED

analysis modes.

mitre_mapping.py

Retrieves candidate MITRE ATT&CK techniques using the available security evidence and MITRE knowledge base.

mitre_evaluator.py

Validates retrieved MITRE candidates against the observed evidence.

security_report.py

Uses the structured security evidence and validated MITRE results to generate an AI-assisted security investigation report.

risk_alert_engine.py

Converts evidence into analytical alert prioritisation and generates SOC-style alerts.

report_export.py

Supports exporting security analysis results into multiple formats.

app.py

Provides the Streamlit SOC dashboard and user-facing analysis workflow.

Security Design Principles

The project follows several security-analysis principles:

Evidence before attribution

Observed telemetry is separated from interpretation.

Candidate retrieval is not confirmation

A high semantic similarity score does not establish that an ATT&CK technique occurred.

Labels are contextual evidence

Dataset labels are useful for evaluation but are not automatically treated as proof.

Missing telemetry is explicitly reported

Unavailable source identity, authentication, endpoint or application data is treated as an evidence limitation.

Confidence is separate from severity

Severity and confidence describe different dimensions of an investigation.

No forced MITRE mapping

The system can return no supported ATT&CK technique when evidence is insufficient.

No hard-coded attack mappings

Attack-specific mappings are not embedded into the analysis logic.

Technology Stack
Python
Pandas
NumPy
Streamlit
Plotly
OpenAI API
MITRE ATT&CK Enterprise
python-dotenv
Scikit-learn / embedding-based retrieval components
ReportLab
python-docx
OpenPyXL
Installation

Clone the repository:

git clone https://github.com/Meritimade/ai-security-copilot.git
cd ai-security-copilot

Create a virtual environment:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt

Create a .env file:

OPENAI_API_KEY=your_api_key_here

Do not commit the .env file.

Running the Dashboard

Start the Streamlit application:

python -m streamlit run app.py --server.port 8502

The application will open in the browser.

Running the Analysis Pipeline

The core pipeline can be executed from the terminal.

Step 1 — Clean the dataset
python data_cleaner.py
Step 2 — Validate the dataset
python data_validation.py
Step 3 — Discover the schema
python schema_discovery.py
Step 4 — Analyse security behaviour
python security_analysis.py
Step 5 — Retrieve MITRE candidates
python mitre_mapping.py
Step 6 — Validate MITRE candidates
python mitre_evaluator.py
Step 7 — Generate the AI security report
python security_report.py
Step 8 — Generate risk alerts
python risk_alert_engine.py
Environment Variables

The application requires an OpenAI API key for AI-assisted analysis.

Example:

OPENAI_API_KEY=your_api_key_here

API keys must never be committed to GitHub.

For Streamlit Cloud, the API key should be configured using Streamlit Secrets rather than committed to the repository.

Deployment

The dashboard can be deployed using Streamlit Community Cloud.

Live application:

https://ai-security-copilot-momub5wdtbqrxt9jth94gf.streamlit.app

Source repository:

https://github.com/Meritimade/ai-security-copilot

Data Protection

Security telemetry can contain sensitive information.

Users should not upload:

Passwords
API keys
Private certificates
Authentication secrets
Unauthorised personal data
Other confidential information

Only security material appropriate for the analysis environment should be uploaded.

Limitations

This project is an AI-assisted security analytics and investigation system.

It does not replace:

A production SIEM
An EDR platform
Network detection and response tooling
Human SOC analysts
Incident-response procedures
Full packet capture analysis
Application-layer telemetry
Authentication telemetry

The quality of analysis depends on the quality and completeness of the available telemetry.

Flow-level data alone may not be sufficient to establish:

Attacker identity
Compromised host
Account compromise
Process execution
Command execution
Authentication success or failure
Application-layer exploitation
Malicious intent

These limitations are surfaced as part of the evidence and investigation workflow.

Future Development

Potential future improvements include:

Configurable organisational risk-scoring profiles
Additional security telemetry schemas
Authentication-log correlation
Endpoint telemetry integration
SIEM connector integration
Real-time alert ingestion
Historical alert comparison
Analyst feedback and case management
Additional ATT&CK data sources
Automated investigation playbooks
Expanded threat-intelligence integration
Improved entity and identity correlation
Academic / Professional Purpose

This project demonstrates practical application of:

Cybersecurity analytics
Security operations concepts
Data engineering
Behavioural anomaly detection
MITRE ATT&CK
Risk analysis
Evidence-based investigation
Generative AI
Security reporting
Security dashboard development

The project focuses on maintaining a clear distinction between what the telemetry demonstrates and what the system can only infer.

Author

Merit Osifo

MSc Applied Cybersecurity