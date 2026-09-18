# AI Security Copilot

An AI-assisted security analysis and SOC-style investigation platform designed to analyse security telemetry, identify suspicious behaviour, validate MITRE ATT&CK techniques against available evidence, and generate analyst-oriented security reports.


## Dashboard

## Project Overview

AI Security Copilot combines security analytics, behavioural analysis, MITRE ATT&CK knowledge, evidence-based validation, and AI-assisted investigation into a single workflow.

The system is designed to work with different types of security datasets rather than relying on hard-coded attack rules.

## Core Objectives

- Automatically analyse uploaded security datasets
- Discover the structure and available security telemetry
- Identify suspicious or anomalous behaviour
- Generate security findings and risk alerts
- Retrieve relevant MITRE ATT&CK techniques
- Validate MITRE techniques against actual evidence
- Distinguish confirmed evidence from possible interpretations
- Identify missing telemetry that limits investigation
- Generate AI-assisted SOC investigation reports
- Provide an interactive security operations dashboard

## Architecture

Dataset
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
Risk / Alert Engine
↓
MITRE ATT&CK Candidate Retrieval
↓
Evidence-Based MITRE Validation
↓
AI Security Analyst
↓
SOC Dashboard

## Dataset-Agnostic Design

The Copilot is designed to adapt to the telemetry available in each dataset.

The schema discovery component dynamically searches for security-relevant fields including:

- Source identity
- Destination identity
- Source port
- Destination port
- Protocol
- Timestamp
- Username
- Hostname
- Process
- Command
- Authentication outcome
- Application-layer events
- Network flow information
- Packet information
- Byte information
- TCP flags
- Flow duration
- Security labels

If a dataset contains additional security telemetry, the system can use the detected fields during analysis.

If a field is unavailable, the system records the limitation rather than inventing information.

## Security Analysis

The behavioural analysis engine examines available telemetry for:

- Traffic concentration
- Destination ports
- Protocol distribution
- Flow duration
- Packet behaviour
- Byte behaviour
- TCP flag activity
- Temporal patterns
- Repetitive behaviour
- Statistical anomalies
- Comparative behavioural differences

For labelled datasets, labels are treated as supporting context and evaluation evidence rather than automatically being treated as proof of an attack.

For unlabelled datasets, the system relies on behavioural indicators and anomaly-oriented analysis.

## MITRE ATT&CK Integration

The project integrates the MITRE ATT&CK Enterprise knowledge base.

The MITRE workflow consists of two separate stages:

### Candidate Retrieval

Potentially relevant techniques are retrieved using semantic similarity and structured evidence.

### Evidence Validation

Each candidate is then evaluated against the available security evidence.

The validation process categorises techniques as:

- SUPPORTED
- POSSIBLE
- NOT_SUPPORTED

The system also distinguishes between:

- Observed evidence
- Inferred evidence
- Missing evidence

This prevents semantic similarity or dataset labels from automatically being treated as proof of a MITRE ATT&CK technique.

## AI Security Analyst

The AI analysis layer receives structured security evidence rather than raw unprocessed data.

The AI is instructed to:

- Explain what the evidence shows
- Identify important security findings
- Assess risk
- Explain confidence
- Discuss MITRE ATT&CK assessments
- Identify evidence gaps
- Recommend investigation steps
- Recommend defensive actions
- Avoid inventing unavailable evidence

## SOC Dashboard

The Streamlit dashboard provides:

- Overview
- Security alerts
- Security findings
- Timeline analysis
- MITRE ATT&CK assessment
- AI analyst report
- Evidence centre
- Dataset upload
- Pipeline status
- Risk visualisation
- Alert severity distribution
- Destination port analysis
- Threat indicators
- Telemetry capability analysis

## Current Dataset

The current project uses a network-flow dataset containing:

- 1,048,570 cleaned records
- 80 original dataset columns
- Benign traffic
- FTP-BruteForce traffic
- SSH-Bruteforce traffic

The dataset is used for demonstrating the labelled analysis pipeline and evaluating the system's ability to distinguish contextual labels from independently observed evidence.

## Unlabelled Dataset Testing

The project also includes an unlabelled testing workflow.

The unlabelled pipeline removes the security label and runs the analysis without relying on attack labels.

This demonstrates that the system can:

- Discover available telemetry
- Generate behavioural indicators
- Identify suspicious patterns
- Retrieve MITRE candidates
- Validate candidates against evidence
- Generate a security report

## Data Quality

The data preparation pipeline includes:

- Column normalisation
- Numeric conversion
- Infinite-value handling
- Timestamp validation
- Corrupted-record detection
- Negative flow-duration checks
- Dataset validation

The raw dataset is preserved separately from the processed dataset.

## Project Structure
```text
ai-security-copilot/
│
├── app.py
├── data_cleaner.py
├── data_validation.py
├── log_analyser.py
├── mitre_evaluator.py
├── mitre_mapping.py
├── risk_alert_engine.py
├── schema_discovery.py
├── security_analysis.py
├── security_report.py
├── test_unlabelled.py
│
├── MITRE/
│   ├── mitre_technique_index.json
│   ├── mitre_candidates.json
│   └── mitre_evaluated.json
│
├── requirements.txt
├── .gitignore
└── README.md