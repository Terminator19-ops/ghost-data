# Ghost Data Still Exists - Deletion Audit Agent

HackerRank Orchestrate (October 2026) challenge solution.

## Overview

This solution implements an AI-powered deletion-audit agent that processes 518 deletion requests from `dataset/deletion_requests.csv` and produces `output.csv` with audit decisions and remediation steps.

## Architecture

The pipeline consists of 4 phases:

### Phase 1: Data Foundation
- `loaders.py`: CSV loading, evidence parsing (SQL, JSON, JSONL, text, PDF, PNG OCR)
- `models.py`: Core dataclasses (DeletionRequest, UserIdentity, SystemActivity, DeletionRule, EvidenceRecord, etc.)
- `config.py`: Paths, constants, system IDs, collection mappings

### Phase 2: Request Classification & Evidence Processing
- `request_classifier.py`: LLM-based intent classification (deletion vs access/correction/export)
- `evidence_extractor.py`: Multi-format evidence parsing with provenance tracking
- `evidence_linker.py`: Links evidence to stable user_ids using identity resolution
- `identity_resolver.py`: Resolves current + historical identifiers (emails, phones, email_hashes) from user_identities.csv, user_audit_log.csv, and evidence

### Phase 3: State Reconstruction & Policy Evaluation
- `state_reconstructor.py`: Reconstructs resource state at `audit_at` from evidence
  - Detects replica drift (primary vs read/regional/reporting/failover replicas)
  - Identifies active data flows (SYNC, EXPORT, IMPORT, REPLICATION)
  - Evaluates backup restore risks
- `policy_engine.py`: Applies 15 deletion rules from deletion_rules.csv
  - 7 violation types: record deletion, redaction, anonymization, retention, data flows, restore risks, replica drift
  - Generates remediation and verification actions
- `step_builder.py`: Builds ordered step plans (FINDING → REMEDIATION → VERIFICATION)

### Phase 4: Output Generation
- `main.py`: Orchestrates full pipeline, writes output.csv

## Quick Start

### Prerequisites
- Python 3.10+
- Dependencies: `pandas`, `pytesseract`, `Pillow`, `pymupdf` (fitz)

```bash
uv pip install --python .\venv\Scripts\python.exe pandas pytesseract Pillow pymupdf openai anthropic google-genai groq
```

Note: For OCR, Tesseract must be installed system-wide:
- Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
- macOS: `brew install tesseract`
- Linux: `apt-get install tesseract-ocr`

### Running the Pipeline

```bash
cd code
python main.py
```

The final pipeline prefers Groq Qwen through `GROQ_API_KEY`, then OpenRouter
Nemotron through `OPENROUTER_API_KEY`, NVIDIA through `NVIDIA_API_KEY`,
Google Gemma through `GEMINI_API_KEY`, followed by the existing
Anthropic/OpenAI providers. It also reads uncommitted values from `code/.env`
when the corresponding environment variable is unset. It fails explicitly
when none of those credentials is available; the mock provider is reserved for
unit tests and is not valid for generating submission output.

This will:
1. Load all data from `../dataset/`
2. Extract evidence from all files
3. Build identity resolver with historical enrichment
4. Classify all 518 deletion requests
5. Process each case through state reconstruction and policy evaluation
6. Write `../output.csv` with 518 rows

### Running Sample Validation

```bash
cd code
python validate_samples.py
```

Validates against `dataset/sample_deletion_requests.csv` and `dataset/sample_output.csv`.

## Output Format

`output.csv` contains exactly 518 rows (one per case_id in deletion_requests.csv):

```csv
case_id,deletion_status,steps_json
```

Where:
- `deletion_status`: `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`
- `steps_json`: JSON array of audit steps with fields: step_no, phase, system_id, resource_id, operation, state, evidence_id

## Evaluation Reports

Located in `evaluation/` inside the packaged code:
- `evaluation_report.md`: Accuracy analysis, step compliance, custom test cases, failures/improvements
- `usage_report.md`: Token usage, model calls, projected costs

## Configuration

No external configuration required. All paths are relative to repository root via `config.py`.

## Key Features

1. **Time-aware evidence filtering**: Only evidence with `captured_at` ≤ case `audit_at` is considered
2. **Historical identity resolution**: Combines current snapshot, audit log, and evidence-extracted identifiers
3. **Replica drift detection**: Compares primary vs. 4 replica types at audit time
4. **Active data flow detection**: Finds SYNC/EXPORT/IMPORT/REPLICATION processes that can recreate data
5. **Backup risk evaluation**: Checks backup catalogs for restorable user data
6. **Policy-driven**: Loads all 15 rules from deletion_rules.csv, evaluates conditions against state
7. **Deterministic output**: Fixed ordering, compact JSON serialization

## Project Structure

```
orchestrate-october-2026/
├── dataset/                    # Participant-facing data (read-only)
│   ├── deletion_requests.csv   # 518 evaluation cases
│   ├── sample_deletion_requests.csv
│   ├── sample_output.csv
│   ├── user_identities.csv
│   ├── user_audit_log.csv
│   ├── system_activity.csv
│   ├── deletion_rules.csv
│   ├── evidence_files.csv
│   └── evidence/               # 94 evidence files (SQL, JSON, logs, PDF, PNG)
├── code/                       # Solution (this directory)
│   ├── main.py                 # Entry point
│   ├── validate_samples.py     # Sample validation
│   ├── *.py                    # Pipeline modules
│   └── README.md               # This file
├── evaluation/                 # Generated reports
│   ├── evaluation_report.md
│   └── usage_report.md
├── output.csv                  # Generated submission (518 rows)
└── log.txt                     # Agent session log
```

## Submission Artifacts

Per AGENTS.md §6.9:
- `code.zip`: This code/ directory + evaluation/ reports
- `output.csv`: At repository root
- `log.txt`: At repository root (this file)