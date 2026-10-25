"""
Data loaders for Ghost Data Still Exists challenge.
Loads CSV files and parses evidence files (SQL, JSON, logs, text).
"""
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Iterator, Optional, Set, Tuple, Any
import pandas as pd

from config import (
    DELETION_REQUESTS_CSV,
    USER_IDENTITIES_CSV,
    USER_AUDIT_LOG_CSV,
    SYSTEM_ACTIVITY_CSV,
    DELETION_RULES_CSV,
    EVIDENCE_FILES_CSV,
    EVIDENCE_BASE_DIR,
)
from models import (
    DeletionRequest,
    UserIdentity,
    UserAuditLog,
    SystemActivity,
    DeletionRule,
    EvidenceFile,
    EvidenceRecord,
)


# ============================================================================
# CSV Loaders (using pandas for efficiency)
# ============================================================================

def load_deletion_requests(path: Path = DELETION_REQUESTS_CSV) -> List[DeletionRequest]:
    """Load all deletion requests from CSV."""
    df = pd.read_csv(path)
    # Validate required columns
    expected_cols = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    # Check for duplicate case_ids
    duplicates = df[df.duplicated(subset=["case_id"], keep=False)]
    if not duplicates.empty:
        raise ValueError(f"Duplicate case_ids found: {duplicates['case_id'].tolist()}")
    return [DeletionRequest.from_dict(row) for row in df.to_dict("records")]


def load_user_identities(path: Path = USER_IDENTITIES_CSV) -> List[UserIdentity]:
    """Load current user identities from CSV."""
    df = pd.read_csv(path)
    expected_cols = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    return [UserIdentity.from_dict(row) for row in df.to_dict("records")]


def load_user_audit_log(path: Path = USER_AUDIT_LOG_CSV) -> List[UserAuditLog]:
    """Load user audit log from CSV."""
    df = pd.read_csv(path)
    expected_cols = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    return [UserAuditLog.from_dict(row) for row in df.to_dict("records")]


def load_system_activity(path: Path = SYSTEM_ACTIVITY_CSV) -> List[SystemActivity]:
    """Load system activity from CSV."""
    df = pd.read_csv(path)
    expected_cols = ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    return [SystemActivity.from_dict(row) for row in df.to_dict("records")]


def load_deletion_rules(path: Path = DELETION_RULES_CSV) -> List[DeletionRule]:
    """Load deletion rules from CSV."""
    df = pd.read_csv(path)
    expected_cols = ["rule_id", "data_category", "condition", "required_action"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    return [DeletionRule.from_dict(row) for row in df.to_dict("records")]


def load_evidence_files(path: Path = EVIDENCE_FILES_CSV) -> List[EvidenceFile]:
    """Load evidence file manifest from CSV."""
    df = pd.read_csv(path)
    expected_cols = ["file_id", "file_path", "origin", "captured_at"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    return [EvidenceFile.from_dict(row) for row in df.to_dict("records")]


# ============================================================================
# Evidence Parsers
# ============================================================================

def _quote_sql_identifier(identifier: str) -> str:
    """Quote an SQLite identifier without allowing SQL injection."""
    return '"' + identifier.replace('"', '""') + '"'


def _parse_sql_timestamp(value: Any, fallback: datetime) -> datetime:
    if value in (None, ""):
        return fallback
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return fallback


def _table_metadata(table_name: str) -> Tuple[str, str]:
    """Infer stable metadata only when a table does not carry it explicitly."""
    name = table_name.lower()
    mapping = (
        (("profile",), "account_service", "customer_profiles"),
        (("search",), "search_service", "customer_search_documents"),
        (("analytic",), "analytics_platform", "customer_analytics_reports"),
        (("support",), "support_platform", "support_conversations"),
        (("attachment",), "support_platform", "ticket_attachments"),
        (("export",), "export_service", "customer_export_jobs"),
        (("connector", "subscription"), "integration_service", "connector_configurations"),
        (("backup", "restore"), "backup_service", "backup_archives"),
        (("security",), "security_service", "security_audit_logs"),
        (("legal", "hold"), "legal_service", "legal_hold_records"),
        (("tombstone", "deleted_customer"), "account_service", "account_tombstones"),
    )
    for fragments, system_id, collection in mapping:
        if any(fragment in name for fragment in fragments):
            return system_id, collection
    return "unknown", table_name


def _record_from_sql_row(
    file_id: str,
    captured_at: datetime,
    table_name: str,
    columns: List[str],
    row: Tuple[Any, ...],
    row_number: int,
) -> EvidenceRecord:
    values = dict(zip(columns, row))
    lower_values = {key.lower(): value for key, value in values.items()}

    resource_id = next(
        (
            lower_values.get(name)
            for name in (
                "resource_id", "record_id", "profile_id", "document_id",
                "search_document_id", "export_id", "backup_id",
                "connector_id", "subscription_id", "audit_id",
                "support_id", "attachment_id", "id",
            )
            if lower_values.get(name) not in (None, "")
        ),
        f"{table_name}:{row_number}",
    )
    origin_system = next(
        (
            str(lower_values[name])
            for name in ("origin_system", "system_id", "service", "source_system")
            if lower_values.get(name) not in (None, "")
        ),
        None,
    )
    inferred_system, inferred_collection = _table_metadata(table_name)
    origin_system = origin_system or inferred_system
    collection_name = str(lower_values.get("collection_name") or table_name)

    record_json = dict(values)
    record_json["_source_table"] = table_name
    raw_record_json = lower_values.get("record_json")
    if isinstance(raw_record_json, str):
        try:
            decoded = json.loads(raw_record_json)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            record_json = {**record_json, **decoded}

    updated_at = next(
        (
            value
            for name, value in lower_values.items()
            if name in ("updated_at", "event_time", "captured_at", "created_at", "timestamp", "snapshot_time")
            and value not in (None, "")
        ),
        None,
    )
    return EvidenceRecord(
        file_id=file_id,
        resource_id=str(resource_id),
        origin_system=origin_system,
        collection_name=collection_name,
        record_json=record_json,
        updated_at=_parse_sql_timestamp(updated_at, captured_at),
        captured_at=captured_at,
    )


def parse_sql_database(
    file_path: Path,
    file_id: str,
    captured_at: datetime,
) -> Tuple[List[EvidenceRecord], List[str], List[str]]:
    """Extract every user table from a SQLite-compatible evidence file."""
    """
    Returns records, explicit parse errors, and warnings.  The caller can
    surface errors while retaining successfully extracted tables and rows.
    """
    records = []
    errors = []
    warnings = []
    conn = sqlite3.connect(":memory:")
    try:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
        except (OSError, sqlite3.Error) as exc:
            return [], [f"SQL execution error: {exc}"], []

        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        if not tables:
            warnings.append("No user tables found")

        for table in tables:
            quoted_table = _quote_sql_identifier(table)
            try:
                columns = [
                    row[1]
                    for row in conn.execute(f"PRAGMA table_info({_quote_sql_identifier(table)})").fetchall()
                    if row[1]
                ]
                if not columns:
                    errors.append(f"Invalid schema for table {table}: no columns")
                    continue
                rows = conn.execute(f"SELECT * FROM {quoted_table}").fetchall()
                for row_number, row in enumerate(rows, 1):
                    try:
                        records.append(
                            _record_from_sql_row(
                                file_id, captured_at, table, columns, row, row_number
                            )
                        )
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        errors.append(f"Row parse error in {table} row {row_number}: {exc}")
            except sqlite3.Error as exc:
                errors.append(f"Query/schema error on {table}: {exc}")
    finally:
        conn.close()
    return records, errors, warnings


def parse_sql_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """Parse a SQLite-compatible SQL evidence file."""
    records, errors, _ = parse_sql_database(file_path, file_id, captured_at)
    if errors:
        raise ValueError("; ".join(errors))
    return records


def parse_json_bundle_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """
    Parse a JSON snapshot bundle evidence file.
    Format: {"exported_at", "source", "snapshots": [{"captured_at", "data_store", "collection", "records": [...]}]}
    """
    records = []
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for snapshot in data.get("snapshots", []):
        snap_captured_at = datetime.fromisoformat(snapshot["captured_at"].replace("Z", "+00:00"))
        data_store = snapshot["data_store"]
        collection = snapshot["collection"]

        for record in snapshot.get("records", []):
            resource_id = record.get("resource_id")
            if not resource_id:
                continue

            # Add metadata to record_json
            record_with_meta = dict(record)
            record_with_meta["_data_store"] = data_store
            record_with_meta["_collection"] = collection

            records.append(EvidenceRecord(
                file_id=file_id,
                resource_id=resource_id,
                origin_system=data_store,
                collection_name=collection,
                record_json=record_with_meta,
                updated_at=snap_captured_at,
                captured_at=captured_at,
            ))
    return records


def parse_log_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """
    Parse a structured log evidence file (JSON lines format).
    Each line is a JSON object with fields like trace_id, resource_id, event, matched_value, etc.
    """
    records = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                # Some logs have timestamp prefix before JSON
                if line.startswith("2026-") and " {" in line:
                    # Format: "2026-09-15T08:51:43Z level=DEBUG ... {JSON}"
                    json_start = line.index("{")
                    log_entry = json.loads(line[json_start:])
                else:
                    log_entry = json.loads(line)

                resource_id = log_entry.get("resource_id")
                if not resource_id:
                    continue

                records.append(EvidenceRecord(
                    file_id=file_id,
                    resource_id=resource_id,
                    origin_system=log_entry.get("service", "unknown"),
                    collection_name="log_entry",
                    record_json=log_entry,
                    updated_at=captured_at,  # Logs don't have per-entry timestamps in our format
                    captured_at=captured_at,
                ))
            except json.JSONDecodeError:
                # Skip non-JSON lines
                continue
    return records


def parse_text_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """
    Parse the customer_account_handover text file.
    Format: lines like "- 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com"
    """
    records = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("- 2026-"):
                continue
            if line.startswith("CUSTOMER PLATFORM") or line.startswith("Snapshot:"):
                continue
            if line.startswith("- "):
                line = line[2:]  # Remove "- "
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 6:
                timestamp_str = parts[0]
                system = parts[1]
                resource_id = parts[2]
                record_type = parts[3]
                result = parts[4]
                identifier = parts[5] if len(parts) > 5 else ""

                records.append(EvidenceRecord(
                    file_id=file_id,
                    resource_id=resource_id,
                    origin_system=system,
                    collection_name=record_type.lower(),
                    record_json={
                        "record_type": record_type,
                        "result": result,
                        "identifier": identifier,
                        "timestamp": timestamp_str,
                    },
                    updated_at=datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")),
                    captured_at=captured_at,
                ))
    return records


def parse_pdf_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """
    Parse PDF evidence files using pypdf.
    Returns text content as a single record per PDF.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        # pypdf not installed, return empty list
        return []

    records = []
    try:
        reader = PdfReader(str(file_path))
        text_content = []
        for page in reader.pages:
            text_content.append(page.extract_text())
        full_text = "\n".join(text_content)

        records.append(EvidenceRecord(
            file_id=file_id,
            resource_id=file_path.stem,
            origin_system="pdf_document",
            collection_name="pdf_text",
            record_json={"text": full_text},
            updated_at=captured_at,
            captured_at=captured_at,
        ))
    except Exception:
        pass
    return records


def parse_image_evidence(file_path: Path, file_id: str, captured_at: datetime) -> List[EvidenceRecord]:
    """
    Parse image evidence files using OCR (Tesseract).
    """
    try:
        import pytesseract
        from PIL import Image, ImageEnhance

        image = Image.open(file_path).convert('L')
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)
        text = pytesseract.image_to_string(image, config='--psm 6')

        return [EvidenceRecord(
            file_id=file_id,
            resource_id=file_path.stem,
            origin_system="image_ocr",
            collection_name="ocr_text",
            record_json={"text": text, "extraction_method": "tesseract"},
            updated_at=captured_at,
            captured_at=captured_at,
        )]
    except Exception:
        return []


# ============================================================================
# Evidence Dispatcher
# ============================================================================

EVIDENCE_PARSERS = {
    ".sql": parse_sql_evidence,
    ".json": parse_json_bundle_evidence,
    ".log": parse_log_evidence,
    ".txt": parse_text_evidence,
    ".pdf": parse_pdf_evidence,
    ".png": parse_image_evidence,
}


def parse_evidence_file(evidence_file: EvidenceFile) -> List[EvidenceRecord]:
    """
    Parse a single evidence file based on its extension.
    """
    file_path = EVIDENCE_BASE_DIR / evidence_file.file_path
    if not file_path.exists():
        return []

    ext = file_path.suffix.lower()
    parser = EVIDENCE_PARSERS.get(ext)
    if not parser:
        return []

    return parser(file_path, evidence_file.file_id, evidence_file.captured_at)


def load_all_evidence(evidence_files: List[EvidenceFile]) -> List[EvidenceRecord]:
    """
    Load and parse all evidence files.
    Returns combined list of all EvidenceRecord objects.
    """
    all_records = []
    for ef in evidence_files:
        records = parse_evidence_file(ef)
        all_records.extend(records)
    return all_records


def filter_evidence_by_time(evidence_records: List[EvidenceRecord], audit_at: datetime) -> List[EvidenceRecord]:
    """
    Filter evidence records to only those captured at or before audit_at.
    """
    return [r for r in evidence_records if r.captured_at <= audit_at]