"""
Evidence extraction for Ghost Data Still Exists challenge.
Extracts structured data from all evidence file types with source tracking.
"""
import json
import re
import sqlite3
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Set, Tuple
from collections import defaultdict

from models import EvidenceFile, EvidenceRecord
from config import EVIDENCE_BASE_DIR
from loaders import parse_sql_database


@dataclass
class ExtractionResult:
    """Result of evidence extraction from a single file."""
    file_id: str
    file_path: str
    captured_at: datetime
    records: List[EvidenceRecord]
    parse_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    extraction_method: str = ""  # "sql", "json", "log", "text", "pdf", "ocr", "vision_llm"


@dataclass
class ExtractedFact:
    """A single extracted fact with full provenance."""
    fact_id: str
    file_id: str
    file_path: str
    captured_at: datetime
    event_timestamp: Optional[datetime]
    system_id: str
    resource_id: str
    collection_name: str
    identifier_type: str  # "email", "phone", "email_hash", "user_id", "customer_reference", etc.
    identifier_value: str
    original_text: str
    corrected_text: Optional[str] = None
    correction_method: Optional[str] = None  # "ocr", "regex", "vision_llm", "manual"
    confidence: float = 1.0
    record_json: Dict = field(default_factory=dict)


class EvidenceExtractor:
    """Extracts and parses all evidence files."""

    def __init__(self):
        self.results: List[ExtractionResult] = []
        self.all_facts: List[ExtractedFact] = []
        self.failed_files: List[Tuple[str, str]] = []  # (file_id, error)

    def extract_all(self, evidence_files: List[EvidenceFile]) -> List[ExtractionResult]:
        """Extract from all evidence files."""
        self.results = []
        self.all_facts = []
        self.failed_files = []

        for ef in evidence_files:
            try:
                result = self.extract_file(ef)
                self.results.append(result)
                self.all_facts.extend(self._records_to_facts(result))
            except Exception as e:
                self.failed_files.append((ef.file_id, str(e)))
                self.results.append(ExtractionResult(
                    file_id=ef.file_id,
                    file_path=ef.file_path,
                    captured_at=ef.captured_at,
                    records=[],
                    parse_errors=[f"Fatal extraction error: {str(e)}"]
                ))

        return self.results

    def extract_file(self, evidence_file: EvidenceFile) -> ExtractionResult:
        """Extract from a single evidence file based on extension."""
        file_path = EVIDENCE_BASE_DIR / evidence_file.file_path
        if not file_path.exists():
            return ExtractionResult(
                file_id=evidence_file.file_id,
                file_path=evidence_file.file_path,
                captured_at=evidence_file.captured_at,
                records=[],
                parse_errors=[f"File not found: {file_path}"]
            )

        ext = file_path.suffix.lower()

        if ext == ".sql":
            return self._extract_sql(evidence_file, file_path)
        elif ext == ".json":
            return self._extract_json(evidence_file, file_path)
        elif ext == ".log":
            return self._extract_log(evidence_file, file_path)
        elif ext == ".txt":
            return self._extract_text(evidence_file, file_path)
        elif ext == ".pdf":
            return self._extract_pdf(evidence_file, file_path)
        elif ext in [".png", ".jpg", ".jpeg", ".tiff", ".bmp"]:
            return self._extract_image(evidence_file, file_path)
        else:
            return ExtractionResult(
                file_id=evidence_file.file_id,
                file_path=evidence_file.file_path,
                captured_at=evidence_file.captured_at,
                records=[],
                parse_errors=[f"Unsupported file type: {ext}"]
            )

    def _extract_sql(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract from SQLite-compatible SQL file."""
        records, errors, warnings = parse_sql_database(
            file_path, evidence_file.file_id, evidence_file.captured_at
        )

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="sql"
        )

    def _extract_json(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract from JSON evidence files.

        Supports three top-level formats:
          Format A – "service_exports" dict: keys are service names mapping to dicts
                     whose values are lists of item records.
          Format B – top-level "records" list (also "collection"/"source" keys).
          Format C – "snapshots" list (original snapshot bundle).
        """
        records = []
        errors = []
        warnings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # ── Format C: snapshots list ──────────────────────────────────────
            for snapshot in data.get("snapshots", []):
                try:
                    snap_captured_at = datetime.fromisoformat(
                        snapshot["captured_at"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError) as e:
                    errors.append(f"Invalid snapshot captured_at: {e}")
                    snap_captured_at = evidence_file.captured_at

                data_store = snapshot.get("data_store", "unknown")
                collection = snapshot.get("collection", "unknown")

                for record in snapshot.get("records", []):
                    resource_id = record.get("resource_id")
                    if not resource_id:
                        continue

                    record_with_meta = dict(record)
                    record_with_meta["_data_store"] = data_store
                    record_with_meta["_collection"] = collection

                    try:
                        records.append(EvidenceRecord(
                            file_id=evidence_file.file_id,
                            resource_id=resource_id,
                            origin_system=data_store,
                            collection_name=collection,
                            record_json=record_with_meta,
                            updated_at=snap_captured_at,
                            captured_at=evidence_file.captured_at,
                        ))
                    except Exception as e:
                        errors.append(f"Snapshot record parse error: {e}")

            # ── Format A: service_exports dict ────────────────────────────────
            service_exports = data.get("service_exports")
            if isinstance(service_exports, dict):
                for service_name, service_data in service_exports.items():
                    if not isinstance(service_data, dict):
                        continue
                    # Each key inside service_data is a collection name; value is a list
                    for collection_name, item_list in service_data.items():
                        if not isinstance(item_list, list):
                            continue
                        for item in item_list:
                            if not isinstance(item, dict):
                                continue
                            resource_id = item.get("resource_id")
                            if not resource_id:
                                continue
                            # Determine timestamp from item
                            ts_raw = item.get("observed_at") or item.get("created_at") or item.get("updated_at")
                            try:
                                updated_at = datetime.fromisoformat(
                                    str(ts_raw).replace("Z", "+00:00")
                                ) if ts_raw else evidence_file.captured_at
                            except (ValueError, TypeError):
                                updated_at = evidence_file.captured_at

                            record_with_meta = dict(item)
                            record_with_meta["_data_store"] = service_name
                            record_with_meta["_collection"] = collection_name

                            # Infer state from status indicators
                            pii_keys = ["email", "phone", "email_hash", "customer_reference"]
                            pii_in_item = [k for k in pii_keys if k in item]
                            pii_present = [k for k in pii_in_item if item[k] not in (None, "null", "")]
                            pii_all_null = len(pii_in_item) > 0 and len(pii_present) == 0

                            # Security/legal collections: presence of event_code or retention_until means RETAINED
                            is_security_or_legal = any(
                                x in collection_name.lower()
                                for x in ("security", "audit", "legal", "hold")
                            )

                            if item.get("status_code") == 404:
                                record_with_meta["_inferred_state"] = "ABSENT"
                            elif item.get("status_code") == 200:
                                if pii_all_null:
                                    record_with_meta["_inferred_state"] = "ANONYMIZED"
                                elif pii_present:
                                    record_with_meta["_inferred_state"] = "PRESENT"
                            elif item.get("profile") is None and "profile" in item:
                                # profile key present but null -> record absent
                                record_with_meta["_inferred_state"] = "ABSENT"
                            elif item.get("profile") is not None:
                                record_with_meta["_inferred_state"] = "PRESENT"
                            elif is_security_or_legal and (
                                item.get("event_code") or item.get("retention_until")
                                or item.get("event_name") or item.get("integrity_seal")
                            ):
                                record_with_meta["_inferred_state"] = "RETAINED"
                            elif pii_all_null:
                                record_with_meta["_inferred_state"] = "ANONYMIZED"
                            elif pii_present:
                                record_with_meta["_inferred_state"] = "PRESENT"

                            try:
                                records.append(EvidenceRecord(
                                    file_id=evidence_file.file_id,
                                    resource_id=resource_id,
                                    origin_system=service_name,
                                    collection_name=collection_name,
                                    record_json=record_with_meta,
                                    updated_at=updated_at,
                                    captured_at=evidence_file.captured_at,
                                ))
                            except Exception as e:
                                errors.append(f"Service export record parse error ({service_name}/{collection_name}): {e}")

            # ── Format B: top-level "records" list ────────────────────────────
            elif "records" in data and isinstance(data["records"], list) and "snapshots" not in data:
                # Derive service/collection from top-level keys
                service_name = data.get("source", data.get("origin", "unknown"))
                collection_name = data.get("collection", "records")
                for item in data["records"]:
                    if not isinstance(item, dict):
                        continue
                    resource_id = item.get("resource_id")
                    if not resource_id:
                        continue
                    ts_raw = (
                        item.get("recorded_at")
                        or item.get("observed_at")
                        or item.get("created_at")
                        or item.get("updated_at")
                    )
                    try:
                        updated_at = datetime.fromisoformat(
                            str(ts_raw).replace("Z", "+00:00")
                        ) if ts_raw else evidence_file.captured_at
                    except (ValueError, TypeError):
                        updated_at = evidence_file.captured_at

                    # Infer origin_system from item's "system" field if present
                    origin = item.get("system", service_name)
                    coll = item.get("record_type", collection_name).lower()

                    record_with_meta = dict(item)
                    record_with_meta["_data_store"] = origin
                    record_with_meta["_collection"] = coll

                    # Map result field to inferred state
                    result_val = str(item.get("result", "")).upper()
                    if result_val in ("NOT_FOUND", "ABSENT", "DELETED"):
                        record_with_meta["_inferred_state"] = "ABSENT"
                    elif result_val in ("ANONYMIZED",):
                        record_with_meta["_inferred_state"] = "ANONYMIZED"
                    elif result_val in ("REDACTED",):
                        record_with_meta["_inferred_state"] = "REDACTED"

                    try:
                        records.append(EvidenceRecord(
                            file_id=evidence_file.file_id,
                            resource_id=resource_id,
                            origin_system=origin,
                            collection_name=coll,
                            record_json=record_with_meta,
                            updated_at=updated_at,
                            captured_at=evidence_file.captured_at,
                        ))
                    except Exception as e:
                        errors.append(f"Record list parse error: {e}")

        except json.JSONDecodeError as e:
            errors.append(f"JSON decode error: {e}")
        except Exception as e:
            errors.append(f"JSON extraction error: {e}")

        if not records:
            warnings.append("No records extracted from JSON file")

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="json"
        )

    def _extract_log(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract from structured log files.

        Handles four formats encountered in this dataset:
          1. Pure JSON lines: {"key": "value", ...}
          2. Timestamp + JSON:  2026-..Z {...}
          3. Key=value lines:   2026-..Z level=INFO service=foo trace_id=bar event=x resource_id=y ...
          4. Other structured line formats with pipe/bracket separators (best-effort).

        For key=value "resource_lookup_trace" files the extractor merges
        *_started and *_completed pairs by trace_id so that lookup_key (the
        identifier used for the lookup) is paired with the lookup result
        (rows, http_status, direct PII presence) on the same synthetic record.
        """
        records = []
        errors = []
        warnings = []
        line_count = 0

        # trace_id → merged dict for key=value logs and JSON logs
        kv_by_trace: Dict[str, dict] = {}
        json_by_trace: Dict[str, dict] = {}

        def _parse_kv(line: str) -> Optional[dict]:
            """Parse a key=value log line into a dict. Returns None if no k=v pairs found."""
            # Strip timestamp prefix (ISO-8601 format at start of line)
            stripped = re.sub(r'^20\d{2}-\d{2}-\d{2}T[\d:]+Z\s*', '', line)
            # Allow lines starting with syslog priority markers <15>1 …
            stripped = re.sub(r'^<\d+>\d+\s+\S+\s+', '', stripped)
            # Extract key=value pairs (values may be quoted or unquoted)
            pairs = re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', stripped)
            if not pairs:
                return None
            d: dict = {}
            for k, v in pairs:
                # Strip surrounding quotes
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1].replace('\\"', '"')
                d[k] = v
            return d if d else None

        def _kv_to_record(merged: dict, file_id: str, captured_at: datetime) -> Optional[EvidenceRecord]:
            resource_id = merged.get("resource_id")
            if not resource_id:
                return None
            service = merged.get("service", merged.get("logger", merged.get("function", "unknown")))
            # Determine inferred state from lookup result fields
            rows = merged.get("rows")
            http_status = merged.get("http_status")
            # Direct PII nullness check for anonymized state
            pii_fields = {"email", "phone", "email_hash", "customer_reference", "subject_ref", "lookup_key"}
            pii_keys_in_record = [f for f in pii_fields if f in merged]
            pii_present_fields = {f for f in pii_fields if merged.get(f) not in (None, "null", "")}
            all_pii_null = (
                len(pii_keys_in_record) > 0 and
                all(merged.get(f) in (None, "null", "") for f in pii_keys_in_record)
            )
            inferred = None
            if rows == "0" or http_status == "404":
                inferred = "ABSENT"
            elif rows is not None and rows != "":
                try:
                    r_int = int(rows)
                    if r_int > 0:
                        if pii_present_fields:
                            inferred = "PRESENT"
                        elif all_pii_null:
                            inferred = "ANONYMIZED"
                        else:
                            inferred = "PRESENT"
                except ValueError:
                    pass
            elif all_pii_null:
                inferred = "ANONYMIZED"
            elif pii_present_fields:
                inferred = "PRESENT"
            if inferred:
                merged["_inferred_state"] = inferred

            rec_time = captured_at
            if "event_time" in merged:
                try:
                    rec_time = datetime.fromisoformat(str(merged["event_time"]).replace("Z", "+00:00"))
                except Exception:
                    pass

            return EvidenceRecord(
                file_id=file_id,
                resource_id=resource_id,
                origin_system=service,
                collection_name="log_entry",
                record_json=merged,
                updated_at=rec_time,
                captured_at=captured_at,
            )

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()

            for line_num, raw_line in enumerate(all_lines, 1):
                line = raw_line.strip()
                if not line:
                    continue
                line_count += 1

                # ── Attempt 1: JSON object (full line or embedded after timestamp) ──
                json_obj = None
                if line.startswith("{"):
                    try:
                        json_obj = json.loads(line)
                    except json.JSONDecodeError:
                        pass
                elif re.match(r'^20\d{2}-\d{2}-\d{2}T', line) and " {" in line:
                    try:
                        json_start = line.index("{")
                        json_obj = json.loads(line[json_start:])
                    except (ValueError, json.JSONDecodeError):
                        pass
                elif re.search(r'\{.*\}', line):
                    m = re.search(r'\{.*\}', line)
                    if m:
                        try:
                            json_obj = json.loads(m.group(0))
                        except json.JSONDecodeError:
                            pass

                if json_obj is not None:
                    m_ts = re.match(r'^(20\d{2}-\d{2}-\d{2}T[\d:]+Z)', line)
                    if m_ts and "event_time" not in json_obj:
                        json_obj["event_time"] = m_ts.group(1)
                    trace_id = json_obj.get("trace_id")
                    if trace_id:
                        if trace_id not in json_by_trace:
                            json_by_trace[trace_id] = {}
                        json_by_trace[trace_id].update(json_obj)
                    elif json_obj.get("resource_id"):
                        rec = _kv_to_record(json_obj, evidence_file.file_id, evidence_file.captured_at)
                        if rec:
                            records.append(rec)
                    continue

                # ── Attempt 2: key=value format ──────────────────────────────
                kv = _parse_kv(line)
                if kv:
                    m_ts = re.match(r'^(20\d{2}-\d{2}-\d{2}T[\d:]+Z)', line)
                    if m_ts and "event_time" not in kv:
                        kv["event_time"] = m_ts.group(1)
                    trace_id = kv.get("trace_id")
                    resource_id = kv.get("resource_id")

                    if trace_id:
                        if trace_id not in kv_by_trace:
                            kv_by_trace[trace_id] = {}
                        kv_by_trace[trace_id].update(kv)
                    elif resource_id:
                        rec = _kv_to_record(kv, evidence_file.file_id, evidence_file.captured_at)
                        if rec:
                            records.append(rec)

        except Exception as e:
            errors.append(f"Log extraction error: {e}")

        # Emit merged JSON trace records
        for trace_id, merged in json_by_trace.items():
            rec = _kv_to_record(merged, evidence_file.file_id, evidence_file.captured_at)
            if rec:
                records.append(rec)

        # Emit merged KV trace records
        for trace_id, merged in kv_by_trace.items():
            rec = _kv_to_record(merged, evidence_file.file_id, evidence_file.captured_at)
            if rec:
                records.append(rec)

        if line_count == 0:
            warnings.append("No valid log lines found")

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="log"
        )

    def _extract_text(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract from customer_account_handover text file."""
        records = []
        errors = []
        warnings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("- 2026-"):
                        continue
                    if line.startswith("CUSTOMER PLATFORM") or line.startswith("Snapshot:"):
                        continue

                    if line.startswith("- "):
                        line = line[2:]

                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 6:
                        timestamp_str = parts[0]
                        system = parts[1]
                        resource_id = parts[2]
                        record_type = parts[3]
                        result = parts[4]
                        identifier = parts[5] if len(parts) > 5 else ""

                        try:
                            updated_at = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        except ValueError:
                            updated_at = evidence_file.captured_at
                            warnings.append(f"Invalid timestamp in line: {timestamp_str}")

                        records.append(EvidenceRecord(
                            file_id=evidence_file.file_id,
                            resource_id=resource_id,
                            origin_system=system,
                            collection_name=record_type.lower(),
                            record_json={
                                "record_type": record_type,
                                "result": result,
                                "identifier": identifier,
                                "timestamp": timestamp_str,
                            },
                            updated_at=updated_at,
                            captured_at=evidence_file.captured_at,
                        ))

        except Exception as e:
            errors.append(f"Text extraction error: {e}")

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="text"
        )

    def _extract_pdf(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract text from PDF using pypdf with improved table handling."""
        records = []
        errors = []
        warnings = []

        try:
            from pypdf import PdfReader
        except ImportError:
            errors.append("pypdf not installed")
            return ExtractionResult(
                file_id=evidence_file.file_id,
                file_path=evidence_file.file_path,
                captured_at=evidence_file.captured_at,
                records=[],
                parse_errors=errors,
                extraction_method="pdf"
            )

        try:
            reader = PdfReader(str(file_path))
            text_content = []
            tables_found = False

            for page_num, page in enumerate(reader.pages):
                try:
                    text = page.extract_text()
                    if text:
                        text_content.append(f"--- PAGE {page_num + 1} ---\n{text}")
                except Exception as e:
                    warnings.append(f"Page {page_num + 1} extraction error: {e}")

                # Try to extract tables
                try:
                    if hasattr(page, 'extract_tables'):
                        tables = page.extract_tables()
                        if tables:
                            tables_found = True
                            for table_idx, table in enumerate(tables):
                                table_text = self._format_table(table)
                                text_content.append(f"--- PAGE {page_num + 1} TABLE {table_idx + 1} ---\n{table_text}")
                except Exception:
                    pass

            full_text = "\n".join(text_content)

            if not full_text.strip():
                warnings.append("No text extracted from PDF")

            found_rids = re.findall(r'\b((?:account|search|analytics|support|export|backup|data_flow|tombstone|audit_record)_\d+)\b', full_text)
            chosen_rid = found_rids[0] if found_rids else file_path.stem
            origin_sys = evidence_file.origin if evidence_file.origin else "pdf_document"

            records.append(EvidenceRecord(
                file_id=evidence_file.file_id,
                resource_id=chosen_rid,
                origin_system=origin_sys,
                collection_name="support_attachments" if "support" in origin_sys else "document_records",
                record_json={
                    "text": full_text,
                    "pages": len(reader.pages),
                    "tables_extracted": tables_found,
                    "_inferred_state": "PRESENT" if ("@" in full_text or any(c.isdigit() for c in full_text)) else "ABSENT"
                },
                updated_at=evidence_file.captured_at,
                captured_at=evidence_file.captured_at,
            ))

        except Exception as e:
            errors.append(f"PDF extraction error: {e}")

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="pdf"
        )

    def _format_table(self, table: List[List[Optional[str]]]) -> str:
        """Format a table as text."""
        if not table:
            return ""

        # Find max width for each column
        col_widths = [0] * len(table[0])
        for row in table:
            for i, cell in enumerate(row):
                if cell:
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        lines = []
        for row in table:
            cells = []
            for i, cell in enumerate(row):
                cell_str = str(cell) if cell else ""
                cells.append(cell_str.ljust(col_widths[i]))
            lines.append(" | ".join(cells))

        return "\n".join(lines)

    def _extract_image(self, evidence_file: EvidenceFile, file_path: Path) -> ExtractionResult:
        """Extract text from image using OCR (Tesseract preferred)."""
        records = []
        errors = []
        warnings = []

        # Try Tesseract first
        text = self._ocr_tesseract(file_path, errors, warnings)

        # If Tesseract fails or returns little text, try PaddleOCR
        if not text or len(text.strip()) < 50:
            text_paddle = self._ocr_paddleocr(file_path, errors, warnings)
            if text_paddle and len(text_paddle.strip()) > len(text.strip()):
                text = text_paddle
                warnings.append("Used PaddleOCR as primary (better result)")

        if not text or not text.strip():
            warnings.append("No text extracted from image")
            text = ""

        found_rids = re.findall(r'\b((?:account|search|analytics|support|export|backup|data_flow|tombstone|audit_record)_\d+)\b', text)
        chosen_rid = found_rids[0] if found_rids else file_path.stem
        origin_sys = evidence_file.origin if evidence_file.origin else "image_ocr"

        records.append(EvidenceRecord(
            file_id=evidence_file.file_id,
            resource_id=chosen_rid,
            origin_system=origin_sys,
            collection_name="image_records",
            record_json={
                "text": text,
                "extraction_method": "tesseract" if "tesseract" in str(errors).lower() or not warnings else "paddleocr"
            },
            updated_at=evidence_file.captured_at,
            captured_at=evidence_file.captured_at,
        ))

        return ExtractionResult(
            file_id=evidence_file.file_id,
            file_path=evidence_file.file_path,
            captured_at=evidence_file.captured_at,
            records=records,
            parse_errors=errors,
            warnings=warnings,
            extraction_method="ocr"
        )

    def _ocr_tesseract(self, file_path: Path, errors: List[str], warnings: List[str]) -> str:
        """OCR using Tesseract."""
        try:
            import pytesseract
            from PIL import Image
        except ImportError:
            errors.append("Tesseract not available (pytesseract or PIL not installed)")
            return ""

        try:
            image = Image.open(file_path)
            # Preprocess for better OCR
            image = image.convert('L')  # Grayscale
            # Increase contrast
            from PIL import ImageEnhance
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(2.0)

            text = pytesseract.image_to_string(image, config='--psm 6')
            return text
        except pytesseract.TesseractNotFoundError:
            errors.append("Tesseract binary not found in PATH")
            return ""
        except Exception as e:
            errors.append(f"Tesseract OCR error: {e}")
            return ""

    def _ocr_paddleocr(self, file_path: Path, errors: List[str], warnings: List[str]) -> str:
        """OCR using PaddleOCR."""
        try:
            from paddleocr import PaddleOCR
        except ImportError:
            errors.append("PaddleOCR not installed")
            return ""

        try:
            ocr = PaddleOCR(use_angle_cls=True, lang='en', show_log=False)
            result = ocr.ocr(str(file_path), cls=True)

            text_lines = []
            for page in result:
                if page:
                    for line in page:
                        if line and len(line) >= 2:
                            text_lines.append(line[1][0])

            return "\n".join(text_lines)
        except Exception as e:
            errors.append(f"PaddleOCR error: {e}")
            return ""

    def _records_to_facts(self, result: ExtractionResult) -> List[ExtractedFact]:
        """Convert EvidenceRecords to ExtractedFacts with identifier extraction."""
        facts = []

        for record in result.records:
            rj = record.record_json

            # Extract identifiers from various sources
            identifiers = self._extract_identifiers_from_record(record)
            if not identifiers and record.resource_id:
                identifiers = [("resource_id", record.resource_id, record.resource_id)]

            for id_type, id_value, original_text in identifiers:
                if not id_value:
                    continue

                fact_id = hashlib.md5(
                    f"{result.file_id}:{record.resource_id}:{id_type}:{id_value}".encode()
                ).hexdigest()[:12]

                # Try to extract event timestamp
                event_ts = None
                for ts_field in ["timestamp", "updated_at", "event_time", "created_at"]:
                    if ts_field in rj and rj[ts_field]:
                        try:
                            event_ts = datetime.fromisoformat(str(rj[ts_field]).replace("Z", "+00:00"))
                            break
                        except (ValueError, TypeError):
                            pass

                fact = ExtractedFact(
                    fact_id=fact_id,
                    file_id=result.file_id,
                    file_path=result.file_path,
                    captured_at=result.captured_at,
                    event_timestamp=event_ts,
                    system_id=record.origin_system,
                    resource_id=record.resource_id,
                    collection_name=record.collection_name,
                    identifier_type=id_type,
                    identifier_value=id_value,
                    original_text=original_text,
                    record_json=rj
                )
                facts.append(fact)

        return facts

    def _extract_identifiers_from_record(self, record: EvidenceRecord) -> List[Tuple[str, str, str]]:
        """Extract all identifiers from a record. Returns list of (type, value, original_text)."""
        identifiers = []
        rj = record.record_json

        # Direct fields (in priority order)
        id_fields = {
            "email": "email",
            "phone": "phone",
            "email_hash": "email_hash",
            "user_id": "user_id",
            "customer_reference": "customer_reference",
            "subject_reference": "subject_reference",
            "owner_email": "email",
            "requester_email": "email",
            "customer_email": "email",
            "contact_email": "email",
            "target_email": "email",
            "requester_phone": "phone",
            "owner_phone": "phone",
            "customer_phone": "phone",
            "subject_selector": "email_or_user",
            "subject_ref": "user_id",
            "lookup_key": "email_or_user",
        }

        for field_name, id_type in id_fields.items():
            val = rj.get(field_name)
            if val and isinstance(val, str) and val.strip() and val.strip().lower() != "null":
                identifiers.append((id_type, val.strip(), val.strip()))

        # Nested document (search_service)
        doc = rj.get("document")
        if isinstance(doc, dict):
            for field_name, id_type in id_fields.items():
                val = doc.get(field_name)
                if val and isinstance(val, str) and val.strip() and val.strip().lower() != "null":
                    identifiers.append((id_type, val.strip(), val.strip()))

        # Nested profile (service_exports account_service profile_lookups)
        profile = rj.get("profile")
        if isinstance(profile, dict):
            for field_name, id_type in id_fields.items():
                val = profile.get(field_name)
                if val and isinstance(val, str) and val.strip() and val.strip().lower() != "null":
                    identifiers.append((id_type, val.strip(), val.strip()))

        # Nested hits.documents (search index_queries)
        hits = rj.get("hits")
        if isinstance(hits, dict):
            for doc_item in hits.get("documents", []):
                if isinstance(doc_item, dict):
                    for field_name, id_type in id_fields.items():
                        val = doc_item.get(field_name)
                        if val and isinstance(val, str) and val.strip() and val.strip().lower() != "null":
                            identifiers.append((id_type, val.strip(), val.strip()))

        # Email hash variations
        for field_name in ["hashed_email", "email_sha256"]:
            val = rj.get(field_name)
            if val and isinstance(val, str) and val.strip():
                identifiers.append(("email_hash", val.strip(), val.strip()))

        # "identifier" field from text-based handover records
        # Classify: if contains @  -> email; if starts with user_ -> user_id; else -> customer_reference
        identifier_val = rj.get("identifier")
        if identifier_val and isinstance(identifier_val, str):
            iv = identifier_val.strip()
            if iv and iv.lower() != "null":
                if "@" in iv and "." in iv:
                    identifiers.append(("email", iv.lower(), iv))
                elif iv.lower().startswith("user_"):
                    identifiers.append(("user_id", iv, iv))
                else:
                    identifiers.append(("customer_reference", iv, iv))

        # "lookup_key" field from log-based traces
        # Same classification rules as "identifier"
        lookup_val = rj.get("lookup_key")
        if lookup_val and isinstance(lookup_val, str):
            lv = lookup_val.strip()
            if lv and lv.lower() not in ("null", "none", ""):
                if "@" in lv and "." in lv:
                    identifiers.append(("email", lv.lower(), lv))
                elif lv.lower().startswith("user_"):
                    identifiers.append(("user_id", lv, lv))
                else:
                    identifiers.append(("customer_reference", lv, lv))

        # Extract emails from text fields using regex
        text_fields = ["message_text", "description", "details", "text", "notes", "message_excerpt"]
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        for field_name in text_fields:
            val = rj.get(field_name)
            if val and isinstance(val, str):
                for match in email_pattern.finditer(val):
                    identifiers.append(("email", match.group(0).lower(), match.group(0)))

        # Extract phones from text
        phone_pattern = re.compile(r'(\+\d{1,3}[\s\-\.\(\)]?\d{1,4}[\s\-\.\(\)]?\d{1,4}[\s\-\.\(\)]?\d{1,9})')
        for field_name in text_fields:
            val = rj.get(field_name)
            if val and isinstance(val, str):
                for match in phone_pattern.finditer(val):
                    phone = match.group(1)
                    normalized = re.sub(r'[\s\-\.\(\)]', '', phone)
                    identifiers.append(("phone", normalized, phone))

        return identifiers


def extract_all_evidence(evidence_files: List[EvidenceFile]) -> Tuple[List[ExtractionResult], List[ExtractedFact]]:
    """
    Convenience function to extract all evidence.

    Returns:
        (extraction_results, all_facts)
    """
    extractor = EvidenceExtractor()
    results = extractor.extract_all(evidence_files)
    return results, extractor.all_facts


def test_evidence_extraction():
    """Test evidence extraction on sample files."""
    from loaders import load_evidence_files

    evidence_files = load_evidence_files()

    # Test on a few files of each type
    test_files = []
    for ef in evidence_files:
        ext = Path(ef.file_path).suffix.lower()
        if ext in [".sql", ".json", ".log", ".txt", ".pdf", ".png"] and len(test_files) < 10:
            test_files.append(ef)

    extractor = EvidenceExtractor()
    results = extractor.extract_all(test_files)
    facts = extractor.all_facts

    print("Evidence Extraction Results:")
    for r in results:
        print(f"  {r.file_id} ({r.extraction_method}): {len(r.records)} records, "
              f"{len(r.parse_errors)} errors, {len(r.warnings)} warnings")
        if r.parse_errors:
            for e in r.parse_errors[:2]:
                print(f"    ERROR: {e}")

    print(f"\nTotal facts extracted: {len(facts)}")

    # Show sample facts
    print("\nSample extracted facts:")
    for fact in facts[:10]:
        print(f"  {fact.fact_id}: {fact.identifier_type}={fact.identifier_value} "
              f"[{fact.system_id}/{fact.resource_id}] from {fact.file_id}")

    # Check for failed files
    if hasattr(extractor, 'failed_files') and extractor.failed_files:
        print("\nFailed files:")
        for fid, err in extractor.failed_files:
            print(f"  {fid}: {err}")

    return results, facts


if __name__ == "__main__":
    test_evidence_extraction()