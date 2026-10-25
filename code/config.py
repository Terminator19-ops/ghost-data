"""
Configuration constants for Ghost Data Still Exists challenge.
"""
from pathlib import Path

# Repository root
REPO_ROOT = Path(__file__).parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_CSV = REPO_ROOT / "output.csv"

# Evidence files CSV paths are relative to DATASET_DIR (e.g., "evidence/logs/...")
# So we need DATASET_DIR to resolve them correctly
EVIDENCE_BASE_DIR = DATASET_DIR

# CSV file paths
DELETION_REQUESTS_CSV = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_CSV = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_CSV = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_CSV = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_CSV = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_CSV = DATASET_DIR / "system_activity.csv"
DELETION_RULES_CSV = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_CSV = DATASET_DIR / "evidence_files.csv"

# Column names (must match CSV headers)
DELETION_REQUEST_COLS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
USER_IDENTITY_COLS = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
USER_AUDIT_LOG_COLS = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
SYSTEM_ACTIVITY_COLS = ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"]
DELETION_RULE_COLS = ["rule_id", "data_category", "condition", "required_action"]
EVIDENCE_FILE_COLS = ["file_id", "file_path", "origin", "captured_at"]

# Deletion statuses
STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Step phases
PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"

# Finding operations
OP_REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
OP_REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
OP_REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
OP_REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"

# Remediation operations
OP_DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
OP_BLOCK_RESTORE = "BLOCK_RESTORE"
OP_DELETE_RECORD = "DELETE_RECORD"
OP_REDACT_RECORD = "REDACT_RECORD"
OP_ANONYMIZE_RECORD = "ANONYMIZE_RECORD"

# Verification operations
OP_VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
OP_VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
OP_VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
OP_VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
OP_VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
OP_VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"

# States
STATE_PRESENT = "PRESENT"
STATE_ABSENT = "ABSENT"
STATE_ACTIVE = "ACTIVE"
STATE_DISABLED = "DISABLED"
STATE_BLOCKED = "BLOCKED"
STATE_REDACTED = "REDACTED"
STATE_ANONYMIZED = "ANONYMIZED"

# Operation order within each phase (for sorting)
FINDING_OP_ORDER = [
    OP_REPORT_REMAINING_RECORD,
    OP_REPORT_EXPOSED_PII,
    OP_REPORT_ACTIVE_DATA_FLOW,
    OP_REPORT_RESTORE_RISK,
]

REMEDIATION_OP_ORDER = [
    OP_DISABLE_DATA_FLOW,
    OP_BLOCK_RESTORE,
    OP_DELETE_RECORD,
    OP_REDACT_RECORD,
    OP_ANONYMIZE_RECORD,
]

VERIFICATION_OP_ORDER = [
    OP_VERIFY_RECORD_ABSENT,
    OP_VERIFY_RECORD_PRESENT,
    OP_VERIFY_RECORD_REDACTED,
    OP_VERIFY_RECORD_ANONYMIZED,
    OP_VERIFY_DATA_FLOW_DISABLED,
    OP_VERIFY_RESTORE_BLOCKED,
]

# Phase order
PHASE_ORDER = [PHASE_FINDING, PHASE_REMEDIATION, PHASE_VERIFICATION]

# Data categories from deletion_rules.csv
DATA_CATEGORIES = [
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE",
]

# System IDs (from evidence)
SYSTEM_IDS = [
    "account_service",
    "search_service",
    "analytics_platform",
    "support_platform",
    "integration_service",
    "backup_service",
    "export_service",
    "security_service",
    "identity_service",
    "profile_service",
    "cache_service",
    "notification_service",
    "email_delivery_service",
    "archive_service",
    "object_store",
]

# Collection names in SQL evidence
COLLECTIONS = [
    "customer_profiles",
    "customer_search_documents",
    "customer_analytics_reports",
    "security_audit_events",
    "backup_catalog",
    "connector_configurations",
    "support_conversations",
    "ticket_attachments",
    "customer_export_jobs",
    "deleted_customer_references",
]