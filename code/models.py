"""
Data models for Ghost Data Still Exists challenge.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import json


@dataclass
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str

    @classmethod
    def from_dict(cls, d: dict) -> "DeletionRequest":
        return cls(
            case_id=d["case_id"],
            email=d["email"].strip().lower(),
            requested_at=datetime.fromisoformat(d["requested_at"].replace("Z", "+00:00")),
            reported_status=d["reported_status"],
            reported_at=datetime.fromisoformat(d["reported_at"].replace("Z", "+00:00")),
            audit_at=datetime.fromisoformat(d["audit_at"].replace("Z", "+00:00")),
            request_text=d["request_text"],
        )


@dataclass
class UserIdentity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime

    @classmethod
    def from_dict(cls, d: dict) -> "UserIdentity":
        return cls(
            user_id=d["user_id"],
            name=d["name"],
            email=d["email"].strip().lower(),
            phone=d["phone"],
            email_hash=d["email_hash"],
            updated_at=datetime.fromisoformat(d["updated_at"].replace("Z", "+00:00")),
        )


@dataclass
class UserAuditLog:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str

    @classmethod
    def from_dict(cls, d: dict) -> "UserAuditLog":
        return cls(
            audit_id=d["audit_id"],
            user_id=d["user_id"],
            event_time=datetime.fromisoformat(d["event_time"].replace("Z", "+00:00")),
            field_name=d["field_name"],
            old_value=d["old_value"],
            new_value=d["new_value"],
        )


@dataclass
class SystemActivity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str

    @classmethod
    def from_dict(cls, d: dict) -> "SystemActivity":
        return cls(
            activity_id=d["activity_id"],
            event_time=datetime.fromisoformat(d["event_time"].replace("Z", "+00:00")),
            event_type=d["event_type"],
            source_system=d["source_system"],
            target_system=d["target_system"],
            resource_id=d["resource_id"],
            reported_result=d["reported_result"],
            details=d["details"],
        )


@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str

    @classmethod
    def from_dict(cls, d: dict) -> "DeletionRule":
        return cls(
            rule_id=d["rule_id"],
            data_category=d["data_category"],
            condition=d["condition"],
            required_action=d["required_action"],
        )


@dataclass
class EvidenceFile:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceFile":
        return cls(
            file_id=d["file_id"],
            file_path=d["file_path"],
            origin=d["origin"],
            captured_at=datetime.fromisoformat(d["captured_at"].replace("Z", "+00:00")),
        )


@dataclass
class EvidenceRecord:
    """A single record extracted from any evidence source."""
    file_id: str
    resource_id: str
    origin_system: str
    collection_name: str
    record_json: dict
    updated_at: datetime
    captured_at: datetime  # When this evidence was captured (from evidence_files.csv)

    @classmethod
    def from_sql_row(cls, file_id: str, captured_at: datetime, row: tuple) -> "EvidenceRecord":
        resource_id, origin_system, collection_name, record_json_str, updated_at_str = row
        return cls(
            file_id=file_id,
            resource_id=resource_id,
            origin_system=origin_system,
            collection_name=collection_name,
            record_json=json.loads(record_json_str),
            updated_at=datetime.fromisoformat(updated_at_str.replace("Z", "+00:00")),
            captured_at=captured_at,
        )


@dataclass
class ResolvedIdentity:
    """Complete identity for a user including current and historical identifiers."""
    user_id: str
    current_email: str
    current_phone: str
    current_email_hash: str
    current_name: str
    historical_emails: set
    historical_phones: set
    historical_email_hashes: set

    def all_emails(self) -> set:
        emails = {self.current_email}
        emails.update(self.historical_emails)
        return emails

    def all_phones(self) -> set:
        phones = {self.current_phone}
        phones.update(self.historical_phones)
        return phones

    def all_email_hashes(self) -> set:
        hashes = {self.current_email_hash}
        hashes.update(self.historical_email_hashes)
        return hashes

    def matches(self, email: str = None, phone: str = None, email_hash: str = None) -> bool:
        if email and email.lower() in self.all_emails():
            return True
        if phone and phone in self.all_phones():
            return True
        if email_hash and email_hash in self.all_email_hashes():
            return True
        return False


@dataclass
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> dict:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }