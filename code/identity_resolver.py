"""
Identity resolution for Ghost Data Still Exists challenge.

Resolves current and historical identifiers for users:
- Current: from user_identities.csv (user_id, email, phone, email_hash, name)
- Historical: from user_audit_log.csv (phone changes) and evidence records (email changes)
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict

from models import UserIdentity, UserAuditLog, ResolvedIdentity, EvidenceRecord
from loaders import filter_evidence_by_time


@dataclass
class IdentityResolver:
    """
    Resolves user identifiers from current snapshot and historical audit log.
    """
    current_identities: Dict[str, UserIdentity]  # user_id -> UserIdentity
    email_to_user_id: Dict[str, str]  # email (lower) -> user_id
    phone_to_user_id: Dict[str, str]  # phone -> user_id
    email_hash_to_user_id: Dict[str, str]  # email_hash -> user_id
    audit_log_by_user: Dict[str, List[UserAuditLog]]  # user_id -> List[UserAuditLog]

    # Historical identifiers extracted from evidence (populated by enrich_from_evidence)
    historical_emails: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    historical_phones: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    historical_email_hashes: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

    @classmethod
    def build(cls, identities: List[UserIdentity], audit_log: List[UserAuditLog]) -> "IdentityResolver":
        """Build resolver from loaded data."""
        current_identities = {u.user_id: u for u in identities}
        email_to_user_id = {}
        phone_to_user_id = {}
        email_hash_to_user_id = {}
        audit_log_by_user = defaultdict(list)

        # Populate historical identifiers from audit log
        historical_emails = defaultdict(set)
        historical_phones = defaultdict(set)
        historical_email_hashes = defaultdict(set)

        for u in identities:
            email_to_user_id[u.email.lower()] = u.user_id
            phone_to_user_id[u.phone] = u.user_id
            email_hash_to_user_id[u.email_hash] = u.user_id
            # Add current identifiers to historical sets
            historical_emails[u.user_id].add(u.email.lower())
            historical_phones[u.user_id].add(u.phone)
            historical_email_hashes[u.user_id].add(u.email_hash)

        for log in audit_log:
            audit_log_by_user[log.user_id].append(log)
            # Extract historical identifiers from audit log
            if log.field_name == "email":
                historical_emails[log.user_id].add(log.old_value.lower())
                historical_emails[log.user_id].add(log.new_value.lower())
            elif log.field_name == "phone":
                historical_phones[log.user_id].add(log.old_value)
                historical_phones[log.user_id].add(log.new_value)
            elif log.field_name == "email_hash":
                historical_email_hashes[log.user_id].add(log.old_value)
                historical_email_hashes[log.user_id].add(log.new_value)

        # Sort audit logs by time for each user
        for user_logs in audit_log_by_user.values():
            user_logs.sort(key=lambda x: x.event_time)

        return cls(
            current_identities=current_identities,
            email_to_user_id=email_to_user_id,
            phone_to_user_id=phone_to_user_id,
            email_hash_to_user_id=email_hash_to_user_id,
            audit_log_by_user=audit_log_by_user,
            historical_emails=historical_emails,
            historical_phones=historical_phones,
            historical_email_hashes=historical_email_hashes,
        )

    def enrich_from_evidence(self, evidence_records: List[EvidenceRecord]) -> None:
        """
        Extract historical identifiers from evidence records.
        Evidence records may contain emails, phones, email_hashes not in current snapshot.
        """
        for record in evidence_records:
            rj = record.record_json

            # From customer_profiles (account_service)
            if record.collection_name == "customer_profiles":
                email = rj.get("email")
                phone = rj.get("phone")
                user_id = rj.get("customer_reference")
                if email and user_id:
                    self.historical_emails[user_id].add(email.lower())
                if phone and user_id:
                    self.historical_phones[user_id].add(phone)

            # From customer_search_documents (search_service)
            elif record.collection_name == "customer_search_documents":
                doc = rj.get("document", {})
                email = doc.get("email")
                customer_ref = doc.get("customer_reference")
                if email and customer_ref:
                    self.historical_emails[customer_ref].add(email.lower())

            # From customer_analytics_reports (analytics_platform)
            elif record.collection_name == "customer_analytics_reports":
                email = rj.get("email")
                phone = rj.get("phone")
                email_hash = rj.get("email_hash")
                user_id = rj.get("user_id")
                if email and user_id:
                    self.historical_emails[user_id].add(email.lower())
                if phone and user_id:
                    self.historical_phones[user_id].add(phone)
                if email_hash and user_id:
                    self.historical_email_hashes[user_id].add(email_hash)

            # From support_conversations (support_platform)
            elif record.collection_name == "support_conversations":
                # Messages may contain emails in message_text
                subject_ref = rj.get("subject_reference")
                message_text = rj.get("message_text", "")
                if subject_ref:
                    # Extract emails from message_text (simple approach)
                    import re
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', message_text)
                    for email in emails:
                        self.historical_emails[subject_ref].add(email.lower())

            # From connector_configurations (integration_service)
            elif record.collection_name == "connector_configurations":
                subject_selector = rj.get("subject_selector")
                if subject_selector and "@" in subject_selector:
                    # Could be email or user_id
                    # If it contains @, treat as email
                    # We don't know the user_id here without more context
                    pass

            # From customer_export_jobs (export_service)
            elif record.collection_name == "customer_export_jobs":
                owner_email = rj.get("owner_email")
                if owner_email:
                    # We need to map owner_email to user_id
                    # This will be resolved via email_to_user_id
                    pass

    def get_historical_identifiers(self, user_id: str, as_of: datetime) -> Dict[str, Set[str]]:
        """
        Get all historical identifiers for a user as of a given time.
        Includes:
        - Current identifiers (if updated_at <= as_of)
        - Phone changes from audit_log (old_value if event_time <= as_of)
        - Historical emails/phones/email_hashes from evidence (if captured_at <= as_of)
        """
        result = {
            "emails": set(),
            "phones": set(),
            "email_hashes": set(),
        }

        identity = self.current_identities.get(user_id)
        if identity and identity.updated_at <= as_of:
            result["emails"].add(identity.email.lower())
            result["phones"].add(identity.phone)
            result["email_hashes"].add(identity.email_hash)

        # Phone, email, and email_hash changes from audit log
        for log in self.audit_log_by_user.get(user_id, []):
            if log.event_time <= as_of:
                if log.field_name == "phone":
                    result["phones"].add(log.old_value)
                    result["phones"].add(log.new_value)
                elif log.field_name == "email":
                    result["emails"].add(log.old_value.lower())
                    result["emails"].add(log.new_value.lower())
                elif log.field_name == "email_hash":
                    result["email_hashes"].add(log.old_value)
                    result["email_hashes"].add(log.new_value)

        # Historical from evidence (already filtered by captured_at in enrich_from_evidence call)
        result["emails"].update(self.historical_emails.get(user_id, set()))
        result["phones"].update(self.historical_phones.get(user_id, set()))
        result["email_hashes"].update(self.historical_email_hashes.get(user_id, set()))

        return result

    def resolve_by_email(self, email: str) -> Optional[str]:
        """Resolve email to user_id (case-insensitive), checking current, historical, and audit log."""
        if not email:
            return None
        email_lower = email.lower()
        uid = self.email_to_user_id.get(email_lower)
        if uid:
            return uid
        for u, emails in self.historical_emails.items():
            if email_lower in emails:
                return u
        for u, logs in self.audit_log_by_user.items():
            for log in logs:
                if log.field_name == "email":
                    if (log.old_value and log.old_value.lower() == email_lower) or (log.new_value and log.new_value.lower() == email_lower):
                        return u
        return None

    def resolve_by_phone(self, phone: str) -> Optional[str]:
        """Resolve phone to user_id, checking current, historical, and audit log."""
        if not phone:
            return None
        uid = self.phone_to_user_id.get(phone)
        if uid:
            return uid
        for u, phones in self.historical_phones.items():
            if phone in phones:
                return u
        for u, logs in self.audit_log_by_user.items():
            for log in logs:
                if log.field_name == "phone":
                    if log.old_value == phone or log.new_value == phone:
                        return u
        return None

    def resolve_by_email_hash(self, email_hash: str) -> Optional[str]:
        """Resolve email_hash to user_id, checking current, historical, and audit log."""
        if not email_hash:
            return None
        uid = self.email_hash_to_user_id.get(email_hash)
        if uid:
            return uid
        for u, hashes in self.historical_email_hashes.items():
            if email_hash in hashes:
                return u
        for u, logs in self.audit_log_by_user.items():
            for log in logs:
                if log.field_name == "email_hash":
                    if log.old_value == email_hash or log.new_value == email_hash:
                        return u
        return None

    def resolve(self, email: str = None, phone: str = None, email_hash: str = None) -> Optional[str]:
        """
        Resolve identifier to user_id.
        Tries email first, then phone, then email_hash.
        """
        if email:
            user_id = self.resolve_by_email(email)
            if user_id:
                return user_id
        if phone:
            user_id = self.resolve_by_phone(phone)
            if user_id:
                return user_id
        if email_hash:
            user_id = self.resolve_by_email_hash(email_hash)
            if user_id:
                return user_id
        return None

    def get_resolved_identity(self, user_id: str, as_of: datetime) -> Optional[ResolvedIdentity]:
        """Get complete resolved identity for a user as of a given time."""
        identity = self.current_identities.get(user_id)
        if not identity:
            return None

        historical = self.get_historical_identifiers(user_id, as_of)

        return ResolvedIdentity(
            user_id=user_id,
            current_email=identity.email,
            current_phone=identity.phone,
            current_email_hash=identity.email_hash,
            current_name=identity.name,
            historical_emails=historical["emails"],
            historical_phones=historical["phones"],
            historical_email_hashes=historical["email_hashes"],
        )

    def find_user_for_request(self, request_email: str, evidence_records: List[EvidenceRecord]) -> Optional[str]:
        """
        Find the user_id for a deletion request.
        1. Try direct match on current email
        2. Try historical emails from evidence (case-insensitive)
        3. Try historical emails from audit log (phones only in audit log)
        """
        # Direct match
        user_id = self.resolve_by_email(request_email)
        if user_id:
            return user_id

        # Search historical emails in evidence
        request_email_lower = request_email.lower()
        for user_id, emails in self.historical_emails.items():
            if request_email_lower in emails:
                return user_id

        # Check if email appears in any evidence record
        for record in evidence_records:
            rj = record.record_json
            # Check various email fields
            for field in ["email", "owner_email", "subject_selector"]:
                val = rj.get(field)
                if val and isinstance(val, str) and val.lower() == request_email_lower:
                    # Try to get user_id from this record
                    for id_field in ["customer_reference", "user_id", "subject_reference"]:
                        uid = rj.get(id_field)
                        if uid and uid.startswith("user_"):
                            return uid
            # Check nested document
            doc = rj.get("document", {})
            if isinstance(doc, dict):
                email = doc.get("email")
                if email and email.lower() == request_email_lower:
                    customer_ref = doc.get("customer_reference")
                    if customer_ref and customer_ref.startswith("user_"):
                        return customer_ref

        return None


def build_resolver_with_evidence(
    identities: List[UserIdentity],
    audit_log: List[UserAuditLog],
    evidence_records: List[EvidenceRecord]
) -> IdentityResolver:
    """
    Build a fully enriched identity resolver.
    """
    resolver = IdentityResolver.build(identities, audit_log)
    resolver.enrich_from_evidence(evidence_records)
    return resolver