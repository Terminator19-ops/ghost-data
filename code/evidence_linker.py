"""
Evidence linking for Ghost Data Still Exists challenge.
Connects extracted evidence to stable user IDs using identity resolution.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple, Any
from collections import defaultdict

from models import UserIdentity, UserAuditLog, ResolvedIdentity, EvidenceRecord
from identity_resolver import IdentityResolver
from evidence_extractor import ExtractedFact


@dataclass
class EvidenceLink:
    """A link between evidence and a user."""
    fact_id: str
    file_id: str
    user_id: str
    matched_identifier_type: str  # "email", "phone", "email_hash", "customer_reference", "user_id"
    matched_identifier_value: str
    match_method: str  # "current", "historical_audit", "historical_evidence", "direct"
    match_confidence: float  # 0.0 - 1.0
    evidence_timestamp: datetime
    resource_id: str
    system_id: str
    collection_name: str
    record_json: Dict
    is_ambiguous: bool = False
    ambiguity_reason: str = ""


@dataclass
class UserEvidenceBundle:
    """All evidence linked to a single user."""
    user_id: str
    resolved_identity: ResolvedIdentity
    links: List[EvidenceLink] = field(default_factory=list)
    ambiguous_links: List[EvidenceLink] = field(default_factory=list)

    def get_records_by_system(self) -> Dict[str, List[EvidenceLink]]:
        """Group links by system_id."""
        result = defaultdict(list)
        for link in self.links:
            result[link.system_id].append(link)
        return dict(result)

    def get_records_by_collection(self) -> Dict[str, List[EvidenceLink]]:
        """Group links by collection_name."""
        result = defaultdict(list)
        for link in self.links:
            result[link.collection_name].append(link)
        return dict(result)

    def get_latest_timestamp(self) -> Optional[datetime]:
        """Get the latest evidence timestamp for this user."""
        timestamps = [link.evidence_timestamp for link in self.links if link.evidence_timestamp]
        return max(timestamps) if timestamps else None


class EvidenceLinker:
    """Links evidence to user IDs using identity resolution."""

    def __init__(self, resolver: IdentityResolver):
        self.resolver = resolver
        self.user_bundles: Dict[str, UserEvidenceBundle] = {}
        self.unlinked_facts: List[ExtractedFact] = []
        self.ambiguous_matches: List[Tuple[ExtractedFact, List[str]]] = []  # (fact, possible_user_ids)

    def link_all_facts(self, facts: List[ExtractedFact], audit_at: datetime) -> Dict[str, UserEvidenceBundle]:
        """
        Link all extracted facts to user IDs.

        Args:
            facts: List of extracted facts from evidence
            audit_at: The audit cutoff time

        Returns:
            Dict mapping user_id to UserEvidenceBundle
        """
        self.user_bundles = {}
        self.unlinked_facts = []
        self.ambiguous_matches = []

        # First, try direct identifier matches (ignoring facts whose event/capture is after audit_at)
        for fact in facts:
            fact_time = fact.event_timestamp if fact.event_timestamp else fact.captured_at
            if fact_time and fact_time > audit_at:
                continue
            self._link_fact(fact, audit_at)

        # Cross-reference with system activity for sibling/workflow resources
        self._link_activity_resources(audit_at)

        # Build bundles
        self._build_bundles(audit_at)

        return self.user_bundles

    def _link_fact(self, fact: ExtractedFact, audit_at: datetime) -> None:
        """Link a single fact to a user ID."""
        possible_users = set()
        best_match = None
        best_confidence = 0.0
        best_method = ""
        matched_type = ""
        matched_value = ""

        # Strategy 1: Direct user_id / customer_reference / subject_reference match
        val = fact.identifier_value.strip()
        if (fact.identifier_type in ("user_id", "customer_reference", "subject_reference") or fact.identifier_type == "email_or_user") and val.startswith("user_"):
            user_id = val
            if user_id in self.resolver.current_identities:
                possible_users.add(user_id)
                best_match = user_id
                best_confidence = 1.0
                best_method = "direct"
                matched_type = fact.identifier_type
                matched_value = val

        # Strategy 2: Email match (current or historical)
        is_email = fact.identifier_type == "email" or (
            fact.identifier_type in ("email_or_user", "subject_reference") and "@" in val
        ) or ("@" in val and "." in val)
        if is_email and not best_match:
            email = val.lower()
            # Try current identities
            user_id = self.resolver.resolve_by_email(email)
            if user_id:
                possible_users.add(user_id)
                if 0.95 > best_confidence:
                    best_match = user_id
                    best_confidence = 0.95
                    best_method = "current"
                    matched_type = "email"
                    matched_value = email

            # Try historical emails from evidence
            for uid, emails in self.resolver.historical_emails.items():
                if email in emails:
                    possible_users.add(uid)
                    if 0.9 > best_confidence:
                        best_match = uid
                        best_confidence = 0.9
                        best_method = "historical_evidence"
                        matched_type = "email"
                        matched_value = email

            # Try audit log for email changes
            for uid, logs in self.resolver.audit_log_by_user.items():
                for log in logs:
                    if log.field_name == "email" and log.event_time <= audit_at:
                        if log.old_value.lower() == email or log.new_value.lower() == email:
                            possible_users.add(uid)
                            if 0.85 > best_confidence:
                                best_match = uid
                                best_confidence = 0.85
                                best_method = "historical_audit"
                                matched_type = "email"
                                matched_value = email

        # Strategy 3: Phone match (current or historical)
        if fact.identifier_type == "phone" and not best_match:
            phone = fact.identifier_value
            # Try current identities
            user_id = self.resolver.resolve_by_phone(phone)
            if user_id:
                possible_users.add(user_id)
                if 0.95 > best_confidence:
                    best_match = user_id
                    best_confidence = 0.95
                    best_method = "current"
                    matched_type = "phone"
                    matched_value = phone

            # Try historical phones from evidence
            for uid, phones in self.resolver.historical_phones.items():
                if phone in phones:
                    possible_users.add(uid)
                    if 0.9 > best_confidence:
                        best_match = uid
                        best_confidence = 0.9
                        best_method = "historical_evidence"
                        matched_type = "phone"
                        matched_value = phone

            # Try audit log for phone changes
            for uid, logs in self.resolver.audit_log_by_user.items():
                for log in logs:
                    if log.field_name == "phone" and log.event_time <= audit_at:
                        if log.old_value == phone or log.new_value == phone:
                            possible_users.add(uid)
                            if 0.85 > best_confidence:
                                best_match = uid
                                best_confidence = 0.85
                                best_method = "historical_audit"
                                matched_type = "phone"
                                matched_value = phone

        # Strategy 4: Email hash match
        if fact.identifier_type == "email_hash" and not best_match:
            email_hash = fact.identifier_value
            user_id = self.resolver.resolve_by_email_hash(email_hash)
            if user_id:
                possible_users.add(user_id)
                if 0.95 > best_confidence:
                    best_match = user_id
                    best_confidence = 0.95
                    best_method = "current"
                    matched_type = "email_hash"
                    matched_value = email_hash

            # Try historical email hashes
            for uid, hashes in self.resolver.historical_email_hashes.items():
                if email_hash in hashes:
                    possible_users.add(uid)
                    if 0.9 > best_confidence:
                        best_match = uid
                        best_confidence = 0.9
                        best_method = "historical_evidence"
                        matched_type = "email_hash"
                        matched_value = email_hash

        # Strategy 5: Cross-reference with resource_id patterns
        # Some resource_ids contain user_id (e.g., "account_user_123")
        if not best_match and fact.resource_id.startswith("account_"):
            # Extract potential user_id from resource_id
            parts = fact.resource_id.split("_")
            for part in parts:
                if part.startswith("user_"):
                    if part in self.resolver.current_identities:
                        possible_users.add(part)
                        if 0.7 > best_confidence:
                            best_match = part
                            best_confidence = 0.7
                            best_method = "resource_id_pattern"
                            matched_type = "resource_id"
                            matched_value = part

        # Check for ambiguity
        is_ambiguous = len(possible_users) > 1
        ambiguity_reason = ""
        if is_ambiguous:
            ambiguity_reason = f"Matched {len(possible_users)} users: {', '.join(sorted(possible_users))}"
            self.ambiguous_matches.append((fact, sorted(possible_users)))

        if best_match:
            link = EvidenceLink(
                fact_id=fact.fact_id,
                file_id=fact.file_id,
                user_id=best_match,
                matched_identifier_type=matched_type,
                matched_identifier_value=matched_value,
                match_method=best_method,
                match_confidence=best_confidence,
                evidence_timestamp=fact.event_timestamp or fact.captured_at,
                resource_id=fact.resource_id,
                system_id=fact.system_id,
                collection_name=fact.collection_name,
                record_json=fact.record_json,
                is_ambiguous=is_ambiguous,
                ambiguity_reason=ambiguity_reason
            )

            if best_match not in self.user_bundles:
                identity = self.resolver.get_resolved_identity(best_match, audit_at)
                self.user_bundles[best_match] = UserEvidenceBundle(
                    user_id=best_match,
                    resolved_identity=identity
                )
            self.user_bundles[best_match].links.append(link)

            if is_ambiguous:
                self.user_bundles[best_match].ambiguous_links.append(link)
        else:
            self.unlinked_facts.append(fact)

    def _link_activity_resources(self, audit_at: datetime) -> None:
        """
        Cross-reference unlinked facts with deletion activities in system_activity.csv.
        """
        import os
        import csv
        from datetime import timedelta
        from config import SYSTEM_ACTIVITY_CSV, SAMPLE_DELETION_REQUESTS_CSV, DELETION_REQUESTS_CSV

        if not os.path.exists(str(SYSTEM_ACTIVITY_CSV)):
            return

        del_acts = []
        try:
            with open(str(SYSTEM_ACTIVITY_CSV), 'r', encoding='utf-8') as f:
                for r in csv.DictReader(f):
                    if r.get('source_system') == 'deletion_worker':
                        t = datetime.fromisoformat(r['event_time'].replace('Z', '+00:00'))
                        if t <= audit_at:
                            del_acts.append({
                                'id': r['activity_id'],
                                'time': t,
                                'type': r['event_type'],
                                'target': r['target_system'],
                                'rid': r['resource_id'],
                                'result': r['reported_result'],
                                'details': r.get('details', '')
                            })
        except Exception:
            return

        if not del_acts:
            return

        # Load requests to find workflow windows
        req_by_user = {}
        for path in [SAMPLE_DELETION_REQUESTS_CSV, DELETION_REQUESTS_CSV]:
            if os.path.exists(str(path)):
                try:
                    with open(str(path), 'r', encoding='utf-8') as f:
                        for row in csv.DictReader(f):
                            if row.get('reported_status') == 'NOT_STARTED':
                                continue
                            rep_time = datetime.fromisoformat(row['reported_at'].replace('Z', '+00:00'))
                            if rep_time > audit_at:
                                continue
                            email = row['email'].lower()
                            uid = self.resolver.resolve_by_email(email)
                            if uid and uid not in req_by_user:
                                req_by_user[uid] = rep_time
                except Exception:
                    pass

        user_acts_map = defaultdict(list)
        for a in del_acts:
            matched_uids = []
            for uid, rep_time in req_by_user.items():
                if rep_time - timedelta(minutes=80) <= a['time'] <= rep_time + timedelta(minutes=15):
                    matched_uids.append(uid)
            if len(matched_uids) == 1:
                user_acts_map[matched_uids[0]].append(a)
            elif len(matched_uids) > 1:
                assigned = False
                for uid in matched_uids:
                    if uid in self.user_bundles:
                        user_acts_map[uid].append(a)
                        assigned = True
                        break
                if not assigned:
                    user_acts_map[matched_uids[0]].append(a)

        unlinked_by_rid = defaultdict(list)
        for f in self.unlinked_facts:
            unlinked_by_rid[f.resource_id].append(f)

        # Sibling link for existing bundles
        for user_id, bundle in list(self.user_bundles.items()):
            bundle_rids = {l.resource_id for l in bundle.links}
            burst_rids = set()
            if user_id in user_acts_map:
                burst_rids.update(a['rid'] for a in user_acts_map[user_id])
            for ma in [a for a in del_acts if a['rid'] in bundle_rids]:
                t = ma['time']
                for a in del_acts:
                    if abs((a['time'] - t).total_seconds()) <= 35 * 60:
                        burst_rids.add(a['rid'])

            for rid in burst_rids:
                if rid in unlinked_by_rid:
                    for fact in list(unlinked_by_rid[rid]):
                        if fact in self.unlinked_facts:
                            self.unlinked_facts.remove(fact)
                            link = EvidenceLink(
                                fact_id=fact.fact_id,
                                file_id=fact.file_id,
                                user_id=user_id,
                                matched_identifier_type="activity_cross_reference",
                                matched_identifier_value=rid,
                                match_method="activity_batch",
                                match_confidence=0.85,
                                evidence_timestamp=fact.event_timestamp or fact.captured_at,
                                resource_id=fact.resource_id,
                                system_id=fact.system_id,
                                collection_name=fact.collection_name,
                                record_json=fact.record_json,
                                is_ambiguous=False,
                                ambiguity_reason=""
                            )
                            bundle.links.append(link)

        # Also check for users that had requests and workflow activities but no bundle yet
        for uid, acts in user_acts_map.items():
            u_rids = {a['rid'] for a in acts}
            for rid in u_rids:
                if rid in unlinked_by_rid:
                    for fact in list(unlinked_by_rid[rid]):
                        if fact in self.unlinked_facts:
                            self.unlinked_facts.remove(fact)
                            if uid not in self.user_bundles:
                                identity = self.resolver.get_resolved_identity(uid, audit_at)
                                self.user_bundles[uid] = UserEvidenceBundle(
                                    user_id=uid,
                                    resolved_identity=identity
                                )
                            link = EvidenceLink(
                                fact_id=fact.fact_id,
                                file_id=fact.file_id,
                                user_id=uid,
                                matched_identifier_type="activity_cross_reference",
                                matched_identifier_value=rid,
                                match_method="activity_workflow",
                                match_confidence=0.85,
                                evidence_timestamp=fact.event_timestamp or fact.captured_at,
                                resource_id=fact.resource_id,
                                system_id=fact.system_id,
                                collection_name=fact.collection_name,
                                record_json=fact.record_json,
                                is_ambiguous=False,
                                ambiguity_reason=""
                            )
                            self.user_bundles[uid].links.append(link)

    def _build_bundles(self, audit_at: datetime) -> None:
        """Ensure all bundles have resolved identities."""
        for user_id, bundle in self.user_bundles.items():
            if bundle.resolved_identity is None:
                bundle.resolved_identity = self.resolver.get_resolved_identity(user_id, audit_at)

    def get_user_bundle(self, user_id: str) -> Optional[UserEvidenceBundle]:
        """Get evidence bundle for a user."""
        return self.user_bundles.get(user_id)

    def get_all_bundles(self) -> Dict[str, UserEvidenceBundle]:
        """Get all user evidence bundles."""
        return self.user_bundles

    def get_unlinked_facts(self) -> List[ExtractedFact]:
        """Get facts that couldn't be linked to any user."""
        return self.unlinked_facts

    def get_ambiguous_matches(self) -> List[Tuple[ExtractedFact, List[str]]]:
        """Get facts with ambiguous user matches."""
        return self.ambiguous_matches

    def filter_by_audit_time(self, audit_at: datetime) -> Dict[str, UserEvidenceBundle]:
        """Filter links to only those with evidence_timestamp <= audit_at."""
        filtered = {}
        for user_id, bundle in self.user_bundles.items():
            filtered_links = [
                link for link in bundle.links
                if link.evidence_timestamp <= audit_at
            ]
            filtered_ambiguous = [
                link for link in bundle.ambiguous_links
                if link.evidence_timestamp <= audit_at
            ]
            if filtered_links or filtered_ambiguous:
                filtered[user_id] = UserEvidenceBundle(
                    user_id=bundle.user_id,
                    resolved_identity=bundle.resolved_identity,
                    links=filtered_links,
                    ambiguous_links=filtered_ambiguous
                )
        return filtered

    def get_link_stats(self) -> Dict[str, Any]:
        """Get statistics about linking results."""
        total_links = sum(len(b.links) for b in self.user_bundles.values())
        total_ambiguous = sum(len(b.ambiguous_links) for b in self.user_bundles.values())
        users_with_evidence = len(self.user_bundles)

        by_system = defaultdict(int)
        by_collection = defaultdict(int)
        by_method = defaultdict(int)

        for bundle in self.user_bundles.values():
            for link in bundle.links:
                by_system[link.system_id] += 1
                by_collection[link.collection_name] += 1
                by_method[link.match_method] += 1

        return {
            "total_users_with_evidence": users_with_evidence,
            "total_links": total_links,
            "total_ambiguous_links": total_ambiguous,
            "unlinked_facts": len(self.unlinked_facts),
            "ambiguous_facts": len(self.ambiguous_matches),
            "by_system": dict(by_system),
            "by_collection": dict(by_collection),
            "by_match_method": dict(by_method)
        }


def link_evidence_to_users(
    facts: List[ExtractedFact],
    resolver: IdentityResolver,
    audit_at: datetime
) -> Tuple[Dict[str, UserEvidenceBundle], List[ExtractedFact], List[Tuple[ExtractedFact, List[str]]]]:
    """
    Convenience function to link all evidence to users.

    Returns:
        (user_bundles, unlinked_facts, ambiguous_matches)
    """
    linker = EvidenceLinker(resolver)
    bundles = linker.link_all_facts(facts, audit_at)
    return bundles, linker.get_unlinked_facts(), linker.get_ambiguous_matches()


def test_evidence_linking():
    """Test evidence linking with sample data."""
    from loaders import (
        load_user_identities,
        load_user_audit_log,
        load_evidence_files
    )
    from identity_resolver import build_resolver_with_evidence
    from evidence_extractor import extract_all_evidence

    # Load data
    identities = load_user_identities()
    audit_log = load_user_audit_log()
    evidence_files = load_evidence_files()

    # Extract evidence (test on subset)
    test_evidence_files = [ef for ef in evidence_files if ef.file_id in [
        "evidence_01", "evidence_02", "evidence_03", "evidence_05", "evidence_07"
    ]]

    extraction_results, facts = extract_all_evidence(test_evidence_files)

    print(f"Extracted {len(facts)} facts from {len(test_evidence_files)} evidence files")

    # Build resolver with evidence
    # First load all evidence records for resolver enrichment
    all_evidence_files = evidence_files[:20]  # Subset for testing
    _, all_facts = extract_all_evidence(all_evidence_files)
    all_records = []
    for er in extraction_results:
        all_records.extend(er.records)

    resolver = build_resolver_with_evidence(identities, audit_log, all_records)

    # Test linking for a specific audit time
    audit_at = datetime.fromisoformat("2026-09-15T12:00:00+00:00")

    linker = EvidenceLinker(resolver)
    bundles = linker.link_all_facts(facts, audit_at)
    unlinked = linker.get_unlinked_facts()
    ambiguous = linker.get_ambiguous_matches()

    print(f"\nLinking Results:")
    print(f"  Users with evidence: {len(bundles)}")
    print(f"  Total links: {sum(len(b.links) for b in bundles.values())}")
    print(f"  Ambiguous links: {sum(len(b.ambiguous_links) for b in bundles.values())}")
    print(f"  Unlinked facts: {len(unlinked)}")
    print(f"  Ambiguous matches: {len(ambiguous)}")

    # Show sample bundles
    print("\nSample user bundles:")
    for user_id, bundle in list(bundles.items())[:5]:
        print(f"  {user_id} ({bundle.resolved_identity.current_name if bundle.resolved_identity else 'Unknown'}): "
              f"{len(bundle.links)} links, {len(bundle.ambiguous_links)} ambiguous")
        for link in bundle.links[:3]:
            print(f"    {link.matched_identifier_type}={link.matched_identifier_value} "
                  f"({link.match_method}, conf={link.match_confidence:.2f}) "
                  f"[{link.system_id}/{link.resource_id}] from {link.file_id}")

    # Show unlinked facts sample
    if unlinked:
        print(f"\nSample unlinked facts ({len(unlinked)} total):")
        for fact in unlinked[:5]:
            print(f"  {fact.fact_id}: {fact.identifier_type}={fact.identifier_value} "
                  f"[{fact.system_id}/{fact.resource_id}] from {fact.file_id}")

    # Show ambiguous matches
    if ambiguous:
        print(f"\nAmbiguous matches ({len(ambiguous)} total):")
        for fact, users in ambiguous[:5]:
            print(f"  {fact.fact_id}: {fact.identifier_type}={fact.identifier_value} -> {users}")

    stats = linker.get_link_stats()
    print(f"\nLink Stats: {stats}")

    return bundles, unlinked, ambiguous


if __name__ == "__main__":
    test_evidence_linking()