"""
Policy Engine for Ghost Data Still Exists challenge.

Applies deletion rules to reconstructed state to determine violations
and generate remediation plans.
"""
import csv
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from models import DeletionRule
from state_reconstructor import (
    StateReconstructionResult, ReconstructedResource,
    ResourceState, ActiveDataFlow, BackupRestoreRisk, ReplicaType
)
from config import SYSTEM_IDS, DELETION_RULES_CSV


class ViolationType(Enum):
    """Types of policy violations."""
    RECORD_SHOULD_BE_DELETED = "record_should_be_deleted"           # DELETE rule but PRESENT
    RECORD_SHOULD_BE_REDACTED = "record_should_be_redacted"         # REDACT rule but PRESENT with PII
    RECORD_SHOULD_BE_ANONYMIZED = "record_should_be_anonymized"     # ANONYMIZE rule but attributable
    RECORD_SHOULD_BE_RETAINED = "record_should_be_retained"         # RETAIN rule but ABSENT
    ACTIVE_DATA_FLOW = "active_data_flow"                           # Data flow can recreate data
    RESTORE_RISK = "restore_risk"                                   # Backup can restore data
    REPLICA_DRIFT = "replica_drift"                                 # Replica has data primary doesn't


class RemediationAction(Enum):
    """Remediation actions from the challenge spec."""
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"


class VerificationAction(Enum):
    """Verification actions from the challenge spec."""
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


@dataclass
class PolicyViolation:
    """A policy violation found during evaluation."""
    violation_type: ViolationType
    resource: ReconstructedResource
    rule: DeletionRule
    description: str
    evidence_id: str
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW

    # Remediation
    required_action: Optional[RemediationAction] = None
    target_state: Optional[ResourceState] = None

    # Verification
    verification_action: Optional[VerificationAction] = None
    verification_state: Optional[ResourceState] = None


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation for a user."""
    user_id: str
    audit_at: datetime
    violations: List[PolicyViolation] = field(default_factory=list)
    is_complete: bool = False  # True if no violations

    # Computed properties
    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def finding_violations(self) -> List[PolicyViolation]:
        """Violations that become FINDING steps."""
        return [v for v in self.violations if v.violation_type in (
            ViolationType.RECORD_SHOULD_BE_DELETED,
            ViolationType.RECORD_SHOULD_BE_REDACTED,
            ViolationType.RECORD_SHOULD_BE_ANONYMIZED,
            ViolationType.ACTIVE_DATA_FLOW,
            ViolationType.RESTORE_RISK,
            ViolationType.REPLICA_DRIFT,
        )]

    @property
    def remediation_violations(self) -> List[PolicyViolation]:
        """Violations that need REMEDIATION steps."""
        return [v for v in self.violations if v.required_action is not None]

    def get_deletion_status(self) -> str:
        """Determine overall deletion status."""
        if not self.has_violations:
            return "COMPLETE"
        # Check if any violation is about data that shouldn't be deleted (retention)
        has_retention_violation = any(
            v.violation_type == ViolationType.RECORD_SHOULD_BE_RETAINED
            for v in self.violations
        )
        if has_retention_violation:
            return "INCOMPLETE"  # Still incomplete if retained records missing
        return "INCOMPLETE"


class PolicyEngine:
    """
    Evaluates reconstructed state against deletion rules.

    Loads rules from deletion_rules.csv and applies them to each resource.
    Generates violations, remediation plans, and verification steps.
    """

    def __init__(self, rules_path: str = None):
        if rules_path is None:
            rules_path = str(DELETION_RULES_CSV)
        self.rules = self._load_rules(rules_path)
        self.rules_by_category = self._index_rules_by_category()

    def _load_rules(self, path: str) -> List[DeletionRule]:
        """Load deletion rules from CSV."""
        rules = []
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rules.append(DeletionRule(
                    rule_id=row['rule_id'],
                    data_category=row['data_category'],
                    condition=row['condition'],
                    required_action=row['required_action']
                ))
        return rules

    def _index_rules_by_category(self) -> Dict[str, List[DeletionRule]]:
        """Index rules by data_category for fast lookup."""
        index = {}
        for rule in self.rules:
            if rule.data_category not in index:
                index[rule.data_category] = []
            index[rule.data_category].append(rule)
        return index

    def evaluate(
        self,
        user_id: str,
        audit_at: datetime,
        state: StateReconstructionResult
    ) -> PolicyEvaluationResult:
        """
        Evaluate reconstructed state against deletion rules.

        Args:
            user_id: The user's stable ID
            audit_at: The audit cutoff time
            state: Reconstructed state from StateReconstructor

        Returns:
            PolicyEvaluationResult with violations and remediation plan
        """
        result = PolicyEvaluationResult(user_id=user_id, audit_at=audit_at)

        # 1. Evaluate each resource against its category rules
        for resource in state.resources:
            self._evaluate_resource(resource, state, result)

        # 2. Evaluate active data flows
        for flow in state.active_data_flows:
            self._evaluate_data_flow(flow, state, result)

        # 3. Evaluate backup risks
        for risk in state.backup_risks:
            self._evaluate_backup_risk(risk, state, result)

        # 4. Check replica drift
        self._evaluate_replica_drift(state, result)

        # 5. Determine overall completeness
        result.is_complete = not result.has_violations

        return result

    def _evaluate_resource(
        self,
        resource: ReconstructedResource,
        state: StateReconstructionResult,
        result: PolicyEvaluationResult
    ) -> None:
        """Evaluate a single resource against applicable rules."""
        rules = self.rules_by_category.get(resource.data_category, [])
        if not rules:
            return

        for rule in rules:
            violation = self._check_rule(resource, rule, state)
            if violation:
                result.violations.append(violation)

    def _check_rule(
        self,
        resource: ReconstructedResource,
        rule: DeletionRule,
        state: StateReconstructionResult
    ) -> Optional[PolicyViolation]:
        """Check a specific rule against a resource."""
        action = rule.required_action
        condition = rule.condition

        # Evaluate condition
        condition_met = self._evaluate_condition(condition, resource, state)
        if not condition_met:
            return None

        # Check if current state violates required action
        if action == "DELETE":
            if resource.state == ResourceState.PRESENT:
                return PolicyViolation(
                    violation_type=ViolationType.RECORD_SHOULD_BE_DELETED,
                    resource=resource,
                    rule=rule,
                    description=f"{resource.data_category} record {resource.resource_id} should be deleted but is PRESENT",
                    evidence_id=resource.evidence_id,
                    required_action=RemediationAction.DELETE_RECORD,
                    target_state=ResourceState.ABSENT,
                    verification_action=VerificationAction.VERIFY_RECORD_ABSENT,
                    verification_state=ResourceState.ABSENT,
                )
            elif resource.state == ResourceState.RETAINED:
                # Retained when should be deleted - violation
                return PolicyViolation(
                    violation_type=ViolationType.RECORD_SHOULD_BE_DELETED,
                    resource=resource,
                    rule=rule,
                    description=f"{resource.data_category} record {resource.resource_id} should be deleted but is RETAINED",
                    evidence_id=resource.evidence_id,
                    required_action=RemediationAction.DELETE_RECORD,
                    target_state=ResourceState.ABSENT,
                    verification_action=VerificationAction.VERIFY_RECORD_ABSENT,
                    verification_state=ResourceState.ABSENT,
                )

        elif action == "REDACT":
            if resource.state == ResourceState.PRESENT:
                # Check if PII is still present
                if self._has_pii(resource):
                    return PolicyViolation(
                        violation_type=ViolationType.RECORD_SHOULD_BE_REDACTED,
                        resource=resource,
                        rule=rule,
                        description=f"{resource.data_category} record {resource.resource_id} should have PII redacted but PII is PRESENT",
                        evidence_id=resource.evidence_id,
                        required_action=RemediationAction.REDACT_RECORD,
                        target_state=ResourceState.REDACTED,
                        verification_action=VerificationAction.VERIFY_RECORD_REDACTED,
                        verification_state=ResourceState.REDACTED,
                    )
            elif resource.state == ResourceState.ANONYMIZED:
                # Anonymized is acceptable for REDACT (stronger)
                pass

        elif action == "ANONYMIZE":
            if resource.state in (ResourceState.PRESENT, ResourceState.REDACTED):
                # Still attributable to user
                if self._is_attributable(resource):
                    return PolicyViolation(
                        violation_type=ViolationType.RECORD_SHOULD_BE_ANONYMIZED,
                        resource=resource,
                        rule=rule,
                        description=f"{resource.data_category} record {resource.resource_id} should be anonymized but is still attributable",
                        evidence_id=resource.evidence_id,
                        required_action=RemediationAction.ANONYMIZE_RECORD,
                        target_state=ResourceState.ANONYMIZED,
                        verification_action=VerificationAction.VERIFY_RECORD_ANONYMIZED,
                        verification_state=ResourceState.ANONYMIZED,
                    )

        elif action == "RETAIN":
            if resource.state == ResourceState.ABSENT:
                # Record was deleted but should be retained
                return PolicyViolation(
                    violation_type=ViolationType.RECORD_SHOULD_BE_RETAINED,
                    resource=resource,
                    rule=rule,
                    description=f"{resource.data_category} record {resource.resource_id} should be RETAINED but is ABSENT",
                    evidence_id=resource.evidence_id,
                    # Can't remediate - record is gone
                    verification_action=VerificationAction.VERIFY_RECORD_PRESENT,
                    verification_state=ResourceState.PRESENT,
                )

        return None

    def _evaluate_condition(
        self,
        condition: str,
        resource: ReconstructedResource,
        state: StateReconstructionResult
    ) -> bool:
        """Evaluate a rule condition."""
        condition_lower = condition.lower()

        if condition_lower == "always":
            return True

        if "attributable" in condition_lower:
            return self._is_attributable(resource)

        if "contains" in condition_lower and "email" in condition_lower:
            return self._has_email(resource)

        if "shared" in condition_lower and ("customer" in condition_lower or "agent" in condition_lower):
            # SUPPORT_MESSAGE with shared context
            return self._has_shared_context(resource)

        if "belongs only" in condition_lower:
            # SUPPORT_ATTACHMENT belongs only to subject
            return self._attachment_belongs_only_to_subject(resource)

        if "restore access can be blocked" in condition_lower:
            # BACKUP_ARCHIVE - check if any backup risk has can_restore=True
            return any(r.can_restore for r in state.backup_risks)

        if "account is deleted" in condition_lower:
            # ACCOUNT_TOMBSTONE - check if primary account is deleted
            return self._is_account_deleted(resource, state)

        # Default: condition met
        return True

    def _is_attributable(self, resource: ReconstructedResource) -> bool:
        """Check if record is still attributable to a user."""
        rj = resource.record_json

        # Direct identifiers
        if rj.get("user_id") or rj.get("customer_reference") or rj.get("subject_reference"):
            return True
        if rj.get("email") or rj.get("phone") or rj.get("identifier"):
            return True
        if rj.get("email_hash"):
            return True
        if str(rj.get("result", "")).upper() == "IDENTIFIABLE":
            return True

        # Nested document
        doc = rj.get("document", {})
        if isinstance(doc, dict):
            if doc.get("customer_reference") or doc.get("email"):
                return True

        return False

    def _has_pii(self, resource: ReconstructedResource) -> bool:
        """Check if record has PII fields populated."""
        return self._is_attributable(resource)

    def _has_email(self, resource: ReconstructedResource) -> bool:
        """Check if record contains an email."""
        rj = resource.record_json
        if rj.get("email"):
            return True
        doc = rj.get("document", {})
        if isinstance(doc, dict) and doc.get("email"):
            return True
        return False

    def _has_shared_context(self, resource: ReconstructedResource) -> bool:
        """Check if support message has shared context."""
        rj = resource.record_json
        # Check for shared participants
        participants = rj.get("participants", [])
        if isinstance(participants, list) and len(participants) > 1:
            return True
        # Check for order references
        if rj.get("order_id") or rj.get("order_reference"):
            return True
        return False

    def _attachment_belongs_only_to_subject(self, resource: ReconstructedResource) -> bool:
        """Check if attachment belongs only to deletion subject."""
        rj = resource.record_json
        # If attachment has no shared context markers
        return not self._has_shared_context(resource)

    def _is_account_deleted(self, resource: ReconstructedResource, state: StateReconstructionResult) -> bool:
        """Check if primary account is deleted."""
        # Look for account_service primary resource
        primary = state.get_resource("account_service", resource.primary_resource_id or "")
        if primary and primary.state == ResourceState.ABSENT:
            return True
        # Check all account_service resources
        for res in state.resources_by_system.get("account_service", []):
            if res.replica_type == ReplicaType.PRIMARY and res.state == ResourceState.ABSENT:
                return True
        return False

    def _evaluate_data_flow(
        self,
        flow: ActiveDataFlow,
        state: StateReconstructionResult,
        result: PolicyEvaluationResult
    ) -> None:
        """Evaluate an active data flow."""
        if not flow.is_active:
            return

        violation = PolicyViolation(
            violation_type=ViolationType.ACTIVE_DATA_FLOW,
            resource=ReconstructedResource(  # Create minimal resource for flow
                resource_id=flow.data_flow_id,
                system_id=flow.system_id,
                collection_name="connector_configurations",
                data_category="CACHE_ENTRY",
                replica_type=state_reconstructor.ReplicaType.UNKNOWN,
                state=ResourceState.PRESENT,
                evidence_id=flow.evidence_id,
                captured_at=flow.captured_at,
                record_json={}
            ),
            rule=None,
            description=f"Active data flow {flow.data_flow_id} can recreate user data from {flow.source_system} to {flow.target_system}",
            evidence_id=flow.evidence_id,
            required_action=RemediationAction.DISABLE_DATA_FLOW,
            target_state=ResourceState.ABSENT,  # Flow disabled
            verification_action=VerificationAction.VERIFY_DATA_FLOW_DISABLED,
            verification_state=ResourceState.ABSENT,
        )
        result.violations.append(violation)

    def _evaluate_backup_risk(
        self,
        risk: BackupRestoreRisk,
        state: StateReconstructionResult,
        result: PolicyEvaluationResult
    ) -> None:
        """Evaluate a backup restore risk."""
        if not risk.contains_user_data:
            return

        if risk.can_restore and not risk.restore_blocked:
            violation = PolicyViolation(
                violation_type=ViolationType.RESTORE_RISK,
                resource=ReconstructedResource(
                    resource_id=risk.backup_id,
                    system_id=risk.system_id,
                    collection_name="backup_archives",
                    data_category="BACKUP_ARCHIVE",
                    replica_type=state_reconstructor.ReplicaType.UNKNOWN,
                    state=ResourceState.PRESENT,
                    evidence_id=risk.evidence_id,
                    captured_at=risk.captured_at,
                    record_json={}
                ),
                rule=None,
                description=f"Backup {risk.backup_id} contains user data and can restore it",
                evidence_id=risk.evidence_id,
                required_action=RemediationAction.BLOCK_RESTORE,
                target_state=ResourceState.RETAINED,  # Backup retained but restore blocked
                verification_action=VerificationAction.VERIFY_RESTORE_BLOCKED,
                verification_state=ResourceState.RETAINED,
            )
            result.violations.append(violation)

    def _evaluate_replica_drift(
        self,
        state: StateReconstructionResult,
        result: PolicyEvaluationResult
    ) -> None:
        """Check for replica drift violations."""
        # Group by primary
        primary_map = {}
        for res in state.resources:
            if res.replica_type == state_reconstructor.ReplicaType.PRIMARY:
                primary_map[res.resource_id] = res

        for res in state.resources:
            if res.primary_resource_id and res.primary_resource_id in primary_map:
                primary = primary_map[res.primary_resource_id]
                # Drift: replica has data primary doesn't
                if (res.state == ResourceState.PRESENT and
                    primary.state in (ResourceState.ABSENT, ResourceState.REDACTED, ResourceState.ANONYMIZED)):
                    violation = PolicyViolation(
                        violation_type=ViolationType.REPLICA_DRIFT,
                        resource=res,
                        rule=None,
                        description=f"Replica {res.resource_id} has PRESENT data but primary {primary.resource_id} is {primary.state.value}",
                        evidence_id=res.evidence_id,
                        required_action=RemediationAction.DELETE_RECORD,
                        target_state=ResourceState.ABSENT,
                        verification_action=VerificationAction.VERIFY_RECORD_ABSENT,
                        verification_state=ResourceState.ABSENT,
                    )
                    result.violations.append(violation)


# Import here to avoid circular import
import state_reconstructor


def evaluate_policy(
    user_id: str,
    audit_at: datetime,
    state: StateReconstructionResult,
    rules_path: str = None
) -> PolicyEvaluationResult:
    """Convenience function to evaluate policy."""
    if rules_path is None:
        rules_path = str(DELETION_RULES_CSV)
    engine = PolicyEngine(rules_path)
    return engine.evaluate(user_id, audit_at, state)


def test_policy_engine():
    """Test policy engine with sample data."""
    from loaders import (
        load_deletion_requests, load_user_identities, load_user_audit_log,
        load_system_activity, load_evidence_files
    )
    from identity_resolver import build_resolver_with_evidence
    from evidence_extractor import extract_all_evidence
    from evidence_linker import link_evidence_to_users
    from state_reconstructor import reconstruct_state

    # Load sample data
    requests = load_deletion_requests("dataset/sample_deletion_requests.csv")
    identities = load_user_identities()
    audit_log = load_user_audit_log()
    activities = load_system_activity()
    evidence_files = load_evidence_files()[:10]

    # Extract evidence
    extraction_results, facts = extract_all_evidence(evidence_files)
    all_records = []
    for er in extraction_results:
        all_records.extend(er.records)

    # Build resolver
    resolver = build_resolver_with_evidence(identities, audit_log, all_records)

    # Test on first request
    case = requests[0]
    user_id = resolver.find_user_for_request(case.email, all_records)

    if user_id:
        resolved = resolver.get_resolved_identity(user_id, case.audit_at)
        bundles, _, _ = link_evidence_to_users(facts, resolver, case.audit_at)
        bundle = bundles.get(user_id)

        if bundle:
            state = reconstruct_state(case, resolved, bundle, activities)
            result = evaluate_policy(user_id, case.audit_at, state)

            print(f"\nPolicy Evaluation for {case.case_id}:")
            print(f"  User: {user_id}")
            print(f"  Is Complete: {result.is_complete}")
            print(f"  Deletion Status: {result.get_deletion_status()}")
            print(f"  Violations ({len(result.violations)}):")

            for v in result.violations:
                print(f"    {v.violation_type.value}: {v.description}")
                print(f"      Resource: {v.resource.system_id}/{v.resource.resource_id}")
                print(f"      Action: {v.required_action.value if v.required_action else 'N/A'}")
                print(f"      Verify: {v.verification_action.value if v.verification_action else 'N/A'}")


if __name__ == "__main__":
    test_policy_engine()