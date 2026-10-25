"""
Step Builder for Ghost Data Still Exists challenge.

Converts policy violations into the required audit steps format:
- FINDING phase: Report violations found
- REMEDIATION phase: Actions to fix violations
- VERIFICATION phase: Checks to verify remediation
"""
import json
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional

from models import AuditStep
from policy_engine import (
    PolicyEvaluationResult, PolicyViolation,
    ViolationType, RemediationAction, VerificationAction
)
from state_reconstructor import ResourceState, StateReconstructionResult


# ── Canonical sorting constants (problem_statement.md §6.3 / table ordering) ──
_PHASE_ORDER: Dict[str, int] = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

_OP_ORDER: Dict[str, Dict[str, int]] = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    },
}


def _canonical_sort_key(step: AuditStep):
    """Return the spec-mandated sort key: phase, operation-in-table, system_id, resource_id."""
    phase = step.phase
    return (
        _PHASE_ORDER.get(phase, 99),
        _OP_ORDER.get(phase, {}).get(step.operation, 99),
        step.system_id or "",
        step.resource_id or "",
    )


def _renumber(steps: List[AuditStep]) -> List[AuditStep]:
    """Sort steps by canonical key and renumber step_no from 1."""
    steps.sort(key=_canonical_sort_key)
    for i, step in enumerate(steps, 1):
        step.step_no = i
    return steps


@dataclass
class StepPlan:
    """Complete step plan for a case."""
    case_id: str
    deletion_status: str  # COMPLETE, INCOMPLETE, NOT_APPLICABLE
    steps: List[AuditStep]

    def to_json(self) -> str:
        """Serialize steps to JSON string for output.csv."""
        return json.dumps([step.to_dict() for step in self.steps], separators=(',', ':'))


class StepBuilder:
    """
    Builds the ordered step plan from policy evaluation results.

    Phase order: FINDING -> REMEDIATION -> VERIFICATION
    Step numbering: consecutive from 1, after canonical sort.
    """

    def __init__(self):
        self.step_counter = 0

    def build_plan(
        self,
        case_id: str,
        evaluation: PolicyEvaluationResult,
        is_deletion_request: bool,
        state: StateReconstructionResult = None
    ) -> StepPlan:
        """
        Build complete step plan for a case.

        Args:
            case_id: The case identifier
            evaluation: Policy evaluation result
            is_deletion_request: Whether the request authorizes deletion
            state: Reconstructed state (required for COMPLETE cases)

        Returns:
            StepPlan with deletion_status and ordered steps
        """
        self.step_counter = 0
        steps = []

        if not is_deletion_request:
            # NOT_APPLICABLE - no steps needed
            return StepPlan(
                case_id=case_id,
                deletion_status="NOT_APPLICABLE",
                steps=[]
            )

        if evaluation.is_complete:
            # COMPLETE - verification steps proving compliant state
            deletion_status = "COMPLETE"
            steps = self._build_complete_verification_steps(state, evaluation) if state else []
            if not steps:
                # A complete decision must be supported by at least one
                # evidence-backed verification check.  Without evidence we
                # cannot prove completion, so downgrade to INCOMPLETE.
                deletion_status = "INCOMPLETE"
                steps = self._build_incomplete_plan(evaluation, state)
        else:
            # INCOMPLETE - findings, remediation, verification
            deletion_status = evaluation.get_deletion_status()
            steps = self._build_incomplete_plan(evaluation, state)

        # INCOMPLETE must never have an empty steps list per the spec
        if deletion_status == "INCOMPLETE" and not steps:
            steps = [AuditStep(
                step_no=1,
                phase="FINDING",
                system_id="account_service",
                resource_id="unknown",
                operation="REPORT_REMAINING_RECORD",
                state="PRESENT",
                evidence_id="",
            )]

        # Apply canonical sort + renumber to ALL non-NOT_APPLICABLE cases
        if steps:
            _renumber(steps)

        return StepPlan(
            case_id=case_id,
            deletion_status=deletion_status,
            steps=steps
        )

    def _build_incomplete_plan(
        self,
        evaluation: PolicyEvaluationResult,
        state: Optional[StateReconstructionResult] = None
    ) -> List[AuditStep]:
        """Build plan for INCOMPLETE case: FINDING -> REMEDIATION -> VERIFICATION.

        Verification covers both remediated resources AND already-compliant
        resources (e.g. primary account absent, retained audit logs present).
        """
        steps: List[AuditStep] = []
        seen_keys: set = set()  # (system_id, resource_id, phase, operation)

        def _add(step: Optional[AuditStep]) -> None:
            if step is None:
                return
            key = (step.system_id, step.resource_id, step.phase, step.operation)
            if key not in seen_keys:
                seen_keys.add(key)
                steps.append(step)

        # ── FINDING steps ────────────────────────────────────────────────────
        for violation in evaluation.finding_violations:
            _add(self._create_finding_step(violation))

        # ── REMEDIATION steps ────────────────────────────────────────────────
        for violation in evaluation.remediation_violations:
            _add(self._create_remediation_step(violation))

        # ── VERIFICATION steps for remediated resources ──────────────────────
        for violation in evaluation.violations:
            _add(self._create_verification_step(violation))

        # ── VERIFICATION steps for already-compliant resources ──────────────
        if state:
            # 1. Primary account absent check
            for res in state.resources_by_system.get("account_service", []):
                if res.state == ResourceState.ABSENT:
                    _add(AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=res.system_id,
                        resource_id=res.resource_id,
                        operation="VERIFY_RECORD_ABSENT",
                        state="ABSENT",
                        evidence_id=""
                    ))

            # 2. Retained audit logs / legal holds present check
            retained_categories = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}
            for res in state.resources:
                if res.data_category in retained_categories and res.state in (ResourceState.PRESENT, ResourceState.RETAINED):
                    _add(AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=res.system_id,
                        resource_id=res.resource_id,
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id=""
                    ))

            # 3. Tombstone redacted check (if tombstone is compliant)
            for res in state.resources:
                if res.data_category == "ACCOUNT_TOMBSTONE" and res.state == ResourceState.REDACTED:
                    _add(AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=res.system_id,
                        resource_id=res.resource_id,
                        operation="VERIFY_RECORD_REDACTED",
                        state="REDACTED",
                        evidence_id=""
                    ))

        return steps

    def _build_complete_verification_steps(
        self,
        state: StateReconstructionResult,
        evaluation: PolicyEvaluationResult
    ) -> List[AuditStep]:
        """Build evidence-backed verification steps for every compliant resource."""
        if not state:
            return []

        steps: List[AuditStep] = []
        verified_keys = set()
        operation_by_state = {
            ResourceState.ABSENT: ("VERIFY_RECORD_ABSENT", "ABSENT"),
            ResourceState.REDACTED: ("VERIFY_RECORD_REDACTED", "REDACTED"),
            ResourceState.ANONYMIZED: ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        }
        retained_categories = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

        for resource in state.resources:
            operation_state = operation_by_state.get(resource.state)
            if resource.state in (ResourceState.PRESENT, ResourceState.RETAINED):
                if resource.data_category in retained_categories:
                    operation_state = ("VERIFY_RECORD_PRESENT", "PRESENT")
            if not operation_state or not resource.evidence_id:
                continue
            operation, state_value = operation_state
            key = (resource.system_id, resource.resource_id, operation)
            if key in verified_keys:
                continue
            verified_keys.add(key)
            steps.append(AuditStep(
                step_no=0,  # renumbered later by _renumber()
                phase="VERIFICATION",
                system_id=resource.system_id,
                resource_id=resource.resource_id,
                operation=operation,
                state=state_value,
                evidence_id=resource.evidence_id,
            ))

        for flow in state.active_data_flows:
            if not flow.is_active and flow.evidence_id:
                steps.append(AuditStep(
                    step_no=0,
                    phase="VERIFICATION",
                    system_id=flow.system_id,
                    resource_id=flow.data_flow_id,
                    operation="VERIFY_DATA_FLOW_DISABLED",
                    state="DISABLED",
                    evidence_id=flow.evidence_id,
                ))

        for risk in state.backup_risks:
            if risk.restore_blocked and risk.evidence_id:
                steps.append(AuditStep(
                    step_no=0,
                    phase="VERIFICATION",
                    system_id=risk.system_id,
                    resource_id=risk.backup_id,
                    operation="VERIFY_RESTORE_BLOCKED",
                    state="BLOCKED",
                    evidence_id=risk.evidence_id,
                ))

        return steps

    def _get_verification_priority(self, violation: PolicyViolation) -> int:
        """Get priority for verification ordering (kept for compatibility)."""
        if violation.resource.system_id == "account_service":
            if violation.resource.replica_type.name == "PRIMARY":
                return 1
        if violation.resource.system_id == "security_service":
            return 2
        if violation.resource.system_id in ("search_service", "analytics_platform", "support_platform"):
            return 3
        if violation.verification_action in (
            VerificationAction.VERIFY_DATA_FLOW_DISABLED,
            VerificationAction.VERIFY_RESTORE_BLOCKED
        ):
            return 4
        return 5

    def _create_finding_step(self, violation: PolicyViolation) -> Optional[AuditStep]:
        """Create a FINDING step from a violation."""
        self.step_counter += 1

        op_map = {
            ViolationType.RECORD_SHOULD_BE_DELETED: "REPORT_REMAINING_RECORD",
            ViolationType.RECORD_SHOULD_BE_REDACTED: "REPORT_EXPOSED_PII",
            ViolationType.RECORD_SHOULD_BE_ANONYMIZED: "REPORT_EXPOSED_PII",
            ViolationType.ACTIVE_DATA_FLOW: "REPORT_ACTIVE_DATA_FLOW",
            ViolationType.RESTORE_RISK: "REPORT_RESTORE_RISK",
            ViolationType.REPLICA_DRIFT: "REPORT_REMAINING_RECORD",
        }

        state_map = {
            ViolationType.RECORD_SHOULD_BE_DELETED: "PRESENT",
            ViolationType.RECORD_SHOULD_BE_REDACTED: "PRESENT",
            ViolationType.RECORD_SHOULD_BE_ANONYMIZED: "PRESENT",
            ViolationType.ACTIVE_DATA_FLOW: "ACTIVE",
            ViolationType.RESTORE_RISK: "ACTIVE",
            ViolationType.REPLICA_DRIFT: "PRESENT",
        }

        operation = op_map.get(violation.violation_type)
        state = state_map.get(violation.violation_type)

        if not operation or not state:
            return None

        return AuditStep(
            step_no=self.step_counter,
            phase="FINDING",
            system_id=violation.resource.system_id,
            resource_id=violation.resource.resource_id,
            operation=operation,
            state=state,
            evidence_id=violation.evidence_id
        )

    def _create_remediation_step(self, violation: PolicyViolation) -> Optional[AuditStep]:
        """Create a REMEDIATION step from a violation."""
        self.step_counter += 1

        if not violation.required_action:
            return None

        action_map = {
            RemediationAction.DELETE_RECORD: ("DELETE_RECORD", "ABSENT"),
            RemediationAction.REDACT_RECORD: ("REDACT_RECORD", "REDACTED"),
            RemediationAction.ANONYMIZE_RECORD: ("ANONYMIZE_RECORD", "ANONYMIZED"),
            RemediationAction.DISABLE_DATA_FLOW: ("DISABLE_DATA_FLOW", "DISABLED"),
            RemediationAction.BLOCK_RESTORE: ("BLOCK_RESTORE", "BLOCKED"),
        }

        operation, state = action_map.get(violation.required_action, (None, None))
        if not operation:
            return None

        return AuditStep(
            step_no=self.step_counter,
            phase="REMEDIATION",
            system_id=violation.resource.system_id,
            resource_id=violation.resource.resource_id,
            operation=operation,
            state=state,
            evidence_id=""  # Future action, no evidence yet
        )

    def _create_verification_step(
        self,
        violation: PolicyViolation,
        for_complete: bool = False
    ) -> Optional[AuditStep]:
        """Create a VERIFICATION step from a violation."""
        self.step_counter += 1

        if not violation.verification_action:
            return None

        verify_state_map = {
            VerificationAction.VERIFY_RECORD_ABSENT: "ABSENT",
            VerificationAction.VERIFY_RECORD_PRESENT: "PRESENT",
            VerificationAction.VERIFY_RECORD_REDACTED: "REDACTED",
            VerificationAction.VERIFY_RECORD_ANONYMIZED: "ANONYMIZED",
            VerificationAction.VERIFY_DATA_FLOW_DISABLED: "DISABLED",
            VerificationAction.VERIFY_RESTORE_BLOCKED: "BLOCKED",
        }

        state = verify_state_map.get(violation.verification_action)
        if not state:
            return None

        evidence_id = violation.evidence_id if for_complete else ""

        return AuditStep(
            step_no=self.step_counter,
            phase="VERIFICATION",
            system_id=violation.resource.system_id,
            resource_id=violation.resource.resource_id,
            operation=violation.verification_action.value,
            state=state,
            evidence_id=evidence_id
        )


def build_step_plan(
    case_id: str,
    evaluation: PolicyEvaluationResult,
    is_deletion_request: bool,
    state: StateReconstructionResult = None
) -> StepPlan:
    """Convenience function to build step plan."""
    builder = StepBuilder()
    return builder.build_plan(case_id, evaluation, is_deletion_request, state)


def test_step_builder():
    """Test step builder with sample output."""
    # This would be tested via main.py integration
    pass


if __name__ == "__main__":
    test_step_builder()

    test_step_builder()