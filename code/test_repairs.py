import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(__file__).rsplit("\\", 1)[0])

from loaders import load_evidence_files
from evidence_extractor import EvidenceExtractor
from models import DeletionRequest
from policy_engine import PolicyEngine, ViolationType
from state_reconstructor import (
    ReconstructedResource,
    ReplicaType,
    ResourceState,
    StateReconstructionResult,
)
from step_builder import build_step_plan
import main
from llm_provider import create_provider
from request_classifier import classify_request, clear_classification_cache


class FakeResolver:
    def __init__(self, user_id=None):
        self.user_id = user_id

    def find_user_for_request(self, email, evidence_records):
        return self.user_id

    def get_resolved_identity(self, user_id, audit_at):
        return None


def request(case_id="case_test", text="Please delete my account"):
    timestamp = datetime(2026, 9, 1, tzinfo=timezone.utc)
    return DeletionRequest(
        case_id=case_id,
        email="person@example.test",
        requested_at=timestamp,
        reported_status="COMPLETE",
        reported_at=timestamp,
        audit_at=timestamp,
        request_text=text,
    )


class RepairTests(unittest.TestCase):
    def test_auto_provider_requires_configured_llm(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                create_provider("auto")

    def test_classification_cache_avoids_duplicate_provider_calls(self):
        clear_classification_cache()

        class CountingProvider:
            calls = 0
            provider_name = "test"
            model_name = "test-model"

            def complete(self, **kwargs):
                self.calls += 1
                return {
                    "intent": "DELETION",
                    "scope": "FULL_ACCOUNT_AND_DATA",
                    "retention_exceptions": [],
                    "ambiguity": "NONE",
                    "confidence": 0.95,
                    "reasoning": "",
                }

        provider = CountingProvider()
        first = classify_request(request("cache_1"), provider)
        second = classify_request(request("cache_1"), provider)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(first.intent, second.intent)

    def test_every_sql_file_is_inspected_and_heterogeneous_tables_are_extracted(self):
        files = [item for item in load_evidence_files() if item.file_path.endswith(".sql")]
        results = EvidenceExtractor().extract_all(files)
        self.assertEqual(len(results), 24)
        self.assertTrue(all(result.extraction_method == "sql" for result in results))
        self.assertTrue(any(
            result.file_id == "evidence_54"
            and any(record.collection_name == "customer_profiles_failover_replica"
                    for record in result.records)
            for result in results
        ))
        self.assertTrue(any(
            result.file_id == "evidence_57"
            and any(record.collection_name == "search_documents_primary"
                    for record in result.records)
            for result in results
        ))

    @patch("main.classify_requests")
    def test_authorized_request_with_unresolved_identity_is_incomplete(self, classify):
        classify.return_value = {
            "case_test": type("Classification", (), {
                "is_deletion_request": lambda self: True,
            })()
        }
        result = main.process_case(request(), FakeResolver(), [], [], None)
        self.assertEqual(result[1], "INCOMPLETE")

    @patch("main.classify_requests")
    def test_authorized_request_with_no_matching_evidence_is_incomplete(self, classify):
        classify.return_value = {
            "case_test": type("Classification", (), {
                "is_deletion_request": lambda self: True,
            })()
        }
        result = main.process_case(request(), FakeResolver("user_1"), [], [], None)
        self.assertEqual(result[1], "INCOMPLETE")

    @patch("main.classify_requests")
    def test_non_deletion_request_remains_not_applicable(self, classify):
        classify.return_value = {
            "case_test": type("Classification", (), {
                "is_deletion_request": lambda self: False,
            })()
        }
        result = main.process_case(request(text="Please export my data"), FakeResolver(), [], [], None)
        self.assertEqual(result[1], "NOT_APPLICABLE")
        self.assertEqual(result[2], "[]")

    def test_missing_retained_record_has_no_invalid_finding(self):
        timestamp = datetime(2026, 9, 1, tzinfo=timezone.utc)
        resource = ReconstructedResource(
            resource_id="audit_1",
            system_id="security_service",
            collection_name="security_audit_records",
            data_category="SECURITY_AUDIT_LOG",
            replica_type=ReplicaType.PRIMARY,
            state=ResourceState.ABSENT,
            evidence_id="evidence_1",
            captured_at=timestamp,
            record_json={},
        )
        state = StateReconstructionResult("user_1", timestamp, [resource])
        rules_path = Path(__file__).parent.parent / "dataset" / "deletion_rules.csv"
        evaluation = PolicyEngine(str(rules_path)).evaluate(
            "user_1", timestamp, state
        )
        self.assertTrue(any(
            item.violation_type == ViolationType.RECORD_SHOULD_BE_RETAINED
            for item in evaluation.violations
        ))
        plan = build_step_plan("case_test", evaluation, True, state)
        self.assertFalse(any(
            item.operation == "REPORT_REMAINING_RECORD" and item.state == "ABSENT"
            for item in plan.steps
        ))

    def test_complete_plan_cannot_have_empty_verification(self):
        timestamp = datetime(2026, 9, 1, tzinfo=timezone.utc)
        state = StateReconstructionResult("user_1", timestamp, [])
        evaluation = type("CompleteEvaluation", (), {
            "is_complete": True,
            "violations": [],
            "get_deletion_status": lambda self: "COMPLETE",
        })()
        plan = build_step_plan("case_test", evaluation, True, state)
        self.assertEqual(plan.deletion_status, "INCOMPLETE")
        self.assertEqual(plan.steps, [])


if __name__ == "__main__":
    unittest.main()
