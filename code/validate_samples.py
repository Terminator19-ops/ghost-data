"""
Validation script for sample data - runs pipeline on sample_deletion_requests.csv
and compares against sample_output.csv
"""
import sys
import csv
import json
from pathlib import Path
from datetime import datetime

# Add code directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    SAMPLE_DELETION_REQUESTS_CSV,
    SAMPLE_OUTPUT_CSV,
    USER_IDENTITIES_CSV,
    USER_AUDIT_LOG_CSV,
    SYSTEM_ACTIVITY_CSV,
    DELETION_RULES_CSV,
    EVIDENCE_FILES_CSV,
)
from loaders import (
    load_deletion_requests,
    load_user_identities,
    load_user_audit_log,
    load_system_activity,
    load_evidence_files,
    load_all_evidence,
    filter_evidence_by_time,
)
from identity_resolver import build_resolver_with_evidence
from models import DeletionRequest, AuditStep
from request_classifier import classify_requests, ClassificationResult
from evidence_extractor import extract_all_evidence, EvidenceExtractor
from evidence_linker import link_evidence_to_users, EvidenceLinker
from state_reconstructor import StateReconstructor, reconstruct_state
from policy_engine import PolicyEngine, evaluate_policy
from step_builder import StepBuilder, build_step_plan
from llm_provider import get_usage_tracker, create_provider


def load_all_data():
    """Load all required data files."""
    print("Loading all data files...")

    # Load all CSV data using config paths
    sample_requests = load_deletion_requests(str(SAMPLE_DELETION_REQUESTS_CSV))
    identities = load_user_identities(str(USER_IDENTITIES_CSV))
    audit_log = load_user_audit_log(str(USER_AUDIT_LOG_CSV))
    activities = load_system_activity(str(SYSTEM_ACTIVITY_CSV))
    evidence_files = load_evidence_files(str(EVIDENCE_FILES_CSV))

    print(f"  Sample deletion requests: {len(sample_requests)}")
    print(f"  User identities: {len(identities)}")
    print(f"  Audit log entries: {len(audit_log)}")
    print(f"  System activities: {len(activities)}")
    print(f"  Evidence files: {len(evidence_files)}")

    # Extract all evidence
    print("\nExtracting evidence from all files...")
    extractor = EvidenceExtractor()
    extraction_results, all_facts = extract_all_evidence(evidence_files)
    print(f"  Total facts extracted: {len(all_facts)}")

    # Convert to EvidenceRecords for resolver
    all_evidence_records = []
    for er in extraction_results:
        all_evidence_records.extend(er.records)
    print(f"  Total evidence records: {len(all_evidence_records)}")

    return {
        'sample_requests': sample_requests,
        'identities': identities,
        'audit_log': audit_log,
        'activities': activities,
        'evidence_files': evidence_files,
        'extraction_results': extraction_results,
        'all_facts': all_facts,
        'all_evidence_records': all_evidence_records,
    }


def build_resolver(data):
    """Build the identity resolver with all evidence."""
    print("\nBuilding identity resolver with evidence enrichment...")
    resolver = build_resolver_with_evidence(
        data['identities'],
        data['audit_log'],
        data['all_evidence_records']
    )
    print(f"  Resolver built with {len(resolver.current_identities)} current identities")
    print(f"  Historical emails for {len(resolver.historical_emails)} users")
    print(f"  Historical phones for {len(resolver.historical_phones)} users")
    return resolver


def process_case(
    case: DeletionRequest,
    resolver,
    all_facts,
    activities,
    provider,
    classification=None,
) -> tuple:
    """
    Process a single deletion request through the full pipeline.

    Returns:
        (case_id, deletion_status, steps_json)
    """
    # 1. Check if request authorizes deletion
    if classification is None:
        classification = classify_requests([case], provider)[case.case_id]
    is_deletion = classification.is_deletion_request()

    if not is_deletion:
        return case.case_id, "NOT_APPLICABLE", "[]"

    # 2. Find the user for this request
    global all_evidence_records
    user_id = resolver.find_user_for_request(case.email, all_evidence_records)
    if not user_id:
        return case.case_id, "INCOMPLETE", "[]"

    # 3. Get resolved identity at audit_at
    resolved_identity = resolver.get_resolved_identity(user_id, case.audit_at)

    # 4. Link evidence to this user at audit_at
    bundles, _, _ = link_evidence_to_users(all_facts, resolver, case.audit_at)
    evidence_bundle = bundles.get(user_id)

    if not evidence_bundle:
        from evidence_linker import UserEvidenceBundle
        evidence_bundle = UserEvidenceBundle(user_id=user_id, resolved_identity=resolved_identity, links=[])

    # 5. Reconstruct state at audit_at
    state = reconstruct_state(case, resolved_identity, evidence_bundle, activities)

    # 6. Evaluate against deletion policy
    evaluation = evaluate_policy(user_id, case.audit_at, state)

    # 7. Build step plan
    plan = build_step_plan(case.case_id, evaluation, is_deletion, state)

    return plan.case_id, plan.deletion_status, plan.to_json()


def run_sample_pipeline(data, resolver, provider, classification_results):
    """Run the full pipeline on all sample requests."""
    print("\nRunning pipeline on sample requests...")
    print(f"  Processing {len(data['sample_requests'])} cases...")

    all_results = []
    global all_evidence_records
    all_evidence_records = data['all_evidence_records']

    for i, case in enumerate(data['sample_requests']):
        try:
            case_id, deletion_status, steps_json = process_case(
                case,
                resolver,
                data['all_facts'],
                data['activities'],
                provider,
                classification_results.get(case.case_id),
            )
            all_results.append({
                'case_id': case_id,
                'deletion_status': deletion_status,
                'steps_json': steps_json
            })
            if i < 5 or i % 5 == 0:
                print(f"  {case_id}: {deletion_status} ({len(json.loads(steps_json))} steps)")
        except Exception as e:
            print(f"  ERROR processing {case.case_id}: {e}")
            import traceback
            traceback.print_exc()
            # An authorized case that fails during investigation is incomplete.
            all_results.append({
                'case_id': case.case_id,
                'deletion_status': "INCOMPLETE",
                'steps_json': "[]"
            })

    print(f"  Completed: {len(all_results)} results")
    return all_results


def evaluate_against_samples(results):
    """Evaluate our results against sample_output.csv."""
    print("\nEvaluating against sample_output.csv...")

    # Load sample output using config path
    sample_results = {}
    with open(str(SAMPLE_OUTPUT_CSV), 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sample_results[row['case_id']] = row

    # Compare
    matches = 0
    mismatches = 0
    status_matches = 0
    status_mismatches = 0

    for result in results:
        case_id = result['case_id']
        if case_id in sample_results:
            expected = sample_results[case_id]
            status_match = result['deletion_status'] == expected['deletion_status']
            if status_match:
                status_matches += 1
            else:
                status_mismatches += 1

            if (result['deletion_status'] == expected['deletion_status'] and
                result['steps_json'] == expected['steps_json']):
                matches += 1
            else:
                mismatches += 1
                print(f"  MISMATCH {case_id}:")
                print(f"    Expected: {expected['deletion_status']}")
                print(f"    Got:      {result['deletion_status']}")
                # Compare steps
                try:
                    exp_steps = json.loads(expected['steps_json'])
                    got_steps = json.loads(result['steps_json'])
                    if exp_steps != got_steps:
                        print(f"    Steps differ: expected {len(exp_steps)}, got {len(got_steps)}")
                        # Show first difference
                        for j, (e, g) in enumerate(zip(exp_steps, got_steps)):
                            if e != g:
                                print(f"    First diff at step {j+1}:")
                                print(f"      Expected: {e}")
                                print(f"      Got:      {g}")
                                break
                        if len(exp_steps) != len(got_steps):
                            print(f"    Length diff: expected {len(exp_steps)}, got {len(got_steps)}")
                except Exception as e:
                    print(f"    Steps compare error: {e}")

    print(f"\n  Status matches: {status_matches}")
    print(f"  Status mismatches: {status_mismatches}")
    print(f"  Full matches: {matches}")
    print(f"  Full mismatches: {mismatches}")
    total = matches + mismatches
    if total > 0:
        print(f"  Full accuracy: {matches/total*100:.1f}%")
    print(f"  Status accuracy: {status_matches/(status_matches+status_mismatches)*100:.1f}%" if (status_matches+status_mismatches) > 0 else "N/A")

    return {
        'matches': matches,
        'mismatches': mismatches,
        'status_matches': status_matches,
        'status_mismatches': status_mismatches,
    }


def print_usage_report():
    """Print final usage report for evaluation."""
    tracker = get_usage_tracker()
    report = tracker.export_report()

    print("\n" + "=" * 60)
    print("USAGE REPORT")
    print("=" * 60)
    print(f"Total calls: {report['summary']['total_calls']}")
    print(f"Total input tokens: {report['summary']['total_input_tokens']}")
    print(f"Total output tokens: {report['summary']['total_output_tokens']}")
    print(f"Total tokens: {report['summary']['total_tokens']}")
    print(f"Estimated cost: ${report['summary']['estimated_total_cost_usd']:.6f}")

    print("\nBy model:")
    for model, stats in report['by_model'].items():
        print(f"  {model}: {stats['calls']} calls, "
              f"{stats['input_tokens']} in, {stats['output_tokens']} out, "
              f"${stats.get('total_cost_usd', 0):.6f}")


def main():
    """Main entry point for sample validation."""
    print("Ghost Data Still Exists - Sample Validation")
    print("=" * 60)

    try:
        # Phase 1: Load all data
        data = load_all_data()

        # Phase 1b: Build resolver
        resolver = build_resolver(data)

        # Phase 2: Classify all requests
        provider = create_provider("auto")
        classification_results = classify_requests(data['sample_requests'], provider)

        # Phase 3 & 4: Run pipeline on sample data
        results = run_sample_pipeline(
            data,
            resolver,
            provider,
            classification_results,
        )

        # Evaluate against samples
        eval_results = evaluate_against_samples(results)

        # Print usage report
        print_usage_report()

        print("\n" + "=" * 60)
        print("VALIDATION COMPLETE!")
        print("=" * 60)

        return eval_results

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# Global for process_case access
all_evidence_records = []


if __name__ == "__main__":
    main()