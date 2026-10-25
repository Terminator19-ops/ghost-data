"""
Request classification for Ghost Data Still Exists challenge.
Classifies deletion requests to determine intent, scope, retention exceptions, and ambiguity.
"""
import json
import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal
from datetime import datetime

from llm_provider import LLMProvider, create_provider, get_usage_tracker
from models import DeletionRequest


# Classification labels matching the challenge
IntentType = Literal["DELETION", "ACCESS", "CORRECTION", "EXPORT", "OPT_OUT", "OTHER", "AMBIGUOUS"]
ScopeType = Literal["FULL_ACCOUNT_AND_DATA", "SPECIFIC_DATA_CATEGORIES", "PROFILE_ONLY", "EXPORTS_ONLY", "SEARCH_INDEX_ONLY", "UNKNOWN"]


@dataclass
class ClassificationResult:
    """Result of request classification."""
    intent: IntentType
    scope: ScopeType
    retention_exceptions: List[str] = field(default_factory=list)
    ambiguity: str = "NONE"  # NONE, LOW, HIGH
    confidence: float = 0.0
    reasoning: str = ""
    raw_response: Dict = field(default_factory=dict)

    def to_deletion_status(self) -> str:
        """Map intent to challenge deletion_status."""
        if self.intent == "DELETION":
            # Status will be determined by evidence analysis later
            return "PENDING_ANALYSIS"
        elif self.intent in ("ACCESS", "CORRECTION", "EXPORT", "OPT_OUT"):
            return "NOT_APPLICABLE"
        else:
            # AMBIGUOUS or OTHER - needs human review, default to NOT_APPLICABLE for safety
            return "NOT_APPLICABLE"

    def is_deletion_request(self) -> bool:
        """Check if this is a valid deletion request."""
        return self.intent == "DELETION"


# System prompt for classification
CLASSIFICATION_SYSTEM_PROMPT = """You are an expert at classifying data deletion requests for a commerce platform.
Your task is to analyze a user's request text and determine:
1. Intent: What action is the user actually requesting?
2. Scope: What data does the request cover?
3. Retention exceptions: Does the user explicitly allow retaining certain data?
4. Ambiguity: Is the request unclear or contradictory?

Output ONLY valid JSON with these exact fields:
{
  "intent": "DELETION|ACCESS|CORRECTION|EXPORT|OPT_OUT|OTHER|AMBIGUOUS",
  "scope": "FULL_ACCOUNT_AND_DATA|SPECIFIC_DATA_CATEGORIES|PROFILE_ONLY|EXPORTS_ONLY|SEARCH_INDEX_ONLY|UNKNOWN",
  "retention_exceptions": ["list of explicitly allowed data to retain"],
  "ambiguity": "NONE|LOW|HIGH",
  "confidence": 0.0-1.0,
  "reasoning": ""
}

Intent definitions:
- DELETION: User wants account closed and personal data deleted, OR user wants to verify/audit/confirm that their account and personal data were deleted (e.g. "I deleted my account, please verify it is gone", "Check if my account and data have been removed", "Please audit the deletion", "Confirm my profile is removed"). All deletion requests and deletion audit/verification follow-up requests are DELETION.
- ACCESS: User wants to see what data is currently held on their active account without wanting deletion (GDPR Article 15)
- CORRECTION: User wants to fix/update inaccurate data on their active account (GDPR Article 16)
- EXPORT: User wants a portable copy of their data without deleting the account (GDPR Article 20)
- OPT_OUT: User wants to stop marketing emails or advertising while keeping their account active
- OTHER: Clear request completely unrelated to privacy or deletion
- AMBIGUOUS: Request is unclear, contradictory, or could mean multiple things

Scope definitions:
- FULL_ACCOUNT_AND_DATA: Complete account closure with all associated data
- SPECIFIC_DATA_CATEGORIES: Only certain types of data mentioned
- PROFILE_ONLY: Just the user profile/account record
- EXPORTS_ONLY: Only exported data files
- SEARCH_INDEX_ONLY: Only search results/index entries
- UNKNOWN: Cannot determine scope

Retention exceptions: Explicit user statements like "keep my order history", "you can keep anonymous stats", etc.
If none mentioned, return empty array.

Ambiguity:
- NONE: Clear, unambiguous request
- LOW: Minor ambiguity but intent is clear
- HIGH: Major ambiguity, cannot determine intent confidently

Confidence: Your confidence in the classification (0.0-1.0)
Reasoning: Always return an empty string. Do not include explanations.

The request may be in any language. Analyze the semantic meaning, not just keywords.
"""


# User prompt template
CLASSIFICATION_USER_PROMPT = """Analyze this deletion request:

Request text: {request_text}

Email: {email}
Requested at: {requested_at}

Output ONLY the compact JSON classification. Do not include explanations."""

_classification_cache: Dict[str, ClassificationResult] = {}


def _classification_cache_key(
    request: DeletionRequest,
    provider: LLMProvider,
) -> str:
    return json.dumps(
        {
            "request_text": request.request_text,
            "email": request.email,
            "requested_at": request.requested_at.isoformat(),
            "provider": provider.provider_name,
            "model": provider.model_name,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def clear_classification_cache() -> None:
    """Clear cached classifications, primarily for isolated tests."""
    _classification_cache.clear()


def classify_request(
    request: DeletionRequest,
    provider: Optional[LLMProvider] = None
) -> ClassificationResult:
    """
    Classify a single deletion request.

    Args:
        request: The deletion request to classify
        provider: LLM provider (creates default if None)

    Returns:
        ClassificationResult with intent, scope, retention_exceptions, ambiguity, confidence
    """
    if provider is None:
        provider = create_provider("auto")

    cache_key = _classification_cache_key(request, provider)
    cached = _classification_cache.get(cache_key)
    if cached is not None:
        return copy.deepcopy(cached)

    user_prompt = CLASSIFICATION_USER_PROMPT.format(
        request_text=request.request_text,
        email=request.email,
        requested_at=request.requested_at.isoformat()
    )

    response = provider.complete(
        prompt=user_prompt,
        system_prompt=CLASSIFICATION_SYSTEM_PROMPT,
        temperature=0.0,
        max_tokens=256,
        response_format={"type": "json_object"},
        case_id=request.case_id,
    )

    # Validate response structure
    required_fields = ["intent", "scope", "retention_exceptions", "ambiguity", "confidence", "reasoning"]
    for field_name in required_fields:
        if field_name not in response:
            raise ValueError(f"Missing required field in classification response: {field_name}")

    # Validate intent
    valid_intents = ["DELETION", "ACCESS", "CORRECTION", "EXPORT", "OPT_OUT", "OTHER", "AMBIGUOUS"]
    if response["intent"] not in valid_intents:
        raise ValueError(f"Invalid intent: {response['intent']}. Must be one of {valid_intents}")

    # Validate scope
    valid_scopes = ["FULL_ACCOUNT_AND_DATA", "SPECIFIC_DATA_CATEGORIES", "PROFILE_ONLY",
                    "EXPORTS_ONLY", "SEARCH_INDEX_ONLY", "UNKNOWN"]
    if response["scope"] not in valid_scopes:
        raise ValueError(f"Invalid scope: {response['scope']}. Must be one of {valid_scopes}")

    # Validate ambiguity
    valid_ambiguity = ["NONE", "LOW", "HIGH"]
    if response["ambiguity"] not in valid_ambiguity:
        raise ValueError(f"Invalid ambiguity: {response['ambiguity']}. Must be one of {valid_ambiguity}")

    # Validate confidence
    confidence = float(response["confidence"])
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}")

    # Validate retention_exceptions is a list
    if not isinstance(response["retention_exceptions"], list):
        raise ValueError("retention_exceptions must be a list")

    result = ClassificationResult(
        intent=response["intent"],
        scope=response["scope"],
        retention_exceptions=response["retention_exceptions"],
        ambiguity=response["ambiguity"],
        confidence=confidence,
        reasoning=response["reasoning"],
        raw_response=response
    )

    _classification_cache[cache_key] = copy.deepcopy(result)
    return result


def classify_requests(
    requests: List[DeletionRequest],
    provider: Optional[LLMProvider] = None
) -> Dict[str, ClassificationResult]:
    """
    Classify multiple deletion requests.

    Args:
        requests: List of deletion requests
        provider: LLM provider (creates default if None)

    Returns:
        Dict mapping case_id to ClassificationResult
    """
    if provider is None:
        provider = create_provider("auto")

    results = {}
    for request in requests:
        result = classify_request(request, provider)
        results[request.case_id] = result

    return results


def test_classification():
    """Test classification on sample requests."""
    from loaders import load_deletion_requests

    # Load sample requests
    sample_requests = load_deletion_requests("dataset/sample_deletion_requests.csv")

    # Use mock provider for testing
    from llm_provider import MockLLMProvider
    mock = MockLLMProvider("test-model")

    # Set expected responses for sample cases
    mock.set_response("case_01", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "Clear request to close account and remove personal details"
    })
    mock.set_response("case_02", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.9,
        "reasoning": "Spanish request to delete account and check remaining data"
    })
    mock.set_response("case_03", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "French request for permanent account deletion"
    })
    mock.set_response("case_04", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": ["anonymous statistics"],
        "ambiguity": "NONE",
        "confidence": 0.9,
        "reasoning": "Request to delete account but keep anonymous statistics"
    })
    mock.set_response("case_05", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "LOW",
        "confidence": 0.85,
        "reasoning": "User believes deletion was confirmed but email still recognized"
    })
    mock.set_response("case_06", {
        "intent": "DELETION",
        "scope": "SEARCH_INDEX_ONLY",
        "retention_exceptions": [],
        "ambiguity": "LOW",
        "confidence": 0.85,
        "reasoning": "Account page gone but search result remains"
    })
    mock.set_response("case_07", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "Clear request to delete account and identity document"
    })
    mock.set_response("case_08", {
        "intent": "DELETION",
        "scope": "EXPORTS_ONLY",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.9,
        "reasoning": "Request to delete export file after account closure"
    })
    mock.set_response("case_09", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "Clear permanent deletion request"
    })
    mock.set_response("case_10", {
        "intent": "DELETION",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "Clear deletion request"
    })

    results = classify_requests(sample_requests[:10], mock)

    print("Classification Results:")
    for case_id, result in results.items():
        status = result.to_deletion_status()
        print(f"  {case_id}: intent={result.intent}, scope={result.scope}, "
              f"retention={result.retention_exceptions}, ambiguity={result.ambiguity}, "
              f"confidence={result.confidence:.2f}, status={status}")

    # Test with non-deletion request
    print("\nTesting non-deletion request classification:")
    non_deletion_request = DeletionRequest(
        case_id="test_01",
        email="test@example.com",
        requested_at=datetime.now(),
        reported_status="NOT_STARTED",
        reported_at=datetime.now(),
        audit_at=datetime.now(),
        request_text="I would like to access all the data you have on me. Please provide a copy."
    )

    mock.set_response("test_01", {
        "intent": "ACCESS",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "GDPR access request, not deletion"
    })

    result = classify_request(non_deletion_request, mock)
    print(f"  test_01: intent={result.intent}, status={result.to_deletion_status()}")
    assert result.to_deletion_status() == "NOT_APPLICABLE"

    # Test opt-out
    opt_out_request = DeletionRequest(
        case_id="test_02",
        email="test@example.com",
        requested_at=datetime.now(),
        reported_status="NOT_STARTED",
        reported_at=datetime.now(),
        audit_at=datetime.now(),
        request_text="Please stop sending me marketing emails but keep my account active."
    )

    mock.set_response("test_02", {
        "intent": "OPT_OUT",
        "scope": "FULL_ACCOUNT_AND_DATA",
        "retention_exceptions": [],
        "ambiguity": "NONE",
        "confidence": 0.95,
        "reasoning": "Marketing opt-out, not deletion"
    })

    result = classify_request(opt_out_request, mock)
    print(f"  test_02: intent={result.intent}, status={result.to_deletion_status()}")
    assert result.to_deletion_status() == "NOT_APPLICABLE"

    print("\nAll classification tests passed!")
    return results


if __name__ == "__main__":
    test_classification()