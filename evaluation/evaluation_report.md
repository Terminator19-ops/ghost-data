# Evaluation Report: Ghost Data Still Exists

## Validation status

The repaired implementation requires a configured real LLM for classification.
The sample and full final runs were intentionally not generated because neither
`ANTHROPIC_API_KEY` nor `OPENAI_API_KEY` is available in the environment.
The previous `output.csv` was preserved and was not presented as a result of
this repair run.

## Tests completed

- Focused repair suite: **7/7 passed**
- All 24 SQL evidence files: covered by the regression test and successfully
  extracted with heterogeneous schemas.
- Authorized requests with unresolved identity or missing evidence: return
  `INCOMPLETE`.
- Non-deletion requests: remain `NOT_APPLICABLE`.
- Missing retained records: do not emit invalid
  `REPORT_REMAINING_RECORD/ABSENT` findings.
- Complete cases without evidence-backed verification: cannot remain
  `COMPLETE`.
- Automatic provider selection: fails explicitly when real credentials are
  missing.

## Sample evaluation

| Metric | Result |
|---|---:|
| Sample cases evaluated | Not run: real LLM credentials unavailable |
| Status matches | Not available |
| Exact output matches | Not available |
| Remaining mismatches | Not measurable without real classification |

The prior mock-based baseline was 20/32 status matches and 0/32 exact matches.
It is not treated as a valid final evaluation because the mock classifier is
reserved for unit tests.

## Full-dataset validation

Not run. The final pipeline refuses to classify requests without configured
real LLM access, so generating 518 final rows would violate the project
requirements.

## Additional repair cases

1. Profile, search, inventory, failover, and replica SQL tables are extracted
   through schema inspection rather than table-name prefixes.
2. Empty evidence is uncertainty, not proof of deletion.
3. Retention violations use only permitted finding and verification operations.
4. Every complete decision requires evidence-backed verification steps.
5. Mock classification is available only through explicit
   `create_provider("mock")` use in tests.
