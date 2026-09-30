# AgentDojo Final Execution Freeze Candidate v0.1

This PR freezes the final runner **interface and refusal boundary**, not a benchmark result.

The exact model remains `gpt-4.1-mini-2025-04-14`; the provider cap remains USD 5. AgentDojo owns utility/security scoring after the execution barrier. Scorer/gold data is forbidden from runtime governance.

The future result-bearing workflow path is reserved now, but its current body intentionally exits with `EXECUTION_GATE_CLOSED`. This prevents accidental benchmark execution before the final runner body, exact scorer invocation, and hashes have been independently audited.

No clean A/B is executed by this PR.
