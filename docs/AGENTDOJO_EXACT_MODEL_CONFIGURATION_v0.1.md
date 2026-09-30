# AgentDojo Exact Model Configuration v0.1

The selected model for the future clean A/B is the immutable OpenAI snapshot `gpt-4.1-mini-2025-04-14`.

This freeze does not call the model and does not execute AgentDojo. It replaces the previously explored zero-cost local route **for future execution only**; historical zero-cost preflight evidence remains unchanged.

Both arms must use the exact same snapshot and sampling configuration. Alias substitution, fallback models, automatic retry, and post-result model selection are prohibited.

The provider budget cap is USD 5.00 with a hard stop. The API key may exist only in an operator environment or GitHub Actions secret and must never be committed or included in evidence.

Execution Gate remains **CLOSED** until the immutable clean-run workflow and exact native scorer invocation are frozen.
