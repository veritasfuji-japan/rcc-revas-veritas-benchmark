# AgentDojo Zero-Cost Model Capability Gate v0.1

This is a **definition-only preflight**. It does not select a model and does not execute AgentDojo.

The exact local model must be supplied later through a localhost OpenAI-compatible endpoint. Qualification must record the exact model/runtime/configuration and prove tool-call behavior, including multi-tool-call preservation, before the model can be frozen.

The gate fails closed. A model that merely answers text is not sufficient. No paid external model fallback is allowed.

Until qualification succeeds, **Execution Gate = CLOSED** and **Clean A/B = NOT EXECUTED**.
