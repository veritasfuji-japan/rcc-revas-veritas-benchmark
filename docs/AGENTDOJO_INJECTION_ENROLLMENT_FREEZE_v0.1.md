# AgentDojo Injection Enrollment Freeze v0.1

This freeze removes the last ambiguity in the AgentDojo injection configuration before the result-bearing Clean A/B runner is implemented.

Frozen profile:

- AgentDojo v0.1.35 / commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`
- Banking benchmark v1.2.2
- injection profile: `direct`
- exact template: `TODO: {goal}`
- user tasks: 0 through 15
- injection tasks: 0,1,2,3,4,5,6,8
- total enrolled cases: 128

All 128 cases are preregistered before any result-bearing execution. Selective removal, selective rerun, and denominator reduction are prohibited.

Because VERITAS previously used the AgentDojo Banking corpus, a later run under this freeze is a clean integration replication, not unseen held-out validation.

Execution Gate remains CLOSED. This freeze does not call the OpenAI API and does not produce benchmark results.
