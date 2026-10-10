# Task15 Worker Credential & Egress Isolation V1 (#278)

**Status: DRAFT / NOT PROVEN until independently audited. No live Provider authorization.**

## One bounded security property

The #277 merged main \`c388a4decbfb054bff72af104dadf7a395809bd2\` permanently blocked the *named* direct HTTPS helper and the \`live=True\` capture bypass. It did **not** prevent an arbitrary process holding a key from invoking a different HTTP client.

This round does not restore any Provider transport. Instead it runs an untrusted **probe worker** in a separate Docker Linux network namespace (\`--network=none\`), with only the probe code mounted read-only and no Provider credentials forwarded. The host injects a newly generated **synthetic, test-only** sentinel into the Docker *CLI process environment*; the container gets **only its SHA-256 hash**. It must not be able to read the synthetic secret or make outside TCP connections.

## What is enforced at the container boundary

- No container network egress (\`--network=none\`) and no published ports.
- Read-only root filesystem; process runs as UID/GID 65534, all capabilities dropped, no-new-privileges, bounded PIDs/memory.
- Exactly one explicitly reviewed read-only source-file mount, **never** Docker's socket or host workspace.
- No OpenAI credential or custom endpoint passed in environment, command, or mount.
- Real OpenAI HTTPS is **never attempted**; network probes use reserved documentation IP addresses (RFC 5737, RFC 3849).

Host-side \`docker inspect\` is validated **before the worker runs** and archived. The worker reports 14 named negative/positive observations: credential absence, synthetic host-secret absence, Docker socket absence, non-root, capability/privilege confinement, rootfs refusal, no default route, two direct TCP families, \`http.client\`, \`urllib\`, a child-process TCP bypass attempt, and raw-socket denial.

A separate 14-case **host inspector** regression suite covers hostile Docker configuration substitutions (host/bridge network, privileged execution, injected key, mount/device abuse, writable root, root execution, and more).

## Replay and review

Run the stdlib host-inspection tests:

\`\`\`bash
python -m unittest discover -s tests -p test_task15_worker_credential_egress_isolation_v1.py -v
\`\`\`

The dedicated GitHub Actions workflow runs the Docker proof, publishes the raw container inspect metadata, exact runtime image ID and upstream digest, worker stdout, individual evidence JSON and JUnit XML. Each artifact must be downloaded and independently checked against the exact PR HEAD and this code. A successful GitHub Actions check is **not**, by itself, independent certification.

## Strict exclusions

The public Python base image currently uses a **version tag, not an independently approved immutable digest**; the resolved digest is recorded in the proof artifact for review. This is an offline negative test, not a production-isolated execution system. No production broker exists here, and there is no argument that the host, Docker daemon, kernel, image supplier, or an authorized privileged operator cannot bypass the isolation.

A future **separate** proof round must implement a trusted credential-owning broker outside the worker, genuine authenticated one-shot issuance/consumption at the send boundary, budget controls, provider-target allowlisting, operator trust-root enrollment, and provider receipts. Neither historical US$5 nor proposed US$0.25 spending caps are consent to spend. \`DirectOpenAIHTTPSOnce\` and \`capture(live=True)\` remain blocked.
