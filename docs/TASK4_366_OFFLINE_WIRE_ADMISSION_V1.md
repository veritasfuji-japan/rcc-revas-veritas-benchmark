# Task4 #366 — Serialized wire to local one-use attempt (offline)

This adapter binds locally supplied JSON request bytes to the #365
SQLite session/attempt state machine. It checks strict UTF-8, duplicate
JSON keys, expected request keys, frozen model and completion cap, local
byte/token ceilings and same-arm session/ordinal lineage. Invalid wire
consumes a poison attempt and stops that arm.

Tests use synthetic JSON and a synthetic byte-count encoder. This is
**not** the actual OpenAI SDK MockTransport or pinned tiktoken
integration from #325/#326. It is not a Provider billed-token ceiling
or monetary hard cap. The caller supplies the raw bytes and encoder;
neither is independently attested. SQLite is not an externally
protected permit store.

No Provider SDK client, API key, real network sender, real banking
effect, real model response or newly approved spend is introduced.
Passing CI proves only this local adapter behavior. The next step
must integrate with actual #326 captured SDK wire before any live
research run is considered.
