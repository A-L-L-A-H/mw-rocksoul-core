# mw-rocksoul-core (`@moonwitness/rocksoul-core`)

Standalone Zero-ORM cognitive engine and HTTP daemon (TypeScript / Bun, default port `4520`) for the Rocksoul AI fleet.

## Modules

- `src/dag-engine.ts` — Deterministic DAG planner/scheduler: Kahn topological sort, cycle detection, parallel execution waves, critical path calculation, and bounded-concurrency workflow execution.
- `src/merkle-pcw.ts` — Domain-separated SHA-256 Merkle tree root & inclusion proof builder/verifier (`0x00` leaf / `0x01` internal node), cognitive graph diff/merge, and Proof-Carrying Work (`PcwEnvelope`) sealer & verifier.
- `src/risk-policy.ts` — Centralized `R0–R4` Risk Tier policy evaluator, Capability Grant verifier, `DataClassification` (`local_only` / `cloud_eligible`) air-gap guard, single-use human approval token registry, and disjoint multi-agent file ownership overlap detector.
- `src/eval-gates.ts` — Deterministic `G0–G6` capability & safety evaluation harness returning structured gate scores and SHA-256 digest provenance (`agiClaimed: false`).
- `src/server.ts` — Bun HTTP daemon listening on port `4520` (`ROCKSOUL_CORE_PORT` / `PORT`).

## HTTP API (`:4520`)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service health, version, modules, and endpoint manifest |
| `POST` | `/v1/plans/validate` | Validate DAG plan topology, cycles, waves, and optional node ownership |
| `POST` | `/v1/risk/evaluate` | Evaluate R0–R4 risk tier, capability grant, data classification, and approval token |
| `POST` | `/v1/pcw/verify` | Verify sealed `PcwEnvelope` SHA-256 digest, artifacts, Merkle root/proofs, checks, and reviewer independence |
| `POST` | `/v1/swarm/check-overlap` | Detect disjoint multi-agent file ownership conflicts and protected-path claims |
| `POST` | `/v1/evals/g0-g6` | Run deterministic `G0–G6` harness (or score supplied runs/metrics/ablation) |

## Verification & Commands

```bash
bun install
bun run check:zero-orm
bun run typecheck
bun test
bun run build
bun run start
```

## Zero-ORM Invariant

`@moonwitness/rocksoul-core` has zero runtime dependencies and strictly forbids any `@moonwitness/orm-*` imports. Enforce with:

```bash
node scripts/check-zero-orm-imports.mjs
```
