# mw-rocksoul-core — Zero-ORM cognitive engine and HTTP daemon.

**Repository:** [`A-L-L-A-H/mw-rocksoul-core`](https://github.com/A-L-L-A-H/mw-rocksoul-core) · **Stack:** TypeScript · Bun

## What it does

Provides deterministic DAG planning, SHA-256 Merkle proof-carrying work, R0–R4 risk policy, and G0–G6 evaluation gates.

## Quick start

```bash
bun install
bun run start
```

## Verify

```bash
bun run check:zero-orm
bun run typecheck
bun test
bun run build
```

## Configuration

- **Port:** 4520
- **Key configuration:** ROCKSOUL_CORE_PORT / PORT

## Notes

Runtime code has zero dependencies and forbids @moonwitness/orm-* imports.
