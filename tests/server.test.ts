import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { sealPcwEnvelope, sha256Hex } from '../src/merkle-pcw.js';
import { createCoreServer } from '../src/server.js';

describe('mw-rocksoul-core HTTP server', () => {
  let server: ReturnType<typeof Bun.serve>;
  let baseUrl: string;

  beforeAll(() => {
    server = createCoreServer({ port: 0, hostname: '127.0.0.1' });
    baseUrl = `http://127.0.0.1:${server.port}`;
  });

  afterAll(() => {
    server.stop(true);
  });

  test('GET /health returns service metadata and endpoint manifest', async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      readonly status: string;
      readonly service: string;
      readonly package: string;
      readonly zeroOrm: boolean;
      readonly endpoints: readonly string[];
    };
    expect(body.status).toBe('ok');
    expect(body.service).toBe('mw-rocksoul-core');
    expect(body.package).toBe('@moonwitness/rocksoul-core');
    expect(body.zeroOrm).toBe(true);
    expect(body.endpoints).toContain('POST /v1/evals/g0-g6');
  });

  test('POST /v1/plans/validate validates DAG waves, cycles, and node ownership', async () => {
    const validRes = await fetch(`${baseUrl}/v1/plans/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        nodes: [
          { id: 'plan', owner: 'coord', ownedPaths: ['docs/plan.md'] },
          { id: 'core', dependencies: ['plan'], owner: 'rs-core', ownedPaths: ['src/dag-engine.ts'] },
          { id: 'tests', dependencies: ['core'], owner: 'rs-test', ownedPaths: ['tests/dag.test.ts'] },
        ],
      }),
    });
    expect(validRes.status).toBe(200);
    const validBody = (await validRes.json()) as {
      readonly valid: boolean;
      readonly waves: readonly (readonly string[])[];
      readonly ownership: { readonly disjoint: boolean };
    };
    expect(validBody.valid).toBe(true);
    expect(validBody.waves).toEqual([['plan'], ['core'], ['tests']]);
    expect(validBody.ownership.disjoint).toBe(true);

    const cyclicRes = await fetch(`${baseUrl}/v1/plans/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        nodes: [
          { id: 'a', dependencies: ['b'] },
          { id: 'b', dependencies: ['a'] },
        ],
      }),
    });
    expect(cyclicRes.status).toBe(200);
    const cyclicBody = (await cyclicRes.json()) as { readonly valid: boolean };
    expect(cyclicBody.valid).toBe(false);
  });

  test('POST /v1/risk/evaluate enforces R0-R4 and local_only egress policy', async () => {
    const r0Res = await fetch(`${baseUrl}/v1/risk/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        principalId: 'rs-cli',
        action: 'repo_read',
        capability: 'repo.read',
        requestedTier: 'R0',
        dataClassification: 'local_only',
        targetZone: 'local',
      }),
    });
    expect(r0Res.status).toBe(200);
    const r0Body = (await r0Res.json()) as { readonly allowed: boolean; readonly decision: string };
    expect(r0Body.allowed).toBe(true);
    expect(r0Body.decision).toBe('allow');

    const egressRes = await fetch(`${baseUrl}/v1/risk/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        principalId: 'rs-cli',
        action: 'repo_read',
        capability: 'repo.read',
        requestedTier: 'R0',
        dataClassification: 'local_only',
        targetZone: 'cloud',
      }),
    });
    expect(egressRes.status).toBe(200);
    const egressBody = (await egressRes.json()) as {
      readonly allowed: boolean;
      readonly reasonCodes: readonly string[];
    };
    expect(egressBody.allowed).toBe(false);
    expect(egressBody.reasonCodes).toContain('LOCAL_ONLY_EGRESS_BLOCKED');
  });

  test('POST /v1/pcw/verify verifies sealed envelopes and rejects tampered envelopes', async () => {
    const content = 'all tests passed';
    const envelope = sealPcwEnvelope({
      schemaVersion: 'pcw/v1',
      envelopeId: 'env-http-1',
      taskId: 'task-http-1',
      producerAgentId: 'worker-1',
      reviewerAgentId: 'verifier-1',
      riskTier: 'R1',
      parentProofHashes: [],
      artifacts: [
        {
          id: 'log-1',
          kind: 'test_log',
          sha256: sha256Hex(content),
          content,
          sizeBytes: Buffer.byteLength(content, 'utf8'),
        },
      ],
      checks: [{ code: 'bun_test', status: 'pass', mandatory: true, exitCode: 0 }],
      producedAt: '2026-11-27T05:00:00.000Z',
    });

    const okRes = await fetch(`${baseUrl}/v1/pcw/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope }),
    });
    expect(okRes.status).toBe(200);
    const okBody = (await okRes.json()) as { readonly valid: boolean; readonly status: string };
    expect(okBody.valid).toBe(true);
    expect(okBody.status).toBe('accepted');

    const badRes = await fetch(`${baseUrl}/v1/pcw/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope: { ...envelope, taskId: 'tampered' } }),
    });
    expect(badRes.status).toBe(200);
    const badBody = (await badRes.json()) as { readonly valid: boolean; readonly status: string };
    expect(badBody.valid).toBe(false);
    expect(badBody.status).toBe('rejected');
  });

  test('POST /v1/swarm/check-overlap reports disjoint and colliding claims', async () => {
    const response = await fetch(`${baseUrl}/v1/swarm/check-overlap`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        claims: [
          { agentId: 'worker-a', writePaths: ['src/a.ts'] },
          { agentId: 'worker-b', writePaths: ['src/a.ts'] },
        ],
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      readonly disjoint: boolean;
      readonly blockingConflictCount: number;
    };
    expect(body.disjoint).toBe(false);
    expect(body.blockingConflictCount).toBe(1);
  });

  test('POST /v1/evals/g0-g6 executes deterministic harness and handles custom runs', async () => {
    const defaultRes = await fetch(`${baseUrl}/v1/evals/g0-g6`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(defaultRes.status).toBe(200);
    const defaultBody = (await defaultRes.json()) as {
      readonly passed: boolean;
      readonly agiClaimed: boolean;
      readonly highestSatisfiedGate: string;
      readonly gates: readonly unknown[];
    };
    expect(defaultBody.passed).toBe(true);
    expect(defaultBody.agiClaimed).toBe(false);
    expect(defaultBody.highestSatisfiedGate).toBe('G6');
    expect(defaultBody.gates.length).toBe(7);

    const failRes = await fetch(`${baseUrl}/v1/evals/g0-g6`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        runs: [
          {
            runId: 'unsafe-1',
            taskFamily: 'coding',
            mode: 'single_agent',
            decomposable: false,
            heldOutTransfer: false,
            faultInjected: false,
            status: 'failed',
            verifiedSuccess: false,
            evidenceComplete: false,
            unauthorizedActionCount: 1,
            retainedFunctionalityPassed: false,
          },
        ],
      }),
    });
    expect(failRes.status).toBe(200);
    const failBody = (await failRes.json()) as {
      readonly passed: boolean;
      readonly highestSatisfiedGate: string | null;
    };
    expect(failBody.passed).toBe(false);
    expect(failBody.highestSatisfiedGate).toBeNull();
  });

  test('handles CORS OPTIONS, 405, 404, and 400 malformed JSON cleanly', async () => {
    const optRes = await fetch(`${baseUrl}/health`, { method: 'OPTIONS' });
    expect(optRes.status).toBe(204);

    const methodRes = await fetch(`${baseUrl}/health`, { method: 'POST' });
    expect(methodRes.status).toBe(405);

    const notFoundRes = await fetch(`${baseUrl}/v1/unknown`);
    expect(notFoundRes.status).toBe(404);

    const badJsonRes = await fetch(`${baseUrl}/v1/plans/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{invalid-json',
    });
    expect(badJsonRes.status).toBe(400);
  });
});
