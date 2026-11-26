import { describe, expect, test } from 'bun:test';
import {
  buildArtifactMerkleTree,
  buildMerkleTree,
  canonicalStringify,
  diffCognitiveGraphs,
  emptyMerkleRoot,
  generateMerkleProof,
  mergeCognitiveGraphs,
  sealPcwEnvelope,
  sha256Hex,
  verifyMerkleProof,
  verifyPcwEnvelope,
  type CognitiveNode,
  type PcwArtifactRecord,
  type PcwEnvelopeDraft,
} from '../src/merkle-pcw.js';

function makeArtifact(id: string, content: string): PcwArtifactRecord {
  return {
    id,
    kind: 'test_log',
    sha256: sha256Hex(content),
    content,
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    path: `artifacts/${id}.log`,
  };
}

describe('merkle-pcw', () => {
  test('canonicalStringify is deterministic across key orderings and omits undefined fields', () => {
    const a = canonicalStringify({ z: 1, a: { d: 4, c: 3 }, omitted: undefined });
    const b = canonicalStringify({ a: { c: 3, d: 4 }, z: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":4},"z":1}');
  });

  test('builds Merkle trees for empty, single, even, and odd node counts and verifies all inclusion proofs', () => {
    const emptyTree = buildMerkleTree(new Map());
    expect(emptyTree.rootHash).toBe(emptyMerkleRoot());
    expect(generateMerkleProof(emptyTree, 'missing')).toBeNull();

    for (const count of [1, 2, 3, 4, 5, 7]) {
      const nodes = new Map<string, CognitiveNode>();
      for (let i = count; i >= 1; i -= 1) {
        const id = `node-${String(i).padStart(2, '0')}`;
        nodes.set(id, {
          id,
          kind: 'fact',
          payload: { index: i, label: `item-${i}` },
          lamportClock: i,
          peerId: 'peer-a',
        });
      }

      const tree = buildMerkleTree(nodes);
      expect(tree.orderedIds.length).toBe(count);

      for (const id of tree.orderedIds) {
        const proof = generateMerkleProof(tree, id);
        expect(proof).not.toBeNull();
        expect(verifyMerkleProof(proof!)).toBe(true);

        // Tamper leaf hash -> must fail
        expect(verifyMerkleProof({ ...proof!, leafHash: '0'.repeat(64) })).toBe(false);
        // Tamper root hash -> must fail
        expect(verifyMerkleProof({ ...proof!, rootHash: 'f'.repeat(64) })).toBe(false);
      }
    }
  });

  test('diffs and merges cognitive graph snapshots deterministically by lamport clock', () => {
    const sharedOld: CognitiveNode = {
      id: 'n1',
      kind: 'plan',
      payload: { version: 1 },
      lamportClock: 1,
      peerId: 'peer-a',
    };
    const sharedNew: CognitiveNode = {
      id: 'n1',
      kind: 'plan',
      payload: { version: 2 },
      lamportClock: 2,
      peerId: 'peer-b',
    };
    const onlyRemote: CognitiveNode = {
      id: 'n2',
      kind: 'evidence',
      payload: { ok: true },
      lamportClock: 1,
      peerId: 'peer-b',
    };

    const local = { peerId: 'peer-a', nodes: new Map([[sharedOld.id, sharedOld]]) };
    const remote = {
      peerId: 'peer-b',
      nodes: new Map([
        [sharedNew.id, sharedNew],
        [onlyRemote.id, onlyRemote],
      ]),
    };

    const delta = diffCognitiveGraphs(remote, local);
    expect(delta.missingInTarget.map((n) => n.id)).toEqual(['n2']);
    expect(delta.newerInSource.map((n) => n.id)).toEqual(['n1']);
    expect(delta.identicalCount).toBe(0);

    const merged = mergeCognitiveGraphs(local, remote);
    expect(merged.conflictCount).toBe(1);
    expect(merged.appliedNodeIds).toEqual(['n1', 'n2']);
    expect(merged.merged.nodes.get('n1')?.lamportClock).toBe(2);
    expect(merged.rootHash).toHaveLength(64);
  });

  test('seals and verifies valid PcwEnvelope with Merkle proofs and parent proof hashes', () => {
    const parentHash = sha256Hex('predecessor-envelope-1');
    const artA = makeArtifact('art-a', 'bun test: 10 passed');
    const artB = makeArtifact('art-b', 'tsc --noEmit: 0 errors');

    const draft: PcwEnvelopeDraft = {
      schemaVersion: 'pcw/v1',
      envelopeId: 'pcw-001',
      taskId: 'task-dag-1',
      producerAgentId: 'rs-worker-1',
      reviewerAgentId: 'rs-verifier-1',
      riskTier: 'R2',
      parentProofHashes: [parentHash],
      artifacts: [artB, artA],
      checks: [
        { code: 'unit_tests', command: 'bun test', status: 'pass', mandatory: true, exitCode: 0 },
        {
          code: 'docker_build',
          status: 'skipped',
          mandatory: false,
          reason: 'Unit-only verification stage',
        },
      ],
      changedFiles: ['src/dag-engine.ts'],
      producedAt: '2026-11-27T05:00:00.000Z',
      expiresAt: '2026-11-28T05:00:00.000Z',
    };

    const sealed = sealPcwEnvelope(draft);
    const artifactTree = buildArtifactMerkleTree(sealed.artifacts);
    const proofA = generateMerkleProof(artifactTree, 'art-a');
    expect(proofA).not.toBeNull();

    // JSON round-trip preserves exact SHA-256 verification
    const deserialized = JSON.parse(JSON.stringify(sealed)) as typeof sealed;
    const verification = verifyPcwEnvelope(deserialized, {
      expectedParentHashes: [parentHash],
      expectedMerkleRoot: sealed.merkleRoot,
      merkleProofs: [proofA!],
      nowMs: Date.parse('2026-11-27T06:00:00.000Z'),
    });

    expect(verification.valid).toBe(true);
    expect(verification.status).toBe('accepted');
    expect(verification.issues).toEqual([]);
    expect(verification.verifiedArtifactDigests['art-a']).toBe(artA.sha256);
    expect(verification.verifiedArtifactDigests['art-b']).toBe(artB.sha256);
  });

  test('rejects tampered envelopes, digest mismatches, self-approval, missing parents, failed checks, and expiry', () => {
    const parentHash = sha256Hex('predecessor-parent');
    const art = makeArtifact('art-1', 'valid output');
    const sealed = sealPcwEnvelope({
      schemaVersion: 'pcw/v1',
      envelopeId: 'pcw-002',
      taskId: 'task-2',
      producerAgentId: 'agent-1',
      reviewerAgentId: 'agent-2',
      riskTier: 'R2',
      parentProofHashes: [],
      artifacts: [art],
      checks: [{ code: 'tests', status: 'pass', mandatory: true }],
      producedAt: '2026-11-27T05:00:00.000Z',
      expiresAt: '2026-11-27T06:00:00.000Z',
    });

    // 1. Tampered taskId
    const tampered = verifyPcwEnvelope(
      { ...sealed, taskId: 'task-tampered' },
      { nowMs: Date.parse('2026-11-27T05:30:00.000Z') }
    );
    expect(tampered.valid).toBe(false);
    expect(tampered.issues.some((issue) => issue.code === 'ENVELOPE_TAMPERED')).toBe(true);

    // 2. Artifact content mismatch
    const badContent = verifyPcwEnvelope(
      {
        ...sealed,
        artifacts: [{ ...art, content: 'mutated content' }],
      },
      { nowMs: Date.parse('2026-11-27T05:30:00.000Z') }
    );
    expect(badContent.issues.some((issue) => issue.code === 'ARTIFACT_DIGEST_MISMATCH')).toBe(true);

    // 3. Self-approval + missing parent + failed mandatory check + expired
    const badPolicyEnvelope = sealPcwEnvelope({
      schemaVersion: 'pcw/v1',
      envelopeId: 'pcw-003',
      taskId: 'task-3',
      producerAgentId: 'agent-self',
      reviewerAgentId: 'agent-self',
      riskTier: 'R2',
      parentProofHashes: [],
      artifacts: [art],
      checks: [
        { code: 'tests', status: 'fail', mandatory: true },
        { code: 'lint', status: 'skipped', mandatory: false },
      ],
      producedAt: '2026-11-27T05:00:00.000Z',
      expiresAt: '2026-11-27T05:10:00.000Z',
    });

    const badPolicyResult = verifyPcwEnvelope(badPolicyEnvelope, {
      expectedParentHashes: [parentHash],
      nowMs: Date.parse('2026-11-27T05:20:00.000Z'),
    });
    expect(badPolicyResult.valid).toBe(false);
    const codes = badPolicyResult.issues.map((i) => i.code);
    expect(codes).toContain('SELF_APPROVAL_REJECTED');
    expect(codes).toContain('MISSING_PARENT_PROOF');
    expect(codes).toContain('MANDATORY_CHECK_FAILED');
    expect(codes).toContain('MISSING_SKIP_REASON');
    expect(codes).toContain('ENVELOPE_EXPIRED');
  });
});
