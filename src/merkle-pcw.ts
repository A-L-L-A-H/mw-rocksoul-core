import { createHash } from 'node:crypto';
import type { DagRiskTier } from './dag-engine.js';

export const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/u;
export const MERKLE_LEAF_DOMAIN_PREFIX = 0x00;
export const MERKLE_NODE_DOMAIN_PREFIX = 0x01;

export interface CognitiveNode {
  readonly id: string;
  readonly kind: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly lamportClock: number;
  readonly peerId: string;
  readonly deleted?: boolean;
}

export interface CognitiveGraphSnapshot {
  readonly peerId: string;
  readonly nodes: ReadonlyMap<string, CognitiveNode>;
}

export interface MerkleProofStep {
  readonly position: 'left' | 'right';
  readonly hash: string;
}

export interface MerkleProof {
  readonly leafId: string;
  readonly leafHash: string;
  readonly rootHash: string;
  readonly steps: readonly MerkleProofStep[];
}

export interface MerkleTree {
  readonly rootHash: string;
  readonly leafHashes: ReadonlyMap<string, string>;
  readonly levels: readonly (readonly string[])[];
  readonly orderedIds: readonly string[];
}

export interface CognitiveGraphDelta {
  readonly sourcePeerId: string;
  readonly targetPeerId: string;
  readonly missingInTarget: readonly CognitiveNode[];
  readonly newerInSource: readonly CognitiveNode[];
  readonly identicalCount: number;
}

export interface MergeResult {
  readonly merged: CognitiveGraphSnapshot;
  readonly appliedNodeIds: readonly string[];
  readonly conflictCount: number;
  readonly rootHash: string;
}

export type PcwArtifactKind =
  | 'diff'
  | 'test_log'
  | 'report'
  | 'transcript'
  | 'tool_output'
  | 'evidence_bundle'
  | 'eval_result';

export interface PcwArtifactRecord {
  readonly id: string;
  readonly kind: PcwArtifactKind;
  readonly sha256: string;
  readonly content?: string;
  readonly sizeBytes?: number;
  readonly path?: string;
}

export type PcwCheckStatus = 'pass' | 'fail' | 'skipped' | 'not_applicable' | 'not_run';

export interface PcwCheckEvidence {
  readonly code: string;
  readonly command?: string;
  readonly status: PcwCheckStatus;
  readonly mandatory?: boolean;
  readonly exitCode?: number;
  readonly reason?: string;
}

export interface PcwEnvelopeDraft {
  readonly schemaVersion: 'pcw/v1';
  readonly envelopeId: string;
  readonly taskId: string;
  readonly producerAgentId: string;
  readonly reviewerAgentId?: string;
  readonly riskTier: DagRiskTier;
  readonly parentProofHashes: readonly string[];
  readonly artifacts: readonly PcwArtifactRecord[];
  readonly checks: readonly PcwCheckEvidence[];
  readonly changedFiles?: readonly string[];
  readonly producedAt: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PcwEnvelope extends PcwEnvelopeDraft {
  readonly merkleRoot: string;
  readonly envelopeSha256: string;
}

export type PcwVerificationErrorCode =
  | 'INVALID_SCHEMA_VERSION'
  | 'INVALID_ENVELOPE_SHA256'
  | 'ENVELOPE_TAMPERED'
  | 'INVALID_MERKLE_ROOT'
  | 'MERKLE_ROOT_MISMATCH'
  | 'INVALID_MERKLE_PROOF'
  | 'EMPTY_ARTIFACTS'
  | 'DUPLICATE_ARTIFACT_ID'
  | 'INVALID_ARTIFACT_SHA256'
  | 'ARTIFACT_DIGEST_MISMATCH'
  | 'ARTIFACT_SIZE_MISMATCH'
  | 'INVALID_PARENT_PROOF_HASH'
  | 'MISSING_PARENT_PROOF'
  | 'MANDATORY_CHECK_FAILED'
  | 'CHECK_FAILED'
  | 'MISSING_SKIP_REASON'
  | 'SELF_APPROVAL_REJECTED'
  | 'INDEPENDENT_REVIEWER_REQUIRED'
  | 'ENVELOPE_EXPIRED';

export interface PcwVerificationIssue {
  readonly code: PcwVerificationErrorCode;
  readonly message: string;
  readonly artifactId?: string;
  readonly checkCode?: string;
}

export interface PcwVerificationOptions {
  readonly expectedParentHashes?: readonly string[];
  readonly expectedMerkleRoot?: string;
  readonly merkleProofs?: readonly MerkleProof[];
  readonly requireIndependentReviewer?: boolean;
  readonly requireAtLeastOneArtifact?: boolean;
  readonly nowMs?: number;
}

export interface PcwVerificationResult {
  readonly valid: boolean;
  readonly status: 'accepted' | 'rejected';
  readonly envelopeId: string;
  readonly taskId: string;
  readonly computedMerkleRoot: string;
  readonly computedEnvelopeSha256: string;
  readonly artifactCount: number;
  readonly verifiedArtifactDigests: Readonly<Record<string, string>>;
  readonly issues: readonly PcwVerificationIssue[];
  readonly verifiedAt: string;
  readonly reportSha256: string;
}

function compareAscii(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

export function isValidSha256Hex(value: string): boolean {
  return SHA256_HEX_REGEX.test(value);
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

export function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalStringify(entry)).join(',')}]`;
  }
  const record = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort(compareAscii);
  const entries = keys.map(
    (key) => `${JSON.stringify(key)}:${canonicalStringify(record[key])}`
  );
  return `{${entries.join(',')}}`;
}

export function hashMerkleLeafBytes(payload: string): string {
  const input = Buffer.concat([
    Buffer.from([MERKLE_LEAF_DOMAIN_PREFIX]),
    Buffer.from(payload, 'utf8'),
  ]);
  return createHash('sha256').update(input).digest('hex');
}

export function hashMerkleNode(leftHash: string, rightHash: string): string {
  if (!isValidSha256Hex(leftHash) || !isValidSha256Hex(rightHash)) {
    throw new Error('hashMerkleNode requires 64-character lowercase hexadecimal SHA-256 digests.');
  }
  const input = Buffer.concat([
    Buffer.from([MERKLE_NODE_DOMAIN_PREFIX]),
    Buffer.from(leftHash, 'hex'),
    Buffer.from(rightHash, 'hex'),
  ]);
  return createHash('sha256').update(input).digest('hex');
}

export function emptyMerkleRoot(): string {
  return sha256Hex('EMPTY_ROCKSOUL_MERKLE_TREE');
}

export function hashCognitiveNode(node: CognitiveNode): string {
  return hashMerkleLeafBytes(
    canonicalStringify({
      id: node.id,
      kind: node.kind,
      payload: node.payload,
      lamportClock: node.lamportClock,
      peerId: node.peerId,
      deleted: Boolean(node.deleted),
    })
  );
}

export function buildMerkleTreeFromEntries(
  entries: ReadonlyMap<string, string>
): MerkleTree {
  const orderedIds = Array.from(entries.keys()).sort(compareAscii);
  const leafHashes = new Map<string, string>();

  if (orderedIds.length === 0) {
    const emptyRoot = emptyMerkleRoot();
    return {
      rootHash: emptyRoot,
      leafHashes,
      levels: [[emptyRoot]],
      orderedIds: [],
    };
  }

  const leaves: string[] = [];
  for (const id of orderedIds) {
    const hash = entries.get(id);
    if (hash !== undefined) {
      if (!isValidSha256Hex(hash)) {
        throw new Error(`Invalid leaf hash for entry "${id}": must be 64-char hex SHA-256.`);
      }
      leafHashes.set(id, hash);
      leaves.push(hash);
    }
  }

  const levels: string[][] = [leaves];
  let currentLevel = leaves;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = currentLevel[i + 1] ?? left;
      if (left !== undefined && right !== undefined) {
        nextLevel.push(hashMerkleNode(left, right));
      }
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    rootHash: currentLevel[0] ?? emptyMerkleRoot(),
    leafHashes,
    levels,
    orderedIds,
  };
}

export function buildMerkleTree(nodes: ReadonlyMap<string, CognitiveNode>): MerkleTree {
  const hashes = new Map<string, string>();
  for (const [id, node] of nodes.entries()) {
    hashes.set(id, hashCognitiveNode(node));
  }
  return buildMerkleTreeFromEntries(hashes);
}

export function generateMerkleProof(tree: MerkleTree, leafId: string): MerkleProof | null {
  const index = tree.orderedIds.indexOf(leafId);
  if (index === -1) {
    return null;
  }

  const leafHash = tree.leafHashes.get(leafId);
  if (!leafHash) {
    return null;
  }

  const steps: MerkleProofStep[] = [];
  let currentIndex = index;

  for (let levelIndex = 0; levelIndex < tree.levels.length - 1; levelIndex += 1) {
    const level = tree.levels[levelIndex];
    if (!level) {
      break;
    }
    const isRightNode = currentIndex % 2 === 1;
    const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
    const siblingHash =
      siblingIndex < level.length ? level[siblingIndex] : level[currentIndex];
    if (siblingHash === undefined) {
      break;
    }

    steps.push({
      position: isRightNode ? 'left' : 'right',
      hash: siblingHash,
    });

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leafId,
    leafHash,
    rootHash: tree.rootHash,
    steps,
  };
}

export function verifyMerkleProof(proof: MerkleProof): boolean {
  if (!isValidSha256Hex(proof.leafHash) || !isValidSha256Hex(proof.rootHash)) {
    return false;
  }

  let computed = proof.leafHash;
  for (const step of proof.steps) {
    if (!isValidSha256Hex(step.hash)) {
      return false;
    }
    computed =
      step.position === 'left'
        ? hashMerkleNode(step.hash, computed)
        : hashMerkleNode(computed, step.hash);
  }

  return computed === proof.rootHash;
}

function compareNodePrecedence(a: CognitiveNode, b: CognitiveNode): number {
  if (a.lamportClock !== b.lamportClock) {
    return a.lamportClock - b.lamportClock;
  }
  if (a.peerId !== b.peerId) {
    return compareAscii(a.peerId, b.peerId);
  }
  return compareAscii(hashCognitiveNode(a), hashCognitiveNode(b));
}

export function diffCognitiveGraphs(
  source: CognitiveGraphSnapshot,
  target: CognitiveGraphSnapshot
): CognitiveGraphDelta {
  const missingInTarget: CognitiveNode[] = [];
  const newerInSource: CognitiveNode[] = [];
  let identicalCount = 0;

  const sortedIds = Array.from(source.nodes.keys()).sort(compareAscii);
  for (const id of sortedIds) {
    const sourceNode = source.nodes.get(id);
    if (!sourceNode) continue;

    const targetNode = target.nodes.get(id);
    if (!targetNode) {
      missingInTarget.push(sourceNode);
      continue;
    }

    if (hashCognitiveNode(sourceNode) === hashCognitiveNode(targetNode)) {
      identicalCount += 1;
    } else if (compareNodePrecedence(sourceNode, targetNode) > 0) {
      newerInSource.push(sourceNode);
    }
  }

  return {
    sourcePeerId: source.peerId,
    targetPeerId: target.peerId,
    missingInTarget,
    newerInSource,
    identicalCount,
  };
}

export function mergeCognitiveGraphs(
  local: CognitiveGraphSnapshot,
  remote: CognitiveGraphSnapshot,
  mergedPeerId: string = local.peerId
): MergeResult {
  const mergedNodes = new Map<string, CognitiveNode>(local.nodes);
  const appliedNodeIds: string[] = [];
  let conflictCount = 0;

  const remoteIds = Array.from(remote.nodes.keys()).sort(compareAscii);
  for (const id of remoteIds) {
    const remoteNode = remote.nodes.get(id);
    if (!remoteNode) continue;

    const localNode = mergedNodes.get(id);
    if (!localNode) {
      mergedNodes.set(id, remoteNode);
      appliedNodeIds.push(id);
      continue;
    }

    if (hashCognitiveNode(localNode) === hashCognitiveNode(remoteNode)) {
      continue;
    }

    conflictCount += 1;
    if (compareNodePrecedence(remoteNode, localNode) > 0) {
      mergedNodes.set(id, remoteNode);
      appliedNodeIds.push(id);
    }
  }

  const merged: CognitiveGraphSnapshot = {
    peerId: mergedPeerId,
    nodes: mergedNodes,
  };
  const tree = buildMerkleTree(mergedNodes);

  return {
    merged,
    appliedNodeIds,
    conflictCount,
    rootHash: tree.rootHash,
  };
}

export function hashPcwArtifactRecord(artifact: PcwArtifactRecord): string {
  return hashMerkleLeafBytes(
    canonicalStringify({
      id: artifact.id,
      kind: artifact.kind,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
      path: artifact.path,
    })
  );
}

export function buildArtifactMerkleTree(artifacts: readonly PcwArtifactRecord[]): MerkleTree {
  const entries = new Map<string, string>();
  for (const artifact of artifacts) {
    entries.set(artifact.id, hashPcwArtifactRecord(artifact));
  }
  return buildMerkleTreeFromEntries(entries);
}

function computePcwEnvelopeDigest(
  draft: PcwEnvelopeDraft,
  merkleRoot: string
): string {
  const payload = {
    schemaVersion: draft.schemaVersion,
    envelopeId: draft.envelopeId,
    taskId: draft.taskId,
    producerAgentId: draft.producerAgentId,
    reviewerAgentId: draft.reviewerAgentId,
    riskTier: draft.riskTier,
    parentProofHashes: draft.parentProofHashes,
    artifacts: draft.artifacts.map((artifact) => ({
      id: artifact.id,
      kind: artifact.kind,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
      path: artifact.path,
    })),
    checks: draft.checks,
    changedFiles: draft.changedFiles,
    producedAt: draft.producedAt,
    expiresAt: draft.expiresAt,
    metadata: draft.metadata,
    merkleRoot,
  };
  return sha256Hex(canonicalStringify(payload));
}

export function sealPcwEnvelope(draft: PcwEnvelopeDraft): PcwEnvelope {
  const normalizedParents = [...new Set(draft.parentProofHashes)].sort(compareAscii);
  const normalizedArtifacts = [...draft.artifacts].sort((a, b) => compareAscii(a.id, b.id));
  const normalizedChangedFiles =
    draft.changedFiles !== undefined
      ? [...new Set(draft.changedFiles)].sort(compareAscii)
      : undefined;

  const normalizedDraft: PcwEnvelopeDraft = {
    ...draft,
    parentProofHashes: normalizedParents,
    artifacts: normalizedArtifacts,
    ...(normalizedChangedFiles !== undefined ? { changedFiles: normalizedChangedFiles } : {}),
  };

  const artifactTree = buildArtifactMerkleTree(normalizedDraft.artifacts);
  const merkleRoot = artifactTree.rootHash;
  const envelopeSha256 = computePcwEnvelopeDigest(normalizedDraft, merkleRoot);

  return {
    ...normalizedDraft,
    merkleRoot,
    envelopeSha256,
  };
}

export function verifyPcwEnvelope(
  envelope: PcwEnvelope,
  options: PcwVerificationOptions = {}
): PcwVerificationResult {
  const nowMs = options.nowMs ?? Date.now();
  const issues: PcwVerificationIssue[] = [];
  const verifiedArtifactDigests: Record<string, string> = {};

  if (envelope.schemaVersion !== 'pcw/v1') {
    issues.push({
      code: 'INVALID_SCHEMA_VERSION',
      message: `Unsupported PCW schemaVersion "${String(envelope.schemaVersion)}"; expected "pcw/v1".`,
    });
  }

  const requireAtLeastOneArtifact = options.requireAtLeastOneArtifact ?? true;
  if (requireAtLeastOneArtifact && envelope.artifacts.length === 0) {
    issues.push({
      code: 'EMPTY_ARTIFACTS',
      message: `PCW envelope "${envelope.envelopeId}" must contain at least one evidence artifact.`,
    });
  }

  const seenArtifactIds = new Set<string>();
  for (const artifact of envelope.artifacts) {
    if (seenArtifactIds.has(artifact.id)) {
      issues.push({
        code: 'DUPLICATE_ARTIFACT_ID',
        artifactId: artifact.id,
        message: `Duplicate artifact id "${artifact.id}" in PCW envelope.`,
      });
      continue;
    }
    seenArtifactIds.add(artifact.id);

    if (!isValidSha256Hex(artifact.sha256)) {
      issues.push({
        code: 'INVALID_ARTIFACT_SHA256',
        artifactId: artifact.id,
        message: `Artifact "${artifact.id}" has invalid SHA-256 digest "${artifact.sha256}".`,
      });
      continue;
    }

    if (artifact.content !== undefined) {
      const computedContentSha = sha256Hex(artifact.content);
      if (computedContentSha !== artifact.sha256) {
        issues.push({
          code: 'ARTIFACT_DIGEST_MISMATCH',
          artifactId: artifact.id,
          message: `Artifact "${artifact.id}" content digest mismatch (declared ${artifact.sha256} !== computed ${computedContentSha}).`,
        });
        continue;
      }
      if (artifact.sizeBytes !== undefined) {
        const actualBytes = Buffer.byteLength(artifact.content, 'utf8');
        if (actualBytes !== artifact.sizeBytes) {
          issues.push({
            code: 'ARTIFACT_SIZE_MISMATCH',
            artifactId: artifact.id,
            message: `Artifact "${artifact.id}" byte length mismatch (declared ${artifact.sizeBytes} !== actual ${actualBytes}).`,
          });
          continue;
        }
      }
    }

    verifiedArtifactDigests[artifact.id] = artifact.sha256;
  }

  const artifactTree = buildArtifactMerkleTree(envelope.artifacts);
  const computedMerkleRoot = artifactTree.rootHash;

  if (!isValidSha256Hex(envelope.merkleRoot)) {
    issues.push({
      code: 'INVALID_MERKLE_ROOT',
      message: `Envelope merkleRoot "${envelope.merkleRoot}" is not a valid 64-hex SHA-256 digest.`,
    });
  } else if (envelope.merkleRoot !== computedMerkleRoot) {
    issues.push({
      code: 'MERKLE_ROOT_MISMATCH',
      message: `Envelope merkleRoot ${envelope.merkleRoot} !== computed ${computedMerkleRoot}.`,
    });
  }

  if (
    options.expectedMerkleRoot !== undefined &&
    options.expectedMerkleRoot !== computedMerkleRoot
  ) {
    issues.push({
      code: 'MERKLE_ROOT_MISMATCH',
      message: `Computed merkleRoot ${computedMerkleRoot} !== expected ${options.expectedMerkleRoot}.`,
    });
  }

  if (options.merkleProofs !== undefined) {
    for (const proof of options.merkleProofs) {
      if (proof.rootHash !== computedMerkleRoot || !verifyMerkleProof(proof)) {
        issues.push({
          code: 'INVALID_MERKLE_PROOF',
          artifactId: proof.leafId,
          message: `Merkle inclusion proof failed for leaf "${proof.leafId}".`,
        });
      }
    }
  }

  const computedEnvelopeSha256 = computePcwEnvelopeDigest(envelope, computedMerkleRoot);
  if (!isValidSha256Hex(envelope.envelopeSha256)) {
    issues.push({
      code: 'INVALID_ENVELOPE_SHA256',
      message: `Envelope digest "${envelope.envelopeSha256}" is not a valid 64-hex SHA-256 digest.`,
    });
  } else if (envelope.envelopeSha256 !== computedEnvelopeSha256) {
    issues.push({
      code: 'ENVELOPE_TAMPERED',
      message: `Envelope SHA-256 mismatch (declared ${envelope.envelopeSha256} !== computed ${computedEnvelopeSha256}).`,
    });
  }

  for (const parentHash of envelope.parentProofHashes) {
    if (!isValidSha256Hex(parentHash)) {
      issues.push({
        code: 'INVALID_PARENT_PROOF_HASH',
        message: `Parent proof hash "${parentHash}" is not a valid 64-hex SHA-256 digest.`,
      });
    }
  }

  for (const expectedParent of options.expectedParentHashes ?? []) {
    if (!envelope.parentProofHashes.includes(expectedParent)) {
      issues.push({
        code: 'MISSING_PARENT_PROOF',
        message: `Expected predecessor proof hash "${expectedParent}" missing from parentProofHashes.`,
      });
    }
  }

  for (const check of envelope.checks) {
    const mandatory = check.mandatory ?? true;
    if (
      (check.status === 'skipped' || check.status === 'not_applicable') &&
      (!check.reason || check.reason.trim().length === 0)
    ) {
      issues.push({
        code: 'MISSING_SKIP_REASON',
        checkCode: check.code,
        message: `Check "${check.code}" with status "${check.status}" requires a non-empty reason.`,
      });
    }
    if (mandatory && check.status !== 'pass') {
      issues.push({
        code: 'MANDATORY_CHECK_FAILED',
        checkCode: check.code,
        message: `Mandatory check "${check.code}" did not pass (status: ${check.status}).`,
      });
    } else if (!mandatory && check.status === 'fail') {
      issues.push({
        code: 'CHECK_FAILED',
        checkCode: check.code,
        message: `Non-mandatory check "${check.code}" failed.`,
      });
    }
  }

  if (
    envelope.reviewerAgentId !== undefined &&
    envelope.reviewerAgentId.trim() === envelope.producerAgentId.trim()
  ) {
    issues.push({
      code: 'SELF_APPROVAL_REJECTED',
      message: `Producer "${envelope.producerAgentId}" cannot self-approve its own PCW envelope.`,
    });
  }

  const requireReviewer =
    options.requireIndependentReviewer ??
    (envelope.riskTier === 'R2' || envelope.riskTier === 'R3' || envelope.riskTier === 'R4');
  if (requireReviewer && (!envelope.reviewerAgentId || envelope.reviewerAgentId.trim().length === 0)) {
    issues.push({
      code: 'INDEPENDENT_REVIEWER_REQUIRED',
      message: `Risk tier ${envelope.riskTier} requires an independent reviewerAgentId.`,
    });
  }

  if (envelope.expiresAt !== undefined) {
    const expiresMs = Date.parse(envelope.expiresAt);
    if (!Number.isFinite(expiresMs) || expiresMs <= nowMs) {
      issues.push({
        code: 'ENVELOPE_EXPIRED',
        message: `PCW envelope "${envelope.envelopeId}" expired at ${envelope.expiresAt}.`,
      });
    }
  }

  const valid = issues.length === 0;
  const reportBase = {
    valid,
    status: (valid ? 'accepted' : 'rejected') as 'accepted' | 'rejected',
    envelopeId: envelope.envelopeId,
    taskId: envelope.taskId,
    computedMerkleRoot,
    computedEnvelopeSha256,
    artifactCount: envelope.artifacts.length,
    verifiedArtifactDigests,
    issues,
    verifiedAt: new Date(nowMs).toISOString(),
  };

  return {
    ...reportBase,
    reportSha256: sha256Hex(canonicalStringify(reportBase)),
  };
}
