import {
  validateDagPlan,
  type DagNodeDefinition,
  type DagRiskTier,
} from './dag-engine.js';
import {
  evaluateG0ToG6Gates,
  runDeterministicG0ToG6Harness,
  type EvalGateThresholds,
  type EvalRunInput,
  type EvalSummaryMetrics,
  type MemoryAblationSummary,
} from './eval-gates.js';
import {
  verifyPcwEnvelope,
  type MerkleProof,
  type MerkleProofStep,
  type PcwArtifactKind,
  type PcwArtifactRecord,
  type PcwCheckEvidence,
  type PcwCheckStatus,
  type PcwEnvelope,
} from './merkle-pcw.js';
import {
  checkDisjointOwnership,
  evaluateRiskPolicy,
  SingleUseApprovalRegistry,
  type AgentOwnershipClaim,
  type ApprovalToken,
  type CapabilityGrant,
  type DataClassification,
  type RiskTier,
  type TargetZone,
} from './risk-policy.js';

import {
  selectEcoModel,
  type BudgetConfig,
  type RouteClassification,
  type TaskProfile,
} from './eco-router.js';
import {
  PersistentSessionStore,
  type SessionAppendTurnInput,
  type SessionCreateInput,
} from './session-store.js';

export const DEFAULT_CORE_PORT = 4520;
export const SERVICE_NAME = 'mw-rocksoul-core';
export const PACKAGE_NAME = '@moonwitness/rocksoul-core';
export const SERVICE_VERSION = '1.0.0';

export const CORE_ENDPOINTS = Object.freeze([
  'GET /health',
  'POST /v1/plans/validate',
  'POST /v1/risk/evaluate',
  'POST /v1/pcw/verify',
  'POST /v1/swarm/check-overlap',
  'POST /v1/evals/g0-g6',
  'POST /v1/router/select',
  'GET /v1/sessions',
  'POST /v1/sessions',
  'GET /v1/sessions/:id',
]);

export interface CoreServerContext {
  readonly port: number;
  readonly approvalRegistry: SingleUseApprovalRegistry;
  readonly sessionStore: PersistentSessionStore;
}

export interface CoreServerOptions {
  readonly port?: number;
  readonly hostname?: string;
  readonly approvalRegistry?: SingleUseApprovalRegistry;
  readonly sessionStore?: PersistentSessionStore;
}

const VALID_RISK_TIERS = new Set<string>(['R0', 'R1', 'R2', 'R3', 'R4']);
const VALID_ARTIFACT_KINDS = new Set<string>([
  'diff',
  'test_log',
  'report',
  'transcript',
  'tool_output',
  'evidence_bundle',
  'eval_result',
]);
const VALID_CHECK_STATUSES = new Set<string>([
  'pass',
  'fail',
  'skipped',
  'not_applicable',
  'not_run',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isRiskTier(value: unknown): value is RiskTier {
  return typeof value === 'string' && VALID_RISK_TIERS.has(value);
}

function isDataClassification(value: unknown): value is DataClassification {
  return value === 'local_only' || value === 'cloud_eligible';
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(`${JSON.stringify(body)}\n`, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'content-type, authorization',
      'x-content-type-options': 'nosniff',
    },
  });
}

async function readJsonBody(
  request: Request
): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly response: Response }> {
  try {
    const value: unknown = await request.json();
    return { ok: true, value };
  } catch {
    return {
      ok: false,
      response: jsonResponse({ error: 'Request body must be valid JSON.' }, 400),
    };
  }
}

function parseDagNodes(raw: unknown): DagNodeDefinition[] | null {
  let candidate: unknown = raw;
  if (isRecord(raw)) {
    if (Array.isArray(raw.nodes)) {
      candidate = raw.nodes;
    } else if (isRecord(raw.plan) && Array.isArray(raw.plan.nodes)) {
      candidate = raw.plan.nodes;
    }
  }
  if (!Array.isArray(candidate)) {
    return null;
  }

  const parsed: DagNodeDefinition[] = [];
  for (const entry of candidate) {
    if (!isRecord(entry) || typeof entry.id !== 'string') {
      return null;
    }
    if (entry.dependencies !== undefined && !isStringArray(entry.dependencies)) {
      return null;
    }
    if (entry.owner !== undefined && typeof entry.owner !== 'string') {
      return null;
    }
    if (entry.ownedPaths !== undefined && !isStringArray(entry.ownedPaths)) {
      return null;
    }
    if (entry.riskTier !== undefined && !isRiskTier(entry.riskTier)) {
      return null;
    }
    parsed.push({
      id: entry.id,
      ...(entry.dependencies !== undefined ? { dependencies: entry.dependencies } : {}),
      ...(entry.owner !== undefined ? { owner: entry.owner } : {}),
      ...(entry.ownedPaths !== undefined ? { ownedPaths: entry.ownedPaths } : {}),
      ...(entry.riskTier !== undefined ? { riskTier: entry.riskTier as DagRiskTier } : {}),
      ...(entry.data !== undefined ? { data: entry.data } : {}),
    });
  }
  return parsed;
}

function parseCapabilityGrant(raw: unknown): CapabilityGrant | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.grantId !== 'string' ||
    typeof raw.principalId !== 'string' ||
    !isStringArray(raw.capabilities) ||
    !isRiskTier(raw.maxRiskTier) ||
    !Array.isArray(raw.allowedClassifications) ||
    !raw.allowedClassifications.every(isDataClassification)
  ) {
    return null;
  }
  if (raw.allowedPaths !== undefined && !isStringArray(raw.allowedPaths)) return null;
  if (raw.expiresAt !== undefined && typeof raw.expiresAt !== 'string') return null;
  if (raw.revoked !== undefined && typeof raw.revoked !== 'boolean') return null;

  return {
    grantId: raw.grantId,
    principalId: raw.principalId,
    capabilities: raw.capabilities,
    maxRiskTier: raw.maxRiskTier,
    allowedClassifications: raw.allowedClassifications,
    ...(raw.allowedPaths !== undefined ? { allowedPaths: raw.allowedPaths } : {}),
    ...(raw.expiresAt !== undefined ? { expiresAt: raw.expiresAt } : {}),
    ...(raw.revoked !== undefined ? { revoked: raw.revoked } : {}),
  };
}

function parseApprovalToken(raw: unknown): ApprovalToken | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.tokenId !== 'string' ||
    typeof raw.issuerId !== 'string' ||
    typeof raw.approvedByRole !== 'string' ||
    typeof raw.actionDigest !== 'string' ||
    !isRiskTier(raw.riskTier) ||
    typeof raw.expiresAt !== 'string' ||
    typeof raw.singleUse !== 'boolean'
  ) {
    return null;
  }
  if (raw.revoked !== undefined && typeof raw.revoked !== 'boolean') return null;

  return {
    tokenId: raw.tokenId,
    issuerId: raw.issuerId,
    approvedByRole: raw.approvedByRole,
    actionDigest: raw.actionDigest,
    riskTier: raw.riskTier,
    expiresAt: raw.expiresAt,
    singleUse: raw.singleUse,
    ...(raw.revoked !== undefined ? { revoked: raw.revoked } : {}),
  };
}

function parsePcwArtifact(raw: unknown): PcwArtifactRecord | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.id !== 'string' ||
    typeof raw.kind !== 'string' ||
    !VALID_ARTIFACT_KINDS.has(raw.kind) ||
    typeof raw.sha256 !== 'string'
  ) {
    return null;
  }
  if (raw.content !== undefined && typeof raw.content !== 'string') return null;
  if (raw.sizeBytes !== undefined && typeof raw.sizeBytes !== 'number') return null;
  if (raw.path !== undefined && typeof raw.path !== 'string') return null;

  return {
    id: raw.id,
    kind: raw.kind as PcwArtifactKind,
    sha256: raw.sha256,
    ...(raw.content !== undefined ? { content: raw.content } : {}),
    ...(raw.sizeBytes !== undefined ? { sizeBytes: raw.sizeBytes } : {}),
    ...(raw.path !== undefined ? { path: raw.path } : {}),
  };
}

function parsePcwCheck(raw: unknown): PcwCheckEvidence | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.code !== 'string' ||
    typeof raw.status !== 'string' ||
    !VALID_CHECK_STATUSES.has(raw.status)
  ) {
    return null;
  }
  if (raw.command !== undefined && typeof raw.command !== 'string') return null;
  if (raw.mandatory !== undefined && typeof raw.mandatory !== 'boolean') return null;
  if (raw.exitCode !== undefined && typeof raw.exitCode !== 'number') return null;
  if (raw.reason !== undefined && typeof raw.reason !== 'string') return null;

  return {
    code: raw.code,
    status: raw.status as PcwCheckStatus,
    ...(raw.command !== undefined ? { command: raw.command } : {}),
    ...(raw.mandatory !== undefined ? { mandatory: raw.mandatory } : {}),
    ...(raw.exitCode !== undefined ? { exitCode: raw.exitCode } : {}),
    ...(raw.reason !== undefined ? { reason: raw.reason } : {}),
  };
}

function parsePcwEnvelope(raw: unknown): PcwEnvelope | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.schemaVersion !== 'string' ||
    typeof raw.envelopeId !== 'string' ||
    typeof raw.taskId !== 'string' ||
    typeof raw.producerAgentId !== 'string' ||
    !isRiskTier(raw.riskTier) ||
    !isStringArray(raw.parentProofHashes) ||
    !Array.isArray(raw.artifacts) ||
    !Array.isArray(raw.checks) ||
    typeof raw.producedAt !== 'string' ||
    typeof raw.merkleRoot !== 'string' ||
    typeof raw.envelopeSha256 !== 'string'
  ) {
    return null;
  }

  const artifacts: PcwArtifactRecord[] = [];
  for (const item of raw.artifacts) {
    const parsed = parsePcwArtifact(item);
    if (!parsed) return null;
    artifacts.push(parsed);
  }

  const checks: PcwCheckEvidence[] = [];
  for (const item of raw.checks) {
    const parsed = parsePcwCheck(item);
    if (!parsed) return null;
    checks.push(parsed);
  }

  if (raw.reviewerAgentId !== undefined && typeof raw.reviewerAgentId !== 'string') return null;
  if (raw.changedFiles !== undefined && !isStringArray(raw.changedFiles)) return null;
  if (raw.expiresAt !== undefined && typeof raw.expiresAt !== 'string') return null;
  if (raw.metadata !== undefined && !isRecord(raw.metadata)) return null;

  return {
    schemaVersion: raw.schemaVersion as 'pcw/v1',
    envelopeId: raw.envelopeId,
    taskId: raw.taskId,
    producerAgentId: raw.producerAgentId,
    ...(raw.reviewerAgentId !== undefined ? { reviewerAgentId: raw.reviewerAgentId } : {}),
    riskTier: raw.riskTier,
    parentProofHashes: raw.parentProofHashes,
    artifacts,
    checks,
    ...(raw.changedFiles !== undefined ? { changedFiles: raw.changedFiles } : {}),
    producedAt: raw.producedAt,
    ...(raw.expiresAt !== undefined ? { expiresAt: raw.expiresAt } : {}),
    ...(raw.metadata !== undefined ? { metadata: raw.metadata } : {}),
    merkleRoot: raw.merkleRoot,
    envelopeSha256: raw.envelopeSha256,
  };
}

function parseMerkleProofs(raw: unknown): MerkleProof[] | null {
  if (!Array.isArray(raw)) return null;
  const proofs: MerkleProof[] = [];
  for (const item of raw) {
    if (
      !isRecord(item) ||
      typeof item.leafId !== 'string' ||
      typeof item.leafHash !== 'string' ||
      typeof item.rootHash !== 'string' ||
      !Array.isArray(item.steps)
    ) {
      return null;
    }
    const steps: MerkleProofStep[] = [];
    for (const step of item.steps) {
      if (
        !isRecord(step) ||
        (step.position !== 'left' && step.position !== 'right') ||
        typeof step.hash !== 'string'
      ) {
        return null;
      }
      steps.push({ position: step.position, hash: step.hash });
    }
    proofs.push({
      leafId: item.leafId,
      leafHash: item.leafHash,
      rootHash: item.rootHash,
      steps,
    });
  }
  return proofs;
}

function parseOwnershipClaims(raw: unknown): AgentOwnershipClaim[] | null {
  let candidate: unknown = raw;
  if (isRecord(raw)) {
    if (Array.isArray(raw.claims)) {
      candidate = raw.claims;
    } else if (Array.isArray(raw.agents)) {
      candidate = raw.agents;
    }
  }
  if (!Array.isArray(candidate)) {
    return null;
  }

  const claims: AgentOwnershipClaim[] = [];
  for (const item of candidate) {
    if (
      !isRecord(item) ||
      typeof item.agentId !== 'string' ||
      !isStringArray(item.writePaths)
    ) {
      return null;
    }
    if (item.taskId !== undefined && typeof item.taskId !== 'string') return null;
    if (item.readPaths !== undefined && !isStringArray(item.readPaths)) return null;
    claims.push({
      agentId: item.agentId,
      ...(item.taskId !== undefined ? { taskId: item.taskId } : {}),
      writePaths: item.writePaths,
      ...(item.readPaths !== undefined ? { readPaths: item.readPaths } : {}),
    });
  }
  return claims;
}

function parseEvalRuns(raw: unknown): EvalRunInput[] | null {
  if (!Array.isArray(raw)) return null;
  const validStatuses = new Set(['accepted', 'failed', 'partial', 'cancelled']);
  const runs: EvalRunInput[] = [];
  for (const item of raw) {
    if (
      !isRecord(item) ||
      typeof item.runId !== 'string' ||
      typeof item.taskFamily !== 'string' ||
      (item.mode !== 'single_agent' && item.mode !== 'multi_agent') ||
      typeof item.decomposable !== 'boolean' ||
      typeof item.heldOutTransfer !== 'boolean' ||
      typeof item.faultInjected !== 'boolean' ||
      typeof item.status !== 'string' ||
      !validStatuses.has(item.status) ||
      typeof item.verifiedSuccess !== 'boolean' ||
      typeof item.evidenceComplete !== 'boolean' ||
      typeof item.unauthorizedActionCount !== 'number' ||
      typeof item.retainedFunctionalityPassed !== 'boolean'
    ) {
      return null;
    }
    runs.push({
      runId: item.runId,
      taskFamily: item.taskFamily,
      mode: item.mode,
      decomposable: item.decomposable,
      heldOutTransfer: item.heldOutTransfer,
      faultInjected: item.faultInjected,
      status: item.status as EvalRunInput['status'],
      verifiedSuccess: item.verifiedSuccess,
      evidenceComplete: item.evidenceComplete,
      unauthorizedActionCount: item.unauthorizedActionCount,
      retainedFunctionalityPassed: item.retainedFunctionalityPassed,
      ...(typeof item.recoveredFromFault === 'boolean'
        ? { recoveredFromFault: item.recoveredFromFault }
        : {}),
      ...(typeof item.contradictionOrDuplicateCount === 'number'
        ? { contradictionOrDuplicateCount: item.contradictionOrDuplicateCount }
        : {}),
      ...(typeof item.durationMs === 'number' ? { durationMs: item.durationMs } : {}),
    });
  }
  return runs;
}

function parseEvalMetrics(raw: unknown): EvalSummaryMetrics | null {
  if (!isRecord(raw)) return null;
  const numericFields = [
    'totalRuns',
    'acceptedRuns',
    'failedRuns',
    'verifiedSuccessRateBps',
    'evidenceCompletenessBps',
    'retainedFunctionalityRateBps',
    'faultRecoveryRateBps',
    'unauthorizedActionCount',
    'contradictionOrDuplicateCount',
    'multiAgentNetBenefitBps',
    'adaptiveReplanSuccessRateBps',
    'heldOutTransferSuccessRateBps',
  ] as const;

  for (const field of numericFields) {
    if (typeof raw[field] !== 'number' || !Number.isFinite(raw[field])) {
      return null;
    }
  }

  return {
    totalRuns: raw.totalRuns as number,
    acceptedRuns: raw.acceptedRuns as number,
    failedRuns: raw.failedRuns as number,
    verifiedSuccessRateBps: raw.verifiedSuccessRateBps as number,
    evidenceCompletenessBps: raw.evidenceCompletenessBps as number,
    retainedFunctionalityRateBps: raw.retainedFunctionalityRateBps as number,
    faultRecoveryRateBps: raw.faultRecoveryRateBps as number,
    unauthorizedActionCount: raw.unauthorizedActionCount as number,
    contradictionOrDuplicateCount: raw.contradictionOrDuplicateCount as number,
    multiAgentNetBenefitBps: raw.multiAgentNetBenefitBps as number,
    adaptiveReplanSuccessRateBps: raw.adaptiveReplanSuccessRateBps as number,
    heldOutTransferSuccessRateBps: raw.heldOutTransferSuccessRateBps as number,
  };
}

function parseAblation(raw: unknown): MemoryAblationSummary | null {
  if (!isRecord(raw)) return null;
  if (
    typeof raw.utilityGainVsNoMemoryBps !== 'number' ||
    typeof raw.safetyRegressions !== 'number' ||
    (raw.recommendation !== 'promote' &&
      raw.recommendation !== 'hold' &&
      raw.recommendation !== 'reject')
  ) {
    return null;
  }
  return {
    utilityGainVsNoMemoryBps: raw.utilityGainVsNoMemoryBps,
    safetyRegressions: raw.safetyRegressions,
    recommendation: raw.recommendation,
  };
}

function parseThresholds(raw: unknown): Partial<EvalGateThresholds> | null {
  if (!isRecord(raw)) return null;
  const result: Record<string, number> = {};
  const allowedKeys = new Set<string>([
    'minG0VerifiedSuccessBps',
    'minG1EvidenceCompletenessBps',
    'minG2FaultRecoveryBps',
    'minG3MultiAgentNetBenefitBps',
    'minG4AdaptiveReplanBps',
    'minG5MemoryUtilityGainBps',
    'minG6HeldOutTransferBps',
    'minRetainedFunctionalityBps',
    'maxUnauthorizedActions',
  ]);
  for (const [key, value] of Object.entries(raw)) {
    if (!allowedKeys.has(key)) continue;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return null;
    }
    result[key] = value;
  }
  return result as Partial<EvalGateThresholds>;
}

const defaultSessionStore = new PersistentSessionStore(
  process.env.ROCKSOUL_SESSION_STORE_PATH ?? '.rocksoul/sessions.json'
);

export async function handleCoreRequest(
  request: Request,
  context: CoreServerContext = {
    port: DEFAULT_CORE_PORT,
    approvalRegistry: new SingleUseApprovalRegistry(),
    sessionStore: defaultSessionStore,
  }
): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type, authorization',
      },
    });
  }

  if (pathname === '/health') {
    if (request.method !== 'GET') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    return jsonResponse({
      status: 'ok',
      service: SERVICE_NAME,
      package: PACKAGE_NAME,
      version: SERVICE_VERSION,
      port: context.port,
      zeroOrm: true,
      modules: ['dag-engine', 'merkle-pcw', 'risk-policy', 'eval-gates', 'eco-router', 'session-store'],
      endpoints: CORE_ENDPOINTS,
      timestamp: new Date().toISOString(),
    });
  }

  if (pathname === '/v1/plans/validate') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const nodes = parseDagNodes(parsedBody.value);
    if (nodes === null) {
      return jsonResponse(
        { error: 'Invalid plan payload: expected { nodes: DagNodeDefinition[] }.' },
        400
      );
    }

    const validation = validateDagPlan(nodes);
    const claims: AgentOwnershipClaim[] = [];
    for (const node of nodes) {
      if (node.owner !== undefined && node.ownedPaths !== undefined && node.ownedPaths.length > 0) {
        claims.push({
          agentId: node.owner,
          taskId: node.id,
          writePaths: node.ownedPaths,
        });
      }
    }

    if (claims.length > 0) {
      const ownership = checkDisjointOwnership(claims);
      return jsonResponse({
        ...validation,
        valid: validation.valid && ownership.disjoint,
        ownership,
      });
    }

    return jsonResponse(validation);
  }

  if (pathname === '/v1/risk/evaluate') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const body = parsedBody.value;
    if (
      !isRecord(body) ||
      typeof body.principalId !== 'string' ||
      typeof body.action !== 'string' ||
      typeof body.capability !== 'string' ||
      typeof body.dataClassification !== 'string'
    ) {
      return jsonResponse(
        {
          error:
            'Invalid risk evaluation payload: principalId, action, capability, and dataClassification are required strings.',
        },
        400
      );
    }

    if (body.requestedTier !== undefined && !isRiskTier(body.requestedTier)) {
      return jsonResponse({ error: 'requestedTier must be one of R0, R1, R2, R3, R4.' }, 400);
    }
    if (body.targetZone !== undefined && body.targetZone !== 'local' && body.targetZone !== 'cloud') {
      return jsonResponse({ error: 'targetZone must be "local" or "cloud".' }, 400);
    }
    if (body.targetPaths !== undefined && !isStringArray(body.targetPaths)) {
      return jsonResponse({ error: 'targetPaths must be an array of strings.' }, 400);
    }

    let grant: CapabilityGrant | undefined;
    if (body.grant !== undefined) {
      const parsedGrant = parseCapabilityGrant(body.grant);
      if (!parsedGrant) {
        return jsonResponse({ error: 'Invalid grant object.' }, 400);
      }
      grant = parsedGrant;
    }

    let approvalToken: ApprovalToken | undefined;
    if (body.approvalToken !== undefined) {
      const parsedToken = parseApprovalToken(body.approvalToken);
      if (!parsedToken) {
        return jsonResponse({ error: 'Invalid approvalToken object.' }, 400);
      }
      approvalToken = parsedToken;
    }

    const decision = evaluateRiskPolicy({
      principalId: body.principalId,
      action: body.action,
      capability: body.capability,
      ...(body.requestedTier !== undefined ? { requestedTier: body.requestedTier } : {}),
      dataClassification: body.dataClassification,
      ...(body.targetZone !== undefined ? { targetZone: body.targetZone as TargetZone } : {}),
      ...(body.targetPaths !== undefined ? { targetPaths: body.targetPaths } : {}),
      ...(grant !== undefined ? { grant } : {}),
      ...(typeof body.requireGrant === 'boolean' ? { requireGrant: body.requireGrant } : {}),
      ...(approvalToken !== undefined ? { approvalToken } : {}),
      ...(typeof body.actionDigest === 'string' ? { actionDigest: body.actionDigest } : {}),
      ...(typeof body.readOnlyMode === 'boolean' ? { readOnlyMode: body.readOnlyMode } : {}),
      ...(typeof body.requireApprovalForR2 === 'boolean'
        ? { requireApprovalForR2: body.requireApprovalForR2 }
        : {}),
      ...(typeof body.emergencyStopActive === 'boolean'
        ? { emergencyStopActive: body.emergencyStopActive }
        : {}),
      ...(typeof body.nowMs === 'number' ? { nowMs: body.nowMs } : {}),
      approvalRegistry: context.approvalRegistry,
    });

    return jsonResponse(decision);
  }

  if (pathname === '/v1/pcw/verify') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const body = parsedBody.value;
    const rawEnvelope = isRecord(body) && 'envelope' in body ? body.envelope : body;
    const envelope = parsePcwEnvelope(rawEnvelope);
    if (!envelope) {
      return jsonResponse(
        { error: 'Invalid PCW verification payload: expected valid PcwEnvelope.' },
        400
      );
    }

    let expectedParentHashes: string[] | undefined;
    let expectedMerkleRoot: string | undefined;
    let merkleProofs: MerkleProof[] | undefined;
    let requireIndependentReviewer: boolean | undefined;
    let nowMs: number | undefined;

    if (isRecord(body)) {
      if (body.expectedParentHashes !== undefined) {
        if (!isStringArray(body.expectedParentHashes)) {
          return jsonResponse({ error: 'expectedParentHashes must be an array of strings.' }, 400);
        }
        expectedParentHashes = body.expectedParentHashes;
      }
      if (body.expectedMerkleRoot !== undefined) {
        if (typeof body.expectedMerkleRoot !== 'string') {
          return jsonResponse({ error: 'expectedMerkleRoot must be a string.' }, 400);
        }
        expectedMerkleRoot = body.expectedMerkleRoot;
      }
      if (body.merkleProofs !== undefined) {
        const parsedProofs = parseMerkleProofs(body.merkleProofs);
        if (!parsedProofs) {
          return jsonResponse({ error: 'Invalid merkleProofs array.' }, 400);
        }
        merkleProofs = parsedProofs;
      }
      if (typeof body.requireIndependentReviewer === 'boolean') {
        requireIndependentReviewer = body.requireIndependentReviewer;
      }
      if (typeof body.nowMs === 'number') {
        nowMs = body.nowMs;
      }
    }

    const result = verifyPcwEnvelope(envelope, {
      ...(expectedParentHashes !== undefined ? { expectedParentHashes } : {}),
      ...(expectedMerkleRoot !== undefined ? { expectedMerkleRoot } : {}),
      ...(merkleProofs !== undefined ? { merkleProofs } : {}),
      ...(requireIndependentReviewer !== undefined ? { requireIndependentReviewer } : {}),
      ...(nowMs !== undefined ? { nowMs } : {}),
    });

    return jsonResponse(result);
  }

  if (pathname === '/v1/swarm/check-overlap') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const claims = parseOwnershipClaims(parsedBody.value);
    if (!claims) {
      return jsonResponse(
        { error: 'Invalid overlap check payload: expected { claims: AgentOwnershipClaim[] }.' },
        400
      );
    }

    const allowProtectedPaths =
      isRecord(parsedBody.value) && typeof parsedBody.value.allowProtectedPaths === 'boolean'
        ? parsedBody.value.allowProtectedPaths
        : false;

    const report = checkDisjointOwnership(claims, { allowProtectedPaths });
    return jsonResponse(report);
  }

  if (pathname === '/v1/evals/g0-g6') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const body = parsedBody.value;
    if (!isRecord(body)) {
      return jsonResponse({ error: 'Request body must be a JSON object.' }, 400);
    }

    let thresholds: Partial<EvalGateThresholds> | undefined;
    if (body.thresholds !== undefined) {
      const parsedThresholds = parseThresholds(body.thresholds);
      if (!parsedThresholds) {
        return jsonResponse({ error: 'Invalid thresholds object.' }, 400);
      }
      thresholds = parsedThresholds;
    }

    const evaluatedAt = typeof body.evaluatedAt === 'string' ? body.evaluatedAt : undefined;

    if (body.runs === undefined && body.metrics === undefined) {
      const report = await runDeterministicG0ToG6Harness({
        ...(evaluatedAt !== undefined ? { evaluatedAt } : {}),
        ...(thresholds !== undefined ? { thresholds } : {}),
      });
      return jsonResponse(report);
    }

    let runs: EvalRunInput[] | undefined;
    if (body.runs !== undefined) {
      const parsedRuns = parseEvalRuns(body.runs);
      if (!parsedRuns) {
        return jsonResponse({ error: 'Invalid runs array in G0-G6 eval payload.' }, 400);
      }
      runs = parsedRuns;
    }

    let metrics: EvalSummaryMetrics | undefined;
    if (body.metrics !== undefined) {
      const parsedMetrics = parseEvalMetrics(body.metrics);
      if (!parsedMetrics) {
        return jsonResponse({ error: 'Invalid metrics object in G0-G6 eval payload.' }, 400);
      }
      metrics = parsedMetrics;
    }

    let ablation: MemoryAblationSummary | undefined;
    if (body.ablation !== undefined) {
      const parsedAblation = parseAblation(body.ablation);
      if (!parsedAblation) {
        return jsonResponse({ error: 'Invalid ablation object in G0-G6 eval payload.' }, 400);
      }
      ablation = parsedAblation;
    }

    const report = evaluateG0ToG6Gates({
      ...(runs !== undefined ? { runs } : {}),
      ...(metrics !== undefined ? { metrics } : {}),
      ...(ablation !== undefined ? { ablation } : {}),
      ...(typeof body.adaptiveReplanSuccessRateBps === 'number'
        ? { adaptiveReplanSuccessRateBps: body.adaptiveReplanSuccessRateBps }
        : {}),
      ...(thresholds !== undefined ? { thresholds } : {}),
      ...(evaluatedAt !== undefined ? { evaluatedAt } : {}),
    });

    return jsonResponse(report);
  }

  if (pathname === '/v1/router/select') {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }
    const parsedBody = await readJsonBody(request);
    if (!parsedBody.ok) return parsedBody.response;

    const body = parsedBody.value;
    if (!isRecord(body)) {
      return jsonResponse({ error: 'Request body must be a JSON object.' }, 400);
    }

    const taskProfile: TaskProfile = isRecord(body.taskProfile)
      ? {
          ...(typeof body.taskProfile.complexity === 'string'
            ? { complexity: body.taskProfile.complexity }
            : {}),
          ...(typeof body.taskProfile.taskFamily === 'string'
            ? { taskFamily: body.taskProfile.taskFamily }
            : {}),
          ...(typeof body.taskProfile.estimatedTokens === 'number'
            ? { estimatedTokens: body.taskProfile.estimatedTokens }
            : {}),
          ...(typeof body.taskProfile.requiresReasoning === 'boolean'
            ? { requiresReasoning: body.taskProfile.requiresReasoning }
            : {}),
        }
      : {};

    const rawBudgets = isRecord(body.budgets) ? body.budgets : {};
    const budgets: BudgetConfig = {
      dailyTokenLimit:
        typeof rawBudgets.dailyTokenLimit === 'number' ? rawBudgets.dailyTokenLimit : 1_000_000,
      dailyTokensUsed:
        typeof rawBudgets.dailyTokensUsed === 'number' ? rawBudgets.dailyTokensUsed : 0,
      ...(typeof rawBudgets.maxTokensPerRequest === 'number'
        ? { maxTokensPerRequest: rawBudgets.maxTokensPerRequest }
        : {}),
    };

    const rawClassification = isRecord(body.classification) ? body.classification : {};
    const classification: RouteClassification = {
      dataClassification: isDataClassification(rawClassification.dataClassification)
        ? rawClassification.dataClassification
        : 'cloud_eligible',
      ...(typeof rawClassification.airGapped === 'boolean'
        ? { airGapped: rawClassification.airGapped }
        : {}),
    };

    const decision = selectEcoModel(taskProfile, budgets, classification);
    return jsonResponse(decision);
  }

  if (pathname === '/v1/sessions') {
    if (request.method === 'GET') {
      const limitParam = url.searchParams.get('limit');
      const limit = limitParam !== null ? parseInt(limitParam, 10) : 100;
      const sessions = await context.sessionStore.listSessions(Number.isNaN(limit) ? 100 : limit);
      return jsonResponse({ sessions });
    }

    if (request.method === 'POST') {
      const parsedBody = await readJsonBody(request);
      if (!parsedBody.ok) return parsedBody.response;

      const body = parsedBody.value;
      if (!isRecord(body)) {
        return jsonResponse({ error: 'Request body must be a JSON object.' }, 400);
      }

      const input: SessionCreateInput = {
        ...(typeof body.title === 'string' ? { title: body.title } : {}),
        ...(typeof body.workDir === 'string' ? { workDir: body.workDir } : {}),
        ...(typeof body.project === 'string' ? { project: body.project } : {}),
        ...(typeof body.agentProfile === 'string' ? { agentProfile: body.agentProfile } : {}),
        ...(typeof body.model === 'string' ? { model: body.model } : {}),
        ...(typeof body.mode === 'string' ? { mode: body.mode } : {}),
      };

      const session = await context.sessionStore.createSession(input);
      return jsonResponse({ session }, 201);
    }

    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  if (pathname.startsWith('/v1/sessions/')) {
    const sessionId = pathname.slice('/v1/sessions/'.length).trim();
    if (sessionId.length === 0) {
      return jsonResponse({ error: 'Session ID is required.' }, 400);
    }

    if (request.method === 'GET') {
      const sessionData = await context.sessionStore.getSession(sessionId);
      if (!sessionData) {
        return jsonResponse({ error: 'Session not found.', sessionId }, 404);
      }
      return jsonResponse(sessionData);
    }

    if (request.method === 'POST') {
      // Append turn to session
      const parsedBody = await readJsonBody(request);
      if (!parsedBody.ok) return parsedBody.response;

      const body = parsedBody.value;
      if (!isRecord(body) || typeof body.role !== 'string' || typeof body.content !== 'string') {
        return jsonResponse(
          { error: 'Invalid turn payload: role and content are required strings.' },
          400
        );
      }

      const validRoles = new Set(['system', 'user', 'assistant', 'tool']);
      if (!validRoles.has(body.role)) {
        return jsonResponse({ error: 'role must be system, user, assistant, or tool.' }, 400);
      }

      const turnInput: SessionAppendTurnInput = {
        role: body.role as 'system' | 'user' | 'assistant' | 'tool',
        content: body.content,
        ...(Array.isArray(body.toolCalls)
          ? { toolCalls: body.toolCalls as SessionAppendTurnInput['toolCalls'] }
          : {}),
        ...(typeof body.toolCallId === 'string' ? { toolCallId: body.toolCallId } : {}),
        ...(typeof body.toolName === 'string' ? { toolName: body.toolName } : {}),
        ...(isRecord(body.meta) ? { meta: body.meta as SessionAppendTurnInput['meta'] } : {}),
      };

      try {
        const turn = await context.sessionStore.appendTurn(sessionId, turnInput);
        return jsonResponse({ turn }, 201);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return jsonResponse({ error: message }, 404);
      }
    }

    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  return jsonResponse({ error: 'Not Found', path: pathname }, 404);
}

export function createCoreServer(options: CoreServerOptions = {}): ReturnType<typeof Bun.serve> {
  const rawEnvPort = process.env.ROCKSOUL_CORE_PORT ?? process.env.PORT;
  const envPort = rawEnvPort !== undefined ? Number(rawEnvPort) : undefined;
  const resolvedPort =
    options.port ??
    (envPort !== undefined && Number.isInteger(envPort) && envPort >= 0
      ? envPort
      : DEFAULT_CORE_PORT);
  const approvalRegistry = options.approvalRegistry ?? new SingleUseApprovalRegistry();
  const sessionStore = options.sessionStore ?? defaultSessionStore;

  return Bun.serve({
    port: resolvedPort,
    hostname: options.hostname ?? process.env.ROCKSOUL_CORE_HOST ?? '0.0.0.0',
    fetch(request, runningServer): Promise<Response> {
      return handleCoreRequest(request, {
        port: runningServer.port ?? resolvedPort,
        approvalRegistry,
        sessionStore,
      });
    },
  });
}

if (import.meta.main) {
  const server = createCoreServer();
  console.log(
    JSON.stringify({
      event: 'mw_rocksoul_core_started',
      service: SERVICE_NAME,
      package: PACKAGE_NAME,
      port: server.port,
      url: server.url.toString(),
    })
  );
}

