import { canonicalStringify, sha256Hex } from './merkle-pcw.js';

export type RiskTier = 'R0' | 'R1' | 'R2' | 'R3' | 'R4';

export type DataClassification = 'local_only' | 'cloud_eligible';

export type DataClassificationInput = DataClassification | 'local-only' | 'cloud-eligible';

export type TargetZone = 'local' | 'cloud';

export const RISK_TIER_ORDER: Readonly<Record<RiskTier, number>> = {
  R0: 0,
  R1: 1,
  R2: 2,
  R3: 3,
  R4: 4,
};

export type RiskAutonomyLevel =
  | 'autonomous_read'
  | 'bounded_local_write'
  | 'verified_local_execution'
  | 'human_approved_external_effect'
  | 'prohibited';

export interface RiskTierPolicyRule {
  readonly tier: RiskTier;
  readonly autonomy: RiskAutonomyLevel;
  readonly requiresHumanApproval: boolean;
  readonly requiresIndependentVerification: boolean;
  readonly prohibited: boolean;
  readonly allowedInReadOnly: boolean;
  readonly description: string;
}

export const RISK_TIER_POLICY_MATRIX: Readonly<Record<RiskTier, RiskTierPolicyRule>> = {
  R0: {
    tier: 'R0',
    autonomy: 'autonomous_read',
    requiresHumanApproval: false,
    requiresIndependentVerification: false,
    prohibited: false,
    allowedInReadOnly: true,
    description: 'Read-only inspection, retrieval, status checks, and dry-run analysis.',
  },
  R1: {
    tier: 'R1',
    autonomy: 'bounded_local_write',
    requiresHumanApproval: false,
    requiresIndependentVerification: true,
    prohibited: false,
    allowedInReadOnly: false,
    description: 'Reversible local file write within an isolated worktree or owned scope.',
  },
  R2: {
    tier: 'R2',
    autonomy: 'verified_local_execution',
    requiresHumanApproval: false,
    requiresIndependentVerification: true,
    prohibited: false,
    allowedInReadOnly: false,
    description: 'Local command execution, test runner, local git commit, or DAG state transition.',
  },
  R3: {
    tier: 'R3',
    autonomy: 'human_approved_external_effect',
    requiresHumanApproval: true,
    requiresIndependentVerification: true,
    prohibited: false,
    allowedInReadOnly: false,
    description: 'Remote push, external network egress, webhook dispatch, or production deployment.',
  },
  R4: {
    tier: 'R4',
    autonomy: 'prohibited',
    requiresHumanApproval: true,
    requiresIndependentVerification: true,
    prohibited: true,
    allowedInReadOnly: false,
    description:
      'Prohibited destructive or governance-bypass action: secret exfiltration, protected hook/env edits, unrestricted shell.',
  },
};

export interface CapabilityGrant {
  readonly grantId: string;
  readonly principalId: string;
  readonly capabilities: readonly string[];
  readonly maxRiskTier: RiskTier;
  readonly allowedClassifications: readonly DataClassification[];
  readonly allowedPaths?: readonly string[];
  readonly expiresAt?: string;
  readonly revoked?: boolean;
}

export interface ApprovalToken {
  readonly tokenId: string;
  readonly issuerId: string;
  readonly approvedByRole: string;
  readonly actionDigest: string;
  readonly riskTier: RiskTier;
  readonly expiresAt: string;
  readonly singleUse: boolean;
  readonly revoked?: boolean;
}

export type RiskDenyReasonCode =
  | 'EMERGENCY_STOP_ACTIVE'
  | 'INVALID_DATA_CLASSIFICATION'
  | 'PROHIBITED_RISK_TIER_R4'
  | 'PROTECTED_PATH_BLOCKED'
  | 'UNSAFE_PATH_BLOCKED'
  | 'LOCAL_ONLY_EGRESS_BLOCKED'
  | 'READ_ONLY_MODE_DENIED'
  | 'MISSING_CAPABILITY_GRANT'
  | 'GRANT_REVOKED'
  | 'GRANT_EXPIRED'
  | 'GRANT_PRINCIPAL_MISMATCH'
  | 'CAPABILITY_NOT_GRANTED'
  | 'RISK_TIER_EXCEEDS_GRANT'
  | 'CLASSIFICATION_NOT_GRANTED'
  | 'PATH_OUTSIDE_GRANT_SCOPE'
  | 'HUMAN_APPROVAL_REQUIRED'
  | 'INVALID_APPROVAL_TOKEN'
  | 'APPROVAL_TOKEN_ALREADY_CONSUMED';

export interface RiskEvaluationInput {
  readonly principalId: string;
  readonly action: string;
  readonly capability: string;
  readonly requestedTier?: RiskTier;
  readonly dataClassification: DataClassificationInput | string;
  readonly targetZone?: TargetZone;
  readonly targetPaths?: readonly string[];
  readonly grant?: CapabilityGrant;
  readonly requireGrant?: boolean;
  readonly approvalToken?: ApprovalToken;
  readonly actionDigest?: string;
  readonly readOnlyMode?: boolean;
  readonly requireApprovalForR2?: boolean;
  readonly emergencyStopActive?: boolean;
  readonly approvalRegistry?: SingleUseApprovalRegistry;
  readonly nowMs?: number;
}

export interface RiskEvaluationDecision {
  readonly allowed: boolean;
  readonly decision: 'allow' | 'require_human_approval' | 'deny';
  readonly effectiveRiskTier: RiskTier;
  readonly dataClassification: DataClassification;
  readonly targetZone: TargetZone;
  readonly reasonCodes: readonly RiskDenyReasonCode[];
  readonly messages: readonly string[];
  readonly requiresIndependentVerification: boolean;
  readonly requiresHumanApproval: boolean;
  readonly verifiedGrantId?: string;
  readonly verifiedApprovalTokenId?: string;
  readonly evaluatedAt: string;
  readonly decisionSha256: string;
}

export class SingleUseApprovalRegistry {
  private readonly consumedTokens = new Set<string>();

  hasConsumed(tokenId: string): boolean {
    return this.consumedTokens.has(tokenId);
  }

  consume(tokenId: string): boolean {
    if (this.consumedTokens.has(tokenId)) {
      return false;
    }
    this.consumedTokens.add(tokenId);
    return true;
  }

  size(): number {
    return this.consumedTokens.size;
  }
}

const WINDOWS_DRIVE_PREFIX_REGEX = /^[A-Za-z]:(?:\/|$)/u;
const SECRET_FILE_EXTENSION_REGEX = /\.(?:pem|key|p12|pfx)$/iu;
const PROTECTED_PATH_EXACT = new Set<string>([
  '.github/CODEOWNERS',
  '.agents/rules/autonomous-git-release-lock.md',
  '.github/workflows/promote.yml',
  '.github/workflows/sync-main-to-dev.yml',
  '.github/workflows/promotion-policy.yml',
  '.github/workflows/release-orchestrate.yml',
  '.github/workflows/release-prepare.yml',
  '.github/workflows/release.yml',
  'scripts/setup-git-hooks.mjs',
  'scripts/sync-main-to-dev.mjs',
  'scripts/release-orchestrator.mjs',
  'scripts/release-plan.mjs',
]);

const PROTECTED_SEGMENTS = [
  /^\.githooks$/iu,
  /^\.git$/iu,
  /^\.env(?:\..+)?$/iu,
  /^id_rsa(?:\..+)?$/iu,
  /^credentials(?:\..+)?$/iu,
  /^secrets(?:\..+)?$/iu,
];

const PROHIBITED_ACTIONS = new Set<string>([
  'secret_read',
  'secret_exfiltrate',
  'live_policy_self_modify',
  'superadmin_impersonation',
  'unrestricted_shell',
  'git_force_push',
  'rm_rf_root',
]);

const R3_PHRASES = new Set<string>([
  'git_push',
  'remote_push',
  'external_http',
  'cloud_egress',
]);
const R3_TOKENS = new Set<string>(['deploy', 'webhook', 'publish', 'release', 'egress']);

const R2_PHRASES = new Set<string>([
  'run_command',
  'git_commit',
  'test_run',
  'workflow_transition',
]);
const R2_TOKENS = new Set<string>(['exec', 'shell', 'commit', 'build', 'command']);

const R1_PHRASES = new Set<string>(['update_file', 'delete_local']);
const R1_TOKENS = new Set<string>(['write', 'edit', 'create', 'patch', 'append', 'modify', 'delete']);

const R0_TOKENS = new Set<string>([
  'read',
  'list',
  'search',
  'inspect',
  'validate',
  'status',
  'health',
  'diff',
  'plan',
]);

function compareAscii(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

export function normalizePosixPath(rawPath: string): string {
  const trimmed = rawPath.trim().replaceAll('\\', '/');
  if (trimmed === '.' || trimmed === './') {
    return '.';
  }
  let normalized = trimmed;
  while (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }
  while (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export function isUnsafePath(rawPath: string): boolean {
  const trimmed = rawPath.trim();
  if (trimmed.length === 0) return true;
  const slashed = trimmed.replaceAll('\\', '/');
  if (
    trimmed.startsWith('/') ||
    trimmed.startsWith('\\') ||
    slashed.startsWith('/') ||
    WINDOWS_DRIVE_PREFIX_REGEX.test(slashed)
  ) {
    return true;
  }
  const normalized = normalizePosixPath(slashed);
  if (normalized.length === 0) return true;
  return normalized.split('/').some((segment) => segment === '..');
}

export function isProtectedPath(rawPath: string): boolean {
  const normalized = normalizePosixPath(rawPath);
  if (PROTECTED_PATH_EXACT.has(normalized)) {
    return true;
  }
  const segments = normalized.split('/');
  for (const segment of segments) {
    if (PROTECTED_SEGMENTS.some((pattern) => pattern.test(segment))) {
      return true;
    }
    if (SECRET_FILE_EXTENSION_REGEX.test(segment)) {
      return true;
    }
  }
  return false;
}

export function normalizeDataClassification(value: string): DataClassification | null {
  if (value === 'local_only' || value === 'local-only') {
    return 'local_only';
  }
  if (value === 'cloud_eligible' || value === 'cloud-eligible') {
    return 'cloud_eligible';
  }
  return null;
}

export function classifyActionRiskTier(
  action: string,
  targetPaths: readonly string[] = []
): RiskTier {
  const normalizedAction = action.trim().toLowerCase();
  const normalizedSnake = normalizedAction.replace(/[^a-z0-9]+/gu, '_').replace(/^_+|_+$/gu, '');
  const tokens = normalizedSnake.length > 0 ? normalizedSnake.split('_') : [];

  if (PROHIBITED_ACTIONS.has(normalizedAction) || PROHIBITED_ACTIONS.has(normalizedSnake)) {
    return 'R4';
  }
  for (const targetPath of targetPaths) {
    if (isUnsafePath(targetPath) || isProtectedPath(targetPath)) {
      return 'R4';
    }
  }

  if (R3_PHRASES.has(normalizedSnake) || tokens.some((token) => R3_TOKENS.has(token))) {
    return 'R3';
  }
  if (R2_PHRASES.has(normalizedSnake) || tokens.some((token) => R2_TOKENS.has(token))) {
    return 'R2';
  }
  if (R1_PHRASES.has(normalizedSnake) || tokens.some((token) => R1_TOKENS.has(token))) {
    return 'R1';
  }
  if (tokens.some((token) => R0_TOKENS.has(token))) {
    return 'R0';
  }

  // Fail-closed: unknown actions escalate to R3 (human approval required).
  return 'R3';
}

export function matchesCapabilityPattern(grantedPattern: string, requestedCapability: string): boolean {
  const pattern = grantedPattern.trim();
  const requested = requestedCapability.trim();
  if (!pattern || !requested) return false;
  if (pattern === '*' || pattern === requested) return true;
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1);
    return requested.startsWith(prefix);
  }
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return requested.startsWith(prefix);
  }
  return false;
}

function stripGlobSuffix(pattern: string): { readonly prefix: string; readonly hasGlob: boolean } {
  const normalized = normalizePosixPath(pattern);
  const globIndex = normalized.search(/[*?[]/u);
  if (globIndex === -1) {
    return { prefix: normalized, hasGlob: false };
  }
  const beforeGlob = normalized.slice(0, globIndex);
  const lastSlash = beforeGlob.lastIndexOf('/');
  const prefix = lastSlash === -1 ? '.' : normalizePosixPath(beforeGlob.slice(0, lastSlash));
  return { prefix: prefix.length > 0 ? prefix : '.', hasGlob: true };
}

export function pathWithinScope(targetPath: string, allowedScope: string): boolean {
  const normTarget = normalizePosixPath(targetPath);
  const { prefix, hasGlob } = stripGlobSuffix(allowedScope);
  if (prefix === '.') {
    return true;
  }
  if (!hasGlob) {
    return normTarget === prefix || normTarget.startsWith(`${prefix}/`);
  }
  return normTarget === prefix || normTarget.startsWith(`${prefix}/`);
}

function isNonHumanRole(role: string): boolean {
  const lowered = role.trim().toLowerCase();
  return (
    lowered.length === 0 ||
    lowered === 'agent' ||
    lowered === 'service_account' ||
    lowered === 'system' ||
    lowered === 'bot'
  );
}

function maxRiskTier(a: RiskTier, b: RiskTier): RiskTier {
  return RISK_TIER_ORDER[a] >= RISK_TIER_ORDER[b] ? a : b;
}

export function evaluateRiskPolicy(input: RiskEvaluationInput): RiskEvaluationDecision {
  const nowMs = input.nowMs ?? Date.now();
  const targetZone: TargetZone = input.targetZone ?? 'local';
  const targetPaths = input.targetPaths ?? [];
  const reasonCodes: RiskDenyReasonCode[] = [];
  const messages: string[] = [];

  const normalizedClassification = normalizeDataClassification(input.dataClassification);
  const effectiveClassification: DataClassification = normalizedClassification ?? 'local_only';

  const inferredTier = classifyActionRiskTier(input.action, targetPaths);
  const effectiveRiskTier: RiskTier =
    input.requestedTier !== undefined
      ? maxRiskTier(input.requestedTier, inferredTier)
      : inferredTier;

  const rule = RISK_TIER_POLICY_MATRIX[effectiveRiskTier];
  const needsHumanApproval =
    rule.requiresHumanApproval ||
    (effectiveRiskTier === 'R2' && input.requireApprovalForR2 === true);

  let verifiedGrantId: string | undefined;
  let verifiedApprovalTokenId: string | undefined;

  if (normalizedClassification === null) {
    reasonCodes.push('INVALID_DATA_CLASSIFICATION');
    messages.push(
      `Invalid data classification "${input.dataClassification}"; expected "local_only" or "cloud_eligible".`
    );
  }

  if (input.emergencyStopActive === true) {
    reasonCodes.push('EMERGENCY_STOP_ACTIVE');
    messages.push('Emergency stop is active; all agent actions are blocked.');
  }

  for (const pathCandidate of targetPaths) {
    if (isUnsafePath(pathCandidate)) {
      if (!reasonCodes.includes('UNSAFE_PATH_BLOCKED')) {
        reasonCodes.push('UNSAFE_PATH_BLOCKED');
      }
      messages.push(`Unsafe or traversal path blocked: "${pathCandidate}".`);
    } else if (isProtectedPath(pathCandidate)) {
      if (!reasonCodes.includes('PROTECTED_PATH_BLOCKED')) {
        reasonCodes.push('PROTECTED_PATH_BLOCKED');
      }
      messages.push(`Protected governance/secret path blocked: "${pathCandidate}".`);
    }
  }

  if (rule.prohibited) {
    reasonCodes.push('PROHIBITED_RISK_TIER_R4');
    messages.push(`Risk tier R4 is unconditionally prohibited: ${rule.description}`);
  }

  if (effectiveClassification === 'local_only' && targetZone === 'cloud') {
    reasonCodes.push('LOCAL_ONLY_EGRESS_BLOCKED');
    messages.push('DataClassification "local_only" strictly forbids cloud egress.');
  }

  if (input.readOnlyMode === true && !rule.allowedInReadOnly) {
    reasonCodes.push('READ_ONLY_MODE_DENIED');
    messages.push(`Risk tier ${effectiveRiskTier} is denied in read-only execution mode.`);
  }

  // Capability grant enforcement
  const shouldRequireGrant = input.requireGrant ?? (input.grant !== undefined);
  if (input.grant === undefined) {
    if (shouldRequireGrant) {
      reasonCodes.push('MISSING_CAPABILITY_GRANT');
      messages.push(`Principal "${input.principalId}" is missing a capability grant for "${input.capability}".`);
    }
  } else {
    const grant = input.grant;
    let grantValid = true;
    if (grant.revoked === true) {
      grantValid = false;
      reasonCodes.push('GRANT_REVOKED');
      messages.push(`Capability grant "${grant.grantId}" has been revoked.`);
    }
    if (grant.principalId !== input.principalId) {
      grantValid = false;
      reasonCodes.push('GRANT_PRINCIPAL_MISMATCH');
      messages.push(
        `Capability grant "${grant.grantId}" belongs to "${grant.principalId}", not "${input.principalId}".`
      );
    }
    if (grant.expiresAt !== undefined) {
      const grantExpiresMs = Date.parse(grant.expiresAt);
      if (!Number.isFinite(grantExpiresMs) || grantExpiresMs <= nowMs) {
        grantValid = false;
        reasonCodes.push('GRANT_EXPIRED');
        messages.push(`Capability grant "${grant.grantId}" expired at ${grant.expiresAt}.`);
      }
    }
    const capabilityMatched = grant.capabilities.some((pattern) =>
      matchesCapabilityPattern(pattern, input.capability)
    );
    if (!capabilityMatched) {
      grantValid = false;
      reasonCodes.push('CAPABILITY_NOT_GRANTED');
      messages.push(
        `Capability "${input.capability}" is not permitted by grant "${grant.grantId}".`
      );
    }
    if (RISK_TIER_ORDER[effectiveRiskTier] > RISK_TIER_ORDER[grant.maxRiskTier]) {
      grantValid = false;
      reasonCodes.push('RISK_TIER_EXCEEDS_GRANT');
      messages.push(
        `Effective risk tier ${effectiveRiskTier} exceeds grant ceiling ${grant.maxRiskTier}.`
      );
    }
    if (!grant.allowedClassifications.includes(effectiveClassification)) {
      grantValid = false;
      reasonCodes.push('CLASSIFICATION_NOT_GRANTED');
      messages.push(
        `Data classification "${effectiveClassification}" is not permitted by grant "${grant.grantId}".`
      );
    }
    if (grant.allowedPaths !== undefined && targetPaths.length > 0) {
      for (const targetPath of targetPaths) {
        if (isUnsafePath(targetPath)) continue;
        const allowed = grant.allowedPaths.some((scope) => pathWithinScope(targetPath, scope));
        if (!allowed) {
          grantValid = false;
          if (!reasonCodes.includes('PATH_OUTSIDE_GRANT_SCOPE')) {
            reasonCodes.push('PATH_OUTSIDE_GRANT_SCOPE');
          }
          messages.push(
            `Target path "${targetPath}" is outside capability grant "${grant.grantId}" allowedPaths.`
          );
        }
      }
    }
    if (grantValid) {
      verifiedGrantId = grant.grantId;
    }
  }

  // Hard deny checks take precedence over human approval prompts.
  const hasHardDeny = reasonCodes.length > 0;
  let decision: 'allow' | 'require_human_approval' | 'deny' = hasHardDeny ? 'deny' : 'allow';

  if (!hasHardDeny && needsHumanApproval) {
    if (!input.approvalToken) {
      decision = 'require_human_approval';
      reasonCodes.push('HUMAN_APPROVAL_REQUIRED');
      messages.push(`Risk tier ${effectiveRiskTier} requires a valid human approval token.`);
    } else {
      const token = input.approvalToken;
      let tokenValid = true;
      if (token.revoked === true) {
        tokenValid = false;
        reasonCodes.push('INVALID_APPROVAL_TOKEN');
        messages.push(`Approval token "${token.tokenId}" has been revoked.`);
      }
      if (isNonHumanRole(token.approvedByRole)) {
        tokenValid = false;
        reasonCodes.push('INVALID_APPROVAL_TOKEN');
        messages.push(`Approval token requires a human role; got "${token.approvedByRole}".`);
      }
      if (RISK_TIER_ORDER[token.riskTier] < RISK_TIER_ORDER[effectiveRiskTier]) {
        tokenValid = false;
        reasonCodes.push('INVALID_APPROVAL_TOKEN');
        messages.push(
          `Approval token tier ${token.riskTier} does not cover required tier ${effectiveRiskTier}.`
        );
      }
      if (input.actionDigest !== undefined && token.actionDigest !== input.actionDigest) {
        tokenValid = false;
        reasonCodes.push('INVALID_APPROVAL_TOKEN');
        messages.push('Approval token actionDigest does not match requested actionDigest.');
      }
      const tokenExpiresMs = Date.parse(token.expiresAt);
      if (!Number.isFinite(tokenExpiresMs) || tokenExpiresMs <= nowMs) {
        tokenValid = false;
        reasonCodes.push('INVALID_APPROVAL_TOKEN');
        messages.push(`Approval token "${token.tokenId}" is expired.`);
      }
      if (tokenValid && token.singleUse && input.approvalRegistry !== undefined) {
        const consumed = input.approvalRegistry.consume(token.tokenId);
        if (!consumed) {
          tokenValid = false;
          reasonCodes.push('APPROVAL_TOKEN_ALREADY_CONSUMED');
          messages.push(`Single-use approval token "${token.tokenId}" has already been consumed.`);
        }
      }

      if (tokenValid) {
        decision = 'allow';
        verifiedApprovalTokenId = token.tokenId;
      } else {
        decision = 'deny';
      }
    }
  }

  const allowed = decision === 'allow';
  const base = {
    allowed,
    decision,
    effectiveRiskTier,
    dataClassification: effectiveClassification,
    targetZone,
    reasonCodes,
    messages,
    requiresIndependentVerification: rule.requiresIndependentVerification,
    requiresHumanApproval: needsHumanApproval,
    ...(verifiedGrantId !== undefined ? { verifiedGrantId } : {}),
    ...(verifiedApprovalTokenId !== undefined ? { verifiedApprovalTokenId } : {}),
    evaluatedAt: new Date(nowMs).toISOString(),
  };

  return {
    ...base,
    decisionSha256: sha256Hex(canonicalStringify(base)),
  };
}

// ---------------------------------------------------------------------------
// Disjoint Multi-Agent File Ownership Overlap Detector
// ---------------------------------------------------------------------------

export interface AgentOwnershipClaim {
  readonly agentId: string;
  readonly taskId?: string;
  readonly writePaths: readonly string[];
  readonly readPaths?: readonly string[];
}

export type OwnershipConflictKind =
  | 'write_write'
  | 'write_parent_child'
  | 'read_write'
  | 'protected_path'
  | 'unsafe_path';

export interface OwnershipConflict {
  readonly kind: OwnershipConflictKind;
  readonly severity: 'blocking' | 'warning';
  readonly agents: readonly string[];
  readonly pathA: string;
  readonly pathB: string;
  readonly message: string;
}

export interface DisjointOwnershipOptions {
  readonly allowProtectedPaths?: boolean;
}

export interface DisjointOwnershipReport {
  readonly disjoint: boolean;
  readonly agentCount: number;
  readonly totalWritePaths: number;
  readonly blockingConflictCount: number;
  readonly warningCount: number;
  readonly conflicts: readonly OwnershipConflict[];
  readonly normalizedClaims: Readonly<Record<string, readonly string[]>>;
  readonly reportSha256: string;
}

function classifyPathOverlap(pathA: string, pathB: string): 'exact' | 'parent_child' | 'none' {
  const normA = normalizePosixPath(pathA);
  const normB = normalizePosixPath(pathB);
  if (!normA || !normB) return 'none';
  if (normA === normB) return 'exact';

  const globA = stripGlobSuffix(normA);
  const globB = stripGlobSuffix(normB);

  if (globA.prefix === '.' || globB.prefix === '.') {
    return 'parent_child';
  }
  if (
    globA.prefix === globB.prefix &&
    (globA.hasGlob || globB.hasGlob)
  ) {
    return 'parent_child';
  }
  if (
    globA.prefix.startsWith(`${globB.prefix}/`) ||
    globB.prefix.startsWith(`${globA.prefix}/`)
  ) {
    return 'parent_child';
  }

  return 'none';
}

export function checkDisjointOwnership(
  claims: readonly AgentOwnershipClaim[],
  options: DisjointOwnershipOptions = {}
): DisjointOwnershipReport {
  const allowProtectedPaths = options.allowProtectedPaths ?? false;
  const conflicts: OwnershipConflict[] = [];
  const normalizedClaims: Record<string, string[]> = {};
  let totalWritePaths = 0;

  const sortedClaims = [...claims].sort((a, b) => compareAscii(a.agentId, b.agentId));

  for (const claim of sortedClaims) {
    const normalizedWrites: string[] = [];
    for (const rawPath of claim.writePaths) {
      totalWritePaths += 1;
      if (isUnsafePath(rawPath)) {
        conflicts.push({
          kind: 'unsafe_path',
          severity: 'blocking',
          agents: [claim.agentId],
          pathA: rawPath,
          pathB: rawPath,
          message: `Agent "${claim.agentId}" claimed unsafe or traversal path "${rawPath}".`,
        });
        continue;
      }

      const normalized = normalizePosixPath(rawPath);
      normalizedWrites.push(normalized);

      if (!allowProtectedPaths && isProtectedPath(normalized)) {
        conflicts.push({
          kind: 'protected_path',
          severity: 'blocking',
          agents: [claim.agentId],
          pathA: normalized,
          pathB: normalized,
          message: `Agent "${claim.agentId}" claimed protected path "${normalized}".`,
        });
      }
    }
    normalizedClaims[claim.agentId] = [...new Set(normalizedWrites)].sort(compareAscii);
  }

  for (let i = 0; i < sortedClaims.length; i += 1) {
    const claimA = sortedClaims[i];
    if (!claimA) continue;
    const writesA = normalizedClaims[claimA.agentId] ?? [];

    for (let j = i + 1; j < sortedClaims.length; j += 1) {
      const claimB = sortedClaims[j];
      if (!claimB) continue;
      if (claimA.agentId === claimB.agentId) continue;

      const writesB = normalizedClaims[claimB.agentId] ?? [];

      for (const pathA of writesA) {
        for (const pathB of writesB) {
          const overlap = classifyPathOverlap(pathA, pathB);
          if (overlap === 'exact') {
            conflicts.push({
              kind: 'write_write',
              severity: 'blocking',
              agents: [claimA.agentId, claimB.agentId],
              pathA,
              pathB,
              message: `Disjoint write violation: "${claimA.agentId}" and "${claimB.agentId}" both own "${pathA}".`,
            });
          } else if (overlap === 'parent_child') {
            conflicts.push({
              kind: 'write_parent_child',
              severity: 'blocking',
              agents: [claimA.agentId, claimB.agentId],
              pathA,
              pathB,
              message: `Overlapping directory/glob ownership between "${claimA.agentId}" ("${pathA}") and "${claimB.agentId}" ("${pathB}").`,
            });
          }
        }
      }

      // Read-write cross-agent advisory warnings
      const readsB = (claimB.readPaths ?? [])
        .filter((entry) => !isUnsafePath(entry))
        .map(normalizePosixPath);
      for (const pathA of writesA) {
        for (const readB of readsB) {
          if (classifyPathOverlap(pathA, readB) !== 'none') {
            conflicts.push({
              kind: 'read_write',
              severity: 'warning',
              agents: [claimA.agentId, claimB.agentId],
              pathA,
              pathB: readB,
              message: `Agent "${claimB.agentId}" reads "${readB}" while "${claimA.agentId}" writes "${pathA}"; sequence via DAG dependency.`,
            });
          }
        }
      }

      const readsA = (claimA.readPaths ?? [])
        .filter((entry) => !isUnsafePath(entry))
        .map(normalizePosixPath);
      for (const pathB of writesB) {
        for (const readA of readsA) {
          if (classifyPathOverlap(pathB, readA) !== 'none') {
            conflicts.push({
              kind: 'read_write',
              severity: 'warning',
              agents: [claimB.agentId, claimA.agentId],
              pathA: pathB,
              pathB: readA,
              message: `Agent "${claimA.agentId}" reads "${readA}" while "${claimB.agentId}" writes "${pathB}"; sequence via DAG dependency.`,
            });
          }
        }
      }
    }
  }

  conflicts.sort(
    (a, b) =>
      compareAscii(a.severity, b.severity) ||
      compareAscii(a.kind, b.kind) ||
      compareAscii(a.agents.join(','), b.agents.join(',')) ||
      compareAscii(a.pathA, b.pathA) ||
      compareAscii(a.pathB, b.pathB)
  );

  const blockingConflictCount = conflicts.filter((item) => item.severity === 'blocking').length;
  const warningCount = conflicts.filter((item) => item.severity === 'warning').length;

  const reportBase = {
    disjoint: blockingConflictCount === 0,
    agentCount: sortedClaims.length,
    totalWritePaths,
    blockingConflictCount,
    warningCount,
    conflicts,
    normalizedClaims,
  };

  return {
    ...reportBase,
    reportSha256: sha256Hex(canonicalStringify(reportBase)),
  };
}

export const detectSwarmFileOverlap = checkDisjointOwnership;
