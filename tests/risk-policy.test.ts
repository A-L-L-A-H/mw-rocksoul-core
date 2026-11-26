import { describe, expect, test } from 'bun:test';
import { sha256Hex } from '../src/merkle-pcw.js';
import {
  checkDisjointOwnership,
  classifyActionRiskTier,
  evaluateRiskPolicy,
  SingleUseApprovalRegistry,
  type ApprovalToken,
  type CapabilityGrant,
} from '../src/risk-policy.js';

const BASE_NOW_MS = Date.parse('2026-11-27T05:00:00.000Z');

describe('risk-policy', () => {
  test('classifies actions and protected paths into deterministic R0-R4 tiers', () => {
    expect(classifyActionRiskTier('repo_read', ['src/index.ts'])).toBe('R0');
    expect(classifyActionRiskTier('file_write', ['src/index.ts'])).toBe('R1');
    expect(classifyActionRiskTier('test_run', ['tests/a.test.ts'])).toBe('R2');
    expect(classifyActionRiskTier('git_push', ['src/index.ts'])).toBe('R3');
    expect(classifyActionRiskTier('unrestricted_shell')).toBe('R4');
    expect(classifyActionRiskTier('file_write', ['.githooks/pre-commit'])).toBe('R4');
    expect(classifyActionRiskTier('file_read', ['.env.production'])).toBe('R4');
    expect(classifyActionRiskTier('file_read', ['../escape.txt'])).toBe('R4');
    expect(classifyActionRiskTier('mystery_unlisted_op')).toBe('R3');
    expect(classifyActionRiskTier('spreadsheet_export')).toBe('R3');
  });

  test('enforces local_only air-gap, R4 prohibition, read-only mode, and emergency stop', () => {
    const cloudBlocked = evaluateRiskPolicy({
      principalId: 'agent-1',
      action: 'repo_read',
      capability: 'repo.read',
      requestedTier: 'R0',
      dataClassification: 'local_only',
      targetZone: 'cloud',
      nowMs: BASE_NOW_MS,
    });
    expect(cloudBlocked.allowed).toBe(false);
    expect(cloudBlocked.decision).toBe('deny');
    expect(cloudBlocked.reasonCodes).toContain('LOCAL_ONLY_EGRESS_BLOCKED');

    const localAllowed = evaluateRiskPolicy({
      principalId: 'agent-1',
      action: 'repo_read',
      capability: 'repo.read',
      requestedTier: 'R0',
      dataClassification: 'local_only',
      targetZone: 'local',
      nowMs: BASE_NOW_MS,
    });
    expect(localAllowed.allowed).toBe(true);
    expect(localAllowed.decision).toBe('allow');

    const r4Protected = evaluateRiskPolicy({
      principalId: 'agent-1',
      action: 'file_edit',
      capability: 'repo.write',
      requestedTier: 'R1',
      dataClassification: 'local_only',
      targetPaths: ['.github/CODEOWNERS'],
      nowMs: BASE_NOW_MS,
    });
    expect(r4Protected.allowed).toBe(false);
    expect(r4Protected.effectiveRiskTier).toBe('R4');
    expect(r4Protected.reasonCodes).toContain('PROTECTED_PATH_BLOCKED');
    expect(r4Protected.reasonCodes).toContain('PROHIBITED_RISK_TIER_R4');

    const readOnlyDenied = evaluateRiskPolicy({
      principalId: 'agent-1',
      action: 'file_write',
      capability: 'repo.write',
      requestedTier: 'R1',
      dataClassification: 'local_only',
      readOnlyMode: true,
      nowMs: BASE_NOW_MS,
    });
    expect(readOnlyDenied.allowed).toBe(false);
    expect(readOnlyDenied.reasonCodes).toContain('READ_ONLY_MODE_DENIED');

    const emergencyDenied = evaluateRiskPolicy({
      principalId: 'agent-1',
      action: 'repo_read',
      capability: 'repo.read',
      requestedTier: 'R0',
      dataClassification: 'cloud_eligible',
      emergencyStopActive: true,
      nowMs: BASE_NOW_MS,
    });
    expect(emergencyDenied.allowed).toBe(false);
    expect(emergencyDenied.reasonCodes).toContain('EMERGENCY_STOP_ACTIVE');
  });

  test('validates CapabilityGrant principal, wildcard scope, expiry, tier ceiling, classification, and paths', () => {
    const validGrant: CapabilityGrant = {
      grantId: 'grant-1',
      principalId: 'agent-core',
      capabilities: ['repo.*', 'tests.run'],
      maxRiskTier: 'R2',
      allowedClassifications: ['local_only'],
      allowedPaths: ['src/**', 'tests/unit.test.ts'],
      expiresAt: '2026-11-28T00:00:00.000Z',
    };

    const allowed = evaluateRiskPolicy({
      principalId: 'agent-core',
      action: 'file_write',
      capability: 'repo.write',
      requestedTier: 'R1',
      dataClassification: 'local_only',
      targetPaths: ['src/dag-engine.ts'],
      grant: validGrant,
      nowMs: BASE_NOW_MS,
    });
    expect(allowed.allowed).toBe(true);
    expect(allowed.verifiedGrantId).toBe('grant-1');

    const outOfScope = evaluateRiskPolicy({
      principalId: 'agent-core',
      action: 'file_write',
      capability: 'repo.write',
      requestedTier: 'R1',
      dataClassification: 'local_only',
      targetPaths: ['scripts/deploy.sh'],
      grant: validGrant,
      nowMs: BASE_NOW_MS,
    });
    expect(outOfScope.allowed).toBe(false);
    expect(outOfScope.reasonCodes).toContain('PATH_OUTSIDE_GRANT_SCOPE');

    const expiredAndWrongPrincipal = evaluateRiskPolicy({
      principalId: 'other-agent',
      action: 'git_push',
      capability: 'git.push',
      requestedTier: 'R3',
      dataClassification: 'cloud_eligible',
      targetZone: 'cloud',
      grant: { ...validGrant, revoked: true, expiresAt: '2026-11-26T00:00:00.000Z' },
      nowMs: BASE_NOW_MS,
    });
    expect(expiredAndWrongPrincipal.allowed).toBe(false);
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('GRANT_REVOKED');
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('GRANT_PRINCIPAL_MISMATCH');
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('GRANT_EXPIRED');
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('CAPABILITY_NOT_GRANTED');
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('RISK_TIER_EXCEEDS_GRANT');
    expect(expiredAndWrongPrincipal.reasonCodes).toContain('CLASSIFICATION_NOT_GRANTED');
  });

  test('enforces R3 human approval tokens and single-use replay protection', () => {
    const registry = new SingleUseApprovalRegistry();
    const digest = sha256Hex('push:main');

    const needsApproval = evaluateRiskPolicy({
      principalId: 'agent-release',
      action: 'git_push',
      capability: 'git.push',
      requestedTier: 'R3',
      dataClassification: 'cloud_eligible',
      targetZone: 'cloud',
      actionDigest: digest,
      approvalRegistry: registry,
      nowMs: BASE_NOW_MS,
    });
    expect(needsApproval.allowed).toBe(false);
    expect(needsApproval.decision).toBe('require_human_approval');
    expect(needsApproval.reasonCodes).toContain('HUMAN_APPROVAL_REQUIRED');

    const agentRoleToken: ApprovalToken = {
      tokenId: 'tok-bot',
      issuerId: 'agent-self',
      approvedByRole: 'agent',
      actionDigest: digest,
      riskTier: 'R3',
      expiresAt: '2026-11-28T00:00:00.000Z',
      singleUse: true,
    };
    const nonHumanDenied = evaluateRiskPolicy({
      principalId: 'agent-release',
      action: 'git_push',
      capability: 'git.push',
      requestedTier: 'R3',
      dataClassification: 'cloud_eligible',
      targetZone: 'cloud',
      actionDigest: digest,
      approvalToken: agentRoleToken,
      approvalRegistry: registry,
      nowMs: BASE_NOW_MS,
    });
    expect(nonHumanDenied.allowed).toBe(false);
    expect(nonHumanDenied.decision).toBe('deny');
    expect(nonHumanDenied.reasonCodes).toContain('INVALID_APPROVAL_TOKEN');

    const humanToken: ApprovalToken = {
      tokenId: 'tok-human-1',
      issuerId: 'rid:owner',
      approvedByRole: 'owner',
      actionDigest: digest,
      riskTier: 'R3',
      expiresAt: '2026-11-28T00:00:00.000Z',
      singleUse: true,
    };

    const firstUse = evaluateRiskPolicy({
      principalId: 'agent-release',
      action: 'git_push',
      capability: 'git.push',
      requestedTier: 'R3',
      dataClassification: 'cloud_eligible',
      targetZone: 'cloud',
      actionDigest: digest,
      approvalToken: humanToken,
      approvalRegistry: registry,
      nowMs: BASE_NOW_MS,
    });
    expect(firstUse.allowed).toBe(true);
    expect(firstUse.verifiedApprovalTokenId).toBe('tok-human-1');

    const secondUseReplay = evaluateRiskPolicy({
      principalId: 'agent-release',
      action: 'git_push',
      capability: 'git.push',
      requestedTier: 'R3',
      dataClassification: 'cloud_eligible',
      targetZone: 'cloud',
      actionDigest: digest,
      approvalToken: humanToken,
      approvalRegistry: registry,
      nowMs: BASE_NOW_MS,
    });
    expect(secondUseReplay.allowed).toBe(false);
    expect(secondUseReplay.reasonCodes).toContain('APPROVAL_TOKEN_ALREADY_CONSUMED');
  });

  test('detects disjoint multi-agent ownership, write collisions, directory/glob overlap, protected paths, and read-write warnings', () => {
    const clean = checkDisjointOwnership([
      {
        agentId: 'rs-core',
        writePaths: ['src/dag-engine.ts', 'src/merkle-pcw.ts'],
        readPaths: ['package.json'],
      },
      {
        agentId: 'rs-cli',
        writePaths: ['cmd/rocksoul/main.go'],
        readPaths: ['src/dag-engine.ts'],
      },
    ]);
    expect(clean.disjoint).toBe(true);
    expect(clean.blockingConflictCount).toBe(0);
    expect(clean.warningCount).toBe(1);
    expect(clean.conflicts[0]?.kind).toBe('read_write');

    const colliding = checkDisjointOwnership([
      {
        agentId: 'agent-a',
        writePaths: ['src\\shared.ts', 'packages/core/**'],
      },
      {
        agentId: 'agent-b',
        writePaths: ['./src/shared.ts', 'packages/core/src/index.ts', '.env', '../outside.ts'],
      },
    ]);
    expect(colliding.disjoint).toBe(false);
    const kinds = colliding.conflicts.map((conflict) => conflict.kind);
    expect(kinds).toContain('write_write');
    expect(kinds).toContain('write_parent_child');
    expect(kinds).toContain('protected_path');
    expect(kinds).toContain('unsafe_path');
  });
});
