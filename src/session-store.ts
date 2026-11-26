import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

export interface TurnMessageMeta {
  readonly provider?: string;
  readonly model?: string;
  readonly cache?: string;
  readonly rtkTokensSaved?: number;
  readonly tokensIn?: number;
  readonly tokensOut?: number;
  readonly step?: number;
  readonly durationMs?: number;
  readonly isError?: boolean;
  readonly compacted?: boolean;
  readonly riskTier?: string;
}

export interface TurnToolCallFunction {
  readonly name: string;
  readonly arguments: string;
}

export interface TurnToolCall {
  readonly id: string;
  readonly type: string;
  readonly function: TurnToolCallFunction;
}

export interface SessionTurn {
  readonly id: string;
  readonly sessionId: string;
  readonly seq: number;
  readonly role: 'system' | 'user' | 'assistant' | 'tool';
  readonly content: string;
  readonly toolCalls?: TurnToolCall[];
  readonly toolCallId?: string;
  readonly toolName?: string;
  readonly meta?: TurnMessageMeta;
  readonly createdAt: string;
}

export interface WorkgraphNode {
  readonly id: string;
  readonly label: string;
  readonly status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  readonly dependencies?: string[];
  readonly payload?: Record<string, unknown>;
}

export interface WorkgraphEdge {
  readonly from: string;
  readonly to: string;
  readonly kind?: string;
}

export interface Workgraph {
  readonly nodes: WorkgraphNode[];
  readonly edges: WorkgraphEdge[];
}

export interface SessionRecord {
  readonly id: string;
  readonly title: string;
  readonly workDir: string;
  readonly project: string;
  readonly agentProfile: string;
  readonly model: string;
  readonly mode: string;
  readonly status: 'idle' | 'running' | 'completed' | 'error' | 'aborted';
  readonly totalTokensIn: number;
  readonly totalTokensOut: number;
  readonly rtkTokensSaved: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly parentSessionId?: string;
  readonly workgraph?: Workgraph;
}

export interface SessionCreateInput {
  readonly title?: string;
  readonly workDir?: string;
  readonly project?: string;
  readonly agentProfile?: string;
  readonly model?: string;
  readonly mode?: string;
  readonly workgraph?: Workgraph;
}

export interface SessionAppendTurnInput {
  readonly role: 'system' | 'user' | 'assistant' | 'tool';
  readonly content: string;
  readonly toolCalls?: TurnToolCall[];
  readonly toolCallId?: string;
  readonly toolName?: string;
  readonly meta?: TurnMessageMeta;
  readonly createdAt?: string;
}

export interface ForkSessionOptions {
  readonly newTitle?: string;
  readonly upToSeq?: number;
}

interface StoredSnapshot {
  readonly sessions: SessionRecord[];
  readonly turns: Record<string, SessionTurn[]>;
}

export class PersistentSessionStore {
  private readonly filePath: string;
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly turns = new Map<string, SessionTurn[]>();
  private isLoaded = false;
  private lockPromise: Promise<void> = Promise.resolve();

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
  }

  private async acquireLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void = () => {};
    const nextLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    const currentLock = this.lockPromise;
    this.lockPromise = (async () => {
      await currentLock;
      await nextLock;
    })();

    await currentLock;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private async ensureLoaded(): Promise<void> {
    if (this.isLoaded) return;
    try {
      const data = await readFile(this.filePath, 'utf8');
      if (data.trim().length > 0) {
        const parsed = JSON.parse(data) as StoredSnapshot;
        if (Array.isArray(parsed.sessions)) {
          for (const s of parsed.sessions) {
            this.sessions.set(s.id, s);
          }
        }
        if (parsed.turns && typeof parsed.turns === 'object') {
          for (const [k, v] of Object.entries(parsed.turns)) {
            if (Array.isArray(v)) {
              this.turns.set(k, v);
            }
          }
        }
      }
    } catch {
      // File missing or empty, brand new store
    }
    this.isLoaded = true;
  }

  private async flush(): Promise<void> {
    const snapshot: StoredSnapshot = {
      sessions: Array.from(this.sessions.values()),
      turns: Object.fromEntries(this.turns.entries()),
    };
    const dir = path.dirname(this.filePath);
    await mkdir(dir, { recursive: true });

    const tmpPath = `${this.filePath}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
    const serialized = `${JSON.stringify(snapshot, null, 2)}\n`;
    await writeFile(tmpPath, serialized, 'utf8');
    try {
      await rename(tmpPath, this.filePath);
    } catch (err) {
      await rm(tmpPath, { force: true }).catch(() => {});
      throw err;
    }
  }

  async createSession(input: SessionCreateInput = {}): Promise<SessionRecord> {
    return this.acquireLock(async () => {
      await this.ensureLoaded();
      const now = new Date().toISOString();
      const id = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
      const session: SessionRecord = {
        id,
        title: input.title?.trim() || 'New Session',
        workDir: input.workDir?.trim() || process.cwd(),
        project: input.project?.trim() || 'default',
        agentProfile: input.agentProfile?.trim() || 'rocksoul',
        model: input.model?.trim() || 'gemini-2.0-flash',
        mode: input.mode?.trim() || 'act',
        status: 'idle',
        totalTokensIn: 0,
        totalTokensOut: 0,
        rtkTokensSaved: 0,
        createdAt: now,
        updatedAt: now,
        ...(input.workgraph ? { workgraph: input.workgraph } : {}),
      };

      this.sessions.set(id, session);
      this.turns.set(id, []);
      await this.flush();
      return session;
    });
  }

  async getSession(sessionId: string): Promise<{ session: SessionRecord; turns: SessionTurn[] } | null> {
    return this.acquireLock(async () => {
      await this.ensureLoaded();
      const session = this.sessions.get(sessionId);
      if (!session) return null;
      const turns = this.turns.get(sessionId) ?? [];
      return { session: { ...session }, turns: [...turns] };
    });
  }

  async listSessions(limit = 100): Promise<SessionRecord[]> {
    return this.acquireLock(async () => {
      await this.ensureLoaded();
      const list = Array.from(this.sessions.values());
      list.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      return list.slice(0, Math.max(1, limit));
    });
  }

  async appendTurn(sessionId: string, input: SessionAppendTurnInput): Promise<SessionTurn> {
    return this.acquireLock(async () => {
      await this.ensureLoaded();
      const session = this.sessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const existingTurns = this.turns.get(sessionId) ?? [];
      const seq = existingTurns.length + 1;
      const now = input.createdAt ?? new Date().toISOString();
      const turnId = `turn_${sessionId}_${seq}`;

      const turn: SessionTurn = {
        id: turnId,
        sessionId,
        seq,
        role: input.role,
        content: input.content,
        ...(input.toolCalls ? { toolCalls: input.toolCalls } : {}),
        ...(input.toolCallId ? { toolCallId: input.toolCallId } : {}),
        ...(input.toolName ? { toolName: input.toolName } : {}),
        ...(input.meta ? { meta: input.meta } : {}),
        createdAt: now,
      };

      existingTurns.push(turn);
      this.turns.set(sessionId, existingTurns);

      const tokensIn = (input.meta?.tokensIn ?? 0) + session.totalTokensIn;
      const tokensOut = (input.meta?.tokensOut ?? 0) + session.totalTokensOut;
      const rtkTokensSaved = (input.meta?.rtkTokensSaved ?? 0) + session.rtkTokensSaved;

      const updatedSession: SessionRecord = {
        ...session,
        totalTokensIn: tokensIn,
        totalTokensOut: tokensOut,
        rtkTokensSaved,
        updatedAt: now,
      };
      this.sessions.set(sessionId, updatedSession);

      await this.flush();
      return turn;
    });
  }

  async forkSession(sessionId: string, options: ForkSessionOptions = {}): Promise<SessionRecord> {
    return this.acquireLock(async () => {
      await this.ensureLoaded();
      const origin = this.sessions.get(sessionId);
      if (!origin) {
        throw new Error(`Origin session not found: ${sessionId}`);
      }

      const now = new Date().toISOString();
      const forkedId = `sess_fork_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      const originalTurns = this.turns.get(sessionId) ?? [];
      const maxSeq = options.upToSeq ?? originalTurns.length;

      const turnsToCopy: SessionTurn[] = originalTurns
        .filter((t) => t.seq <= maxSeq)
        .map((t) => ({
          ...t,
          id: `turn_${forkedId}_${t.seq}`,
          sessionId: forkedId,
        }));

      const forkedSession: SessionRecord = {
        ...origin,
        id: forkedId,
        title: options.newTitle ?? `Fork of ${origin.title}`,
        parentSessionId: sessionId,
        status: 'idle',
        createdAt: now,
        updatedAt: now,
      };

      this.sessions.set(forkedId, forkedSession);
      this.turns.set(forkedId, turnsToCopy);
      await this.flush();

      return forkedSession;
    });
  }
}
