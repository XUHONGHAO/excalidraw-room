import http from "http";
import https from "https";
import { randomBytes, timingSafeEqual } from "crypto";

export const VAULT_PROTOCOL_VERSION = 1 as const;
export const VAULT_DEPLOYMENT_VERSION = "p4a-f4-v1" as const;
export const VAULT_ROOM_SERVER_VERSION = 1 as const;
export const VAULT_SOCKET_EVENTS = {
  join: "vault:join",
  server: "vault:server",
  serverVolatile: "vault:server-volatile",
  client: "vault:server",
  capabilityRevoked: "vault:capability-revoked",
  capabilityExpired: "vault:capability-expired",
} as const;

export type VaultRole = "viewer" | "editor";
export type VaultMessageType = "realtime.content" | "realtime.presence";
export type VaultDisconnectReason =
  | "revoked"
  | "expired"
  | "vault-revoked"
  | "vault-deleted";

export interface VaultSocketJoinRequest {
  protocolVersion: typeof VAULT_PROTOCOL_VERSION;
  vaultId: string;
  invitationCapability: string;
  senderSessionId: string;
}

export interface VaultRoomProvisionRequest {
  protocolVersion: typeof VAULT_PROTOCOL_VERSION;
  vaultId: string;
  invitationId: string;
}

export interface VaultRoomProvisionResponse {
  protocolVersion: typeof VAULT_PROTOCOL_VERSION;
  activeRoomId: string;
}

export interface VaultCapabilityResolution {
  vaultId: string;
  invitationId: string;
  role: VaultRole;
  authorizationVersion: number;
  activeRoomId: string;
  snapshotGeneration: number;
  expiresAt: number | null;
}

export interface VaultCapabilityDisconnectNotice {
  vaultId: string;
  invitationId: string;
  authorizationVersion: number;
  reason: VaultDisconnectReason;
}

export interface VaultWideDisconnectNotice {
  vaultId: string;
  reason: "vault-revoked" | "vault-deleted";
}

export interface VaultInvitationDisconnectNotice {
  vaultId: string;
  invitationId: string;
  authorizationVersion: number;
  reason: "revoked" | "expired";
}

export type VaultControlPlaneNotice =
  | VaultInvitationDisconnectNotice
  | VaultWideDisconnectNotice;

export interface VaultRealtimeEnvelope {
  version: typeof VAULT_PROTOCOL_VERSION;
  vaultId: string;
  purpose: "realtime";
  messageType: VaultMessageType;
  messageId: string;
  senderSessionId: string;
  sequence: number;
  iv: string;
  ciphertext: string;
}

export interface VaultAdmission {
  readonly vaultId: string;
  readonly invitationId: string;
  readonly role: VaultRole;
  readonly authorizationVersion: number;
  readonly activeRoomId: string;
  readonly senderSessionId: string;
  readonly expiresAt: number | null;
}

export type VaultCapabilityResolver = (
  request: VaultSocketJoinRequest,
) => Promise<VaultCapabilityResolution>;

export interface VaultSocket {
  readonly id: string;
  readonly rooms?: Set<string>;
  on(event: string, listener: (...args: any[]) => void): this;
  off?(event: string, listener: (...args: any[]) => void): this;
  emit(event: string, ...args: any[]): boolean;
  join(room: string): Promise<void> | void;
  leave?(room: string): Promise<void> | void;
  disconnect(close?: boolean): this;
  broadcast: {
    to(room: string): { emit(event: string, ...args: any[]): boolean };
  };
  volatile: {
    broadcast: {
      to(room: string): { emit(event: string, ...args: any[]): boolean };
    };
  };
}

export interface VaultIo {
  on(event: "connection", listener: (socket: VaultSocket) => void): this;
}

export interface VaultServerOptions {
  resolver: VaultCapabilityResolver;
  maxPayloadBytes?: number;
  maxMessagesPerMinute?: number;
  maxConnectionsPerVault?: number;
  rateLimitWindowMs?: number;
  now?: () => number;
  setTimeout?: (callback: () => void, delay: number) => any;
  clearTimeout?: (handle: any) => void;
  logger?: (event: string, metadata: Record<string, unknown>) => void;
}

export interface SupabaseVaultCapabilityResolverOptions {
  supabaseUrl: string;
  anonKey: string;
  timeoutMs?: number;
  allowDockerHostHttp?: boolean;
}

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CAPABILITY_RE = /^[A-Za-z0-9_-]{43}$/;
const ACTIVE_ROOM_ID_RE = /^[A-Za-z0-9_-]{16,128}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;
const MAX_TIMER_DELAY = 2_147_483_647;
const DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024;
const DEFAULT_MAX_MESSAGES_PER_MINUTE = 1200;
const DEFAULT_MAX_CONNECTIONS_PER_VAULT = 64;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const VAULT_ERROR_CODES = new Set([
  "VAULT_URL_INVALID",
  "VAULT_PROTOCOL_UNSUPPORTED",
  "VAULT_SECURE_CONTEXT_REQUIRED",
  "VAULT_CRYPTO_UNAVAILABLE",
  "VAULT_KEY_INVALID",
  "VAULT_CAPABILITY_MISSING",
  "VAULT_CAPABILITY_INVALID",
  "VAULT_CAPABILITY_FORBIDDEN",
  "VAULT_CAPABILITY_EXPIRED",
  "VAULT_CAPABILITY_REVOKED",
  "VAULT_ALREADY_EXISTS",
  "VAULT_NOT_FOUND",
  "VAULT_NOT_ACTIVE",
  "VAULT_ENVELOPE_INVALID",
  "VAULT_MESSAGE_TYPE_UNSUPPORTED",
  "VAULT_DECRYPT_FAILED",
  "VAULT_REPLAY_REJECTED",
  "VAULT_SEQUENCE_REJECTED",
  "VAULT_SNAPSHOT_CONFLICT",
  "VAULT_ASSET_CONFLICT",
  "VAULT_PERSISTENCE_UNAVAILABLE",
  "VAULT_ROOM_PROTOCOL_UNSUPPORTED",
  "VAULT_PLAIN_FALLBACK_FORBIDDEN",
  "VAULT_EGRESS_DENIED",
  "VAULT_RATE_LIMITED",
  "VAULT_PAYLOAD_TOO_LARGE",
  "VAULT_INTERNAL",
]);

export const vaultRoomName = (activeRoomId: string) => `vault@${activeRoomId}`;

export const isVaultInternalRoomName = (roomId: unknown) =>
  typeof roomId === "string" && roomId.startsWith("vault@");

export const parseVaultAllowedOrigins = (
  configuredOrigins: string | undefined,
  allowLocalHttp = true,
) => {
  const origins = (configuredOrigins || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  if (origins.length === 0 || origins.includes("*")) {
    throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
  }
  return Array.from(
    new Set(
      origins.map((origin) => {
        let url: URL;
        try {
          url = new URL(origin);
        } catch {
          throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
        }
        const localHttp =
          allowLocalHttp &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
        if (
          (url.protocol !== "https:" && !localHttp) ||
          url.origin !== origin ||
          url.username ||
          url.password ||
          url.search ||
          url.hash
        ) {
          throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
        }
        return url.origin;
      }),
    ),
  );
};

export const getVaultHttpCorsHeaders = (
  requestOrigin: string | undefined,
  configuredOrigins: string | undefined,
) => {
  let allowedOrigins: readonly string[] = [];
  try {
    allowedOrigins = parseVaultAllowedOrigins(configuredOrigins, true);
  } catch {
    allowedOrigins = [];
  }
  const allowedOrigin =
    requestOrigin && allowedOrigins.includes(requestOrigin)
      ? requestOrigin
      : null;
  return {
    ...(allowedOrigin ? { "Access-Control-Allow-Origin": allowedOrigin } : {}),
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    Vary: "Origin",
  };
};

export class VaultServerError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.name = "VaultServerError";
    this.code = code;
    Object.setPrototypeOf(this, VaultServerError.prototype);
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactKeys = (value: object, expected: readonly string[]) => {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => keys.includes(key))
  );
};

const isSafeIntegerAtLeast = (value: unknown, minimum: number) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;

export function assertVaultRoomProvisionRequest(
  value: unknown,
): asserts value is VaultRoomProvisionRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["protocolVersion", "vaultId", "invitationId"])
  ) {
    throw new VaultServerError("VAULT_ROOM_PROTOCOL_UNSUPPORTED");
  }
  if (value.protocolVersion !== VAULT_PROTOCOL_VERSION) {
    throw new VaultServerError("VAULT_PROTOCOL_UNSUPPORTED");
  }
  if (
    typeof value.vaultId !== "string" ||
    !UUID_RE.test(value.vaultId) ||
    typeof value.invitationId !== "string" ||
    !UUID_RE.test(value.invitationId)
  ) {
    throw new VaultServerError("VAULT_ROOM_PROTOCOL_UNSUPPORTED");
  }
}

export const issueVaultRoomProvision = (): VaultRoomProvisionResponse => {
  const activeRoomId = randomBytes(16)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return Object.freeze({
    protocolVersion: VAULT_PROTOCOL_VERSION,
    activeRoomId,
  });
};

const assertBase64Url = (value: unknown, requiredBytes?: number) => {
  if (
    typeof value !== "string" ||
    !BASE64URL_RE.test(value) ||
    value.length % 4 === 1
  ) {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
  let decoded: Buffer;
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    decoded = Buffer.from(
      normalized + "=".repeat((4 - (normalized.length % 4)) % 4),
      "base64",
    );
  } catch {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
  const canonical = decoded
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  if (canonical !== value) {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
  if (requiredBytes !== undefined) {
    if (decoded.length !== requiredBytes) {
      throw new VaultServerError("VAULT_ENVELOPE_INVALID");
    }
  }
  return decoded.length;
};

export function assertVaultSocketJoinRequest(
  value: unknown,
): asserts value is VaultSocketJoinRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "protocolVersion",
      "vaultId",
      "invitationCapability",
      "senderSessionId",
    ]) ||
    value.protocolVersion !== VAULT_PROTOCOL_VERSION ||
    typeof value.vaultId !== "string" ||
    !UUID_RE.test(value.vaultId) ||
    typeof value.invitationCapability !== "string" ||
    !CAPABILITY_RE.test(value.invitationCapability) ||
    typeof value.senderSessionId !== "string" ||
    !UUID_V4_RE.test(value.senderSessionId)
  ) {
    throw new VaultServerError(
      value &&
      isRecord(value) &&
      value.protocolVersion !== VAULT_PROTOCOL_VERSION
        ? "VAULT_PROTOCOL_UNSUPPORTED"
        : "VAULT_CAPABILITY_INVALID",
    );
  }
}

export function assertVaultCapabilityResolution(
  value: unknown,
  now = Date.now(),
): asserts value is VaultCapabilityResolution {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "vaultId",
      "invitationId",
      "role",
      "authorizationVersion",
      "activeRoomId",
      "snapshotGeneration",
      "expiresAt",
    ]) ||
    typeof value.vaultId !== "string" ||
    !UUID_RE.test(value.vaultId) ||
    typeof value.invitationId !== "string" ||
    !UUID_RE.test(value.invitationId) ||
    (value.role !== "viewer" && value.role !== "editor") ||
    !isSafeIntegerAtLeast(value.authorizationVersion, 1) ||
    typeof value.activeRoomId !== "string" ||
    !ACTIVE_ROOM_ID_RE.test(value.activeRoomId) ||
    !isSafeIntegerAtLeast(value.snapshotGeneration, 0) ||
    (value.expiresAt !== null && !isSafeIntegerAtLeast(value.expiresAt, 0))
  ) {
    throw new VaultServerError("VAULT_CAPABILITY_INVALID");
  }
  const expiresAt = value.expiresAt as number | null;
  if (expiresAt !== null && expiresAt <= now) {
    throw new VaultServerError("VAULT_CAPABILITY_EXPIRED");
  }
}

export function assertVaultRealtimeEnvelope(
  value: unknown,
): asserts value is VaultRealtimeEnvelope {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "version",
      "vaultId",
      "purpose",
      "messageType",
      "messageId",
      "senderSessionId",
      "sequence",
      "iv",
      "ciphertext",
    ])
  ) {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
  if (value.version !== VAULT_PROTOCOL_VERSION) {
    throw new VaultServerError("VAULT_PROTOCOL_UNSUPPORTED");
  }
  if (
    value.messageType !== "realtime.content" &&
    value.messageType !== "realtime.presence"
  ) {
    throw new VaultServerError("VAULT_MESSAGE_TYPE_UNSUPPORTED");
  }
  if (
    typeof value.vaultId !== "string" ||
    !UUID_RE.test(value.vaultId) ||
    value.purpose !== "realtime" ||
    typeof value.messageId !== "string" ||
    !UUID_V4_RE.test(value.messageId) ||
    typeof value.senderSessionId !== "string" ||
    !UUID_V4_RE.test(value.senderSessionId) ||
    !isSafeIntegerAtLeast(value.sequence, 1)
  ) {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
  assertBase64Url(value.iv, 12);
  if (assertBase64Url(value.ciphertext) < 16) {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
}

const canRoleSend = (role: VaultRole, messageType: VaultMessageType) =>
  role === "editor" || messageType === "realtime.presence";

const payloadByteLength = (value: unknown) => {
  try {
    return Buffer.byteLength(JSON.stringify(value), "utf8");
  } catch {
    throw new VaultServerError("VAULT_ENVELOPE_INVALID");
  }
};

const safeAck = (ack: unknown, value: Record<string, unknown>) => {
  if (typeof ack === "function") {
    (ack as (value: Record<string, unknown>) => void)(value);
  }
};

const errorCode = (error: unknown, fallback = "VAULT_INTERNAL") =>
  error instanceof VaultServerError ? error.code : fallback;

type VaultLogEvent =
  | "vault-admitted"
  | "vault-admission-rejected"
  | "vault-broadcast-rejected";

const VAULT_LOG_FIELDS: Record<VaultLogEvent, readonly string[]> = {
  "vault-admitted": ["vaultId", "activeRoomId"],
  "vault-admission-rejected": ["code", "socketId"],
  "vault-broadcast-rejected": ["code", "socketId"],
};

export const sanitizeVaultLogMetadata = (
  event: VaultLogEvent,
  metadata: Record<string, unknown>,
) => {
  const sanitized: Record<string, unknown> = {};
  for (const key of VAULT_LOG_FIELDS[event]) {
    if (Object.prototype.hasOwnProperty.call(metadata, key)) {
      sanitized[key] = metadata[key];
    }
  }
  return sanitized;
};

export class VaultRoomServer {
  private readonly resolver: VaultCapabilityResolver;
  private readonly maxPayloadBytes: number;
  private readonly maxMessagesPerMinute: number;
  private readonly maxConnectionsPerVault: number;
  private readonly rateLimitWindowMs: number;
  private readonly now: () => number;
  private readonly schedule: (callback: () => void, delay: number) => any;
  private readonly cancel: (handle: any) => void;
  private readonly logger: (
    event: string,
    metadata: Record<string, unknown>,
  ) => void;
  private readonly admissions = new WeakMap<VaultSocket, VaultAdmission>();
  private readonly expiryTimers = new WeakMap<VaultSocket, any>();
  private readonly joiningSockets = new WeakSet<VaultSocket>();
  private readonly messageRateWindows = new WeakMap<
    VaultSocket,
    { startedAt: number; count: number }
  >();
  private io: VaultIo | null = null;

  constructor(options: VaultServerOptions) {
    this.resolver = options.resolver;
    this.maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;
    this.maxMessagesPerMinute =
      options.maxMessagesPerMinute ?? DEFAULT_MAX_MESSAGES_PER_MINUTE;
    this.maxConnectionsPerVault =
      options.maxConnectionsPerVault ?? DEFAULT_MAX_CONNECTIONS_PER_VAULT;
    this.rateLimitWindowMs =
      options.rateLimitWindowMs ?? DEFAULT_RATE_LIMIT_WINDOW_MS;
    if (
      !Number.isSafeInteger(this.maxPayloadBytes) ||
      this.maxPayloadBytes < 1 ||
      !Number.isSafeInteger(this.maxMessagesPerMinute) ||
      this.maxMessagesPerMinute < 1 ||
      !Number.isSafeInteger(this.maxConnectionsPerVault) ||
      this.maxConnectionsPerVault < 1 ||
      !Number.isSafeInteger(this.rateLimitWindowMs) ||
      this.rateLimitWindowMs < 1
    ) {
      throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
    }
    this.now = options.now ?? (() => Date.now());
    this.schedule =
      options.setTimeout ?? ((callback, delay) => setTimeout(callback, delay));
    this.cancel = options.clearTimeout ?? ((handle) => clearTimeout(handle));
    this.logger = options.logger ?? (() => undefined);
  }

  attach = (io: VaultIo) => {
    this.io = io;
    io.on("connection", (socket) => this.attachSocket(socket));
    return this;
  };

  attachSocket = (socket: VaultSocket) => {
    socket.on(VAULT_SOCKET_EVENTS.join, (request: unknown, ack?: unknown) => {
      return this.handleJoin(socket, request, ack);
    });
    socket.on(
      VAULT_SOCKET_EVENTS.server,
      (roomId: unknown, envelope: unknown, ack?: unknown) => {
        this.handleBroadcast(socket, roomId, envelope, false, ack);
      },
    );
    socket.on(
      VAULT_SOCKET_EVENTS.serverVolatile,
      (roomId: unknown, envelope: unknown, ack?: unknown) => {
        this.handleBroadcast(socket, roomId, envelope, true, ack);
      },
    );
    socket.on("disconnect", () => this.clearSocket(socket));
    return socket;
  };

  isAdmitted = (socket: VaultSocket) => this.admissions.has(socket);

  isVaultSocketReserved = (socket: VaultSocket) =>
    this.joiningSockets.has(socket) || this.admissions.has(socket);

  disconnectByNotice = (notice: unknown) => {
    const parsed = this.parseNotice(notice);
    const sockets = this.listSockets();
    for (const socket of sockets) {
      const admission = this.admissions.get(socket);
      if (!admission || !this.matchesNotice(admission, parsed)) {
        continue;
      }
      this.emitDisconnectAndClose(socket, {
        vaultId: admission.vaultId,
        invitationId: admission.invitationId,
        authorizationVersion:
          "invitationId" in parsed
            ? parsed.authorizationVersion
            : admission.authorizationVersion,
        reason: parsed.reason,
      });
    }
    return parsed;
  };

  private listSockets = (): readonly VaultSocket[] => {
    const io = this.io as any;
    const map = io?.sockets?.sockets ?? io?.sockets;
    if (map && typeof map.values === "function") {
      return Array.from(map.values()) as VaultSocket[];
    }
    return [];
  };

  private handleJoin = async (
    socket: VaultSocket,
    value: unknown,
    ack: unknown,
  ) => {
    if (this.joiningSockets.has(socket) || this.admissions.has(socket)) {
      safeAck(ack, { ok: false, code: "VAULT_CAPABILITY_INVALID" });
      socket.disconnect(true);
      return;
    }
    this.joiningSockets.add(socket);
    try {
      assertVaultSocketJoinRequest(value);
      const resolution = await this.resolver(value);
      assertVaultCapabilityResolution(resolution, this.now());
      if (resolution.vaultId !== value.vaultId) {
        throw new VaultServerError("VAULT_CAPABILITY_INVALID");
      }
      if (this.hasApplicationRoom(socket)) {
        throw new VaultServerError("VAULT_CAPABILITY_FORBIDDEN");
      }
      if (
        this.countAdmissionsForVault(resolution.vaultId) >=
        this.maxConnectionsPerVault
      ) {
        throw new VaultServerError("VAULT_RATE_LIMITED");
      }
      const admission: VaultAdmission = Object.freeze({
        vaultId: resolution.vaultId,
        invitationId: resolution.invitationId,
        role: resolution.role,
        authorizationVersion: resolution.authorizationVersion,
        activeRoomId: resolution.activeRoomId,
        senderSessionId: value.senderSessionId,
        expiresAt: resolution.expiresAt,
      });
      await socket.join(vaultRoomName(admission.activeRoomId));
      this.admissions.set(socket, admission);
      this.scheduleExpiry(socket, admission);
      safeAck(ack, { ok: true, resolution });
      this.log("vault-admitted", {
        vaultId: admission.vaultId,
        activeRoomId: admission.activeRoomId,
      });
    } catch (error) {
      const code = errorCode(error, "VAULT_PERSISTENCE_UNAVAILABLE");
      safeAck(ack, { ok: false, code });
      this.log("vault-admission-rejected", { code, socketId: socket.id });
      socket.disconnect(true);
    } finally {
      this.joiningSockets.delete(socket);
    }
  };

  private handleBroadcast = (
    socket: VaultSocket,
    roomId: unknown,
    value: unknown,
    volatile: boolean,
    ack: unknown,
  ) => {
    try {
      const admission = this.requireAdmission(socket);
      this.consumeMessageRate(socket);
      if (roomId !== admission.activeRoomId) {
        throw new VaultServerError("VAULT_CAPABILITY_FORBIDDEN");
      }
      assertVaultRealtimeEnvelope(value);
      if (
        value.vaultId !== admission.vaultId ||
        value.senderSessionId !== admission.senderSessionId ||
        !canRoleSend(admission.role, value.messageType)
      ) {
        throw new VaultServerError("VAULT_CAPABILITY_FORBIDDEN");
      }
      const bytes = payloadByteLength(value);
      if (bytes > this.maxPayloadBytes) {
        throw new VaultServerError("VAULT_PAYLOAD_TOO_LARGE");
      }
      const outgoing = {
        sourceSocketId: socket.id,
        admittedSenderSessionId: admission.senderSessionId,
        envelope: value,
      };
      const broadcaster = volatile
        ? socket.volatile.broadcast.to(vaultRoomName(admission.activeRoomId))
        : socket.broadcast.to(vaultRoomName(admission.activeRoomId));
      broadcaster.emit(VAULT_SOCKET_EVENTS.client, outgoing);
      safeAck(ack, { ok: true });
    } catch (error) {
      const code = errorCode(error, "VAULT_ENVELOPE_INVALID");
      safeAck(ack, { ok: false, code });
      this.log("vault-broadcast-rejected", {
        code,
        socketId: socket.id,
      });
    }
  };

  private requireAdmission = (socket: VaultSocket) => {
    const admission = this.admissions.get(socket);
    if (!admission) {
      throw new VaultServerError("VAULT_CAPABILITY_MISSING");
    }
    if (admission.expiresAt !== null && admission.expiresAt <= this.now()) {
      const notice: VaultCapabilityDisconnectNotice = {
        vaultId: admission.vaultId,
        invitationId: admission.invitationId,
        authorizationVersion: admission.authorizationVersion,
        reason: "expired",
      };
      this.emitDisconnectAndClose(socket, notice);
      throw new VaultServerError("VAULT_CAPABILITY_EXPIRED");
    }
    return admission;
  };

  private scheduleExpiry = (socket: VaultSocket, admission: VaultAdmission) => {
    if (admission.expiresAt === null) {
      return;
    }
    const delay = admission.expiresAt - this.now();
    if (delay <= 0) {
      this.emitDisconnectAndClose(socket, {
        vaultId: admission.vaultId,
        invitationId: admission.invitationId,
        authorizationVersion: admission.authorizationVersion,
        reason: "expired",
      });
      return;
    }
    const handle = this.schedule(() => {
      this.expiryTimers.delete(socket);
      const current = this.admissions.get(socket);
      if (current === admission) {
        if (admission.expiresAt !== null && admission.expiresAt <= this.now()) {
          this.emitDisconnectAndClose(socket, {
            vaultId: admission.vaultId,
            invitationId: admission.invitationId,
            authorizationVersion: admission.authorizationVersion,
            reason: "expired",
          });
        } else {
          this.scheduleExpiry(socket, admission);
        }
      }
    }, Math.min(delay, MAX_TIMER_DELAY));
    this.expiryTimers.set(socket, handle);
  };

  private clearSocket = (socket: VaultSocket) => {
    const timer = this.expiryTimers.get(socket);
    if (timer !== undefined) {
      this.cancel(timer);
      this.expiryTimers.delete(socket);
    }
    this.admissions.delete(socket);
    this.messageRateWindows.delete(socket);
  };

  private countAdmissionsForVault = (vaultId: string) =>
    this.listSockets().reduce((count, socket) => {
      const admission = this.admissions.get(socket);
      return count + (admission?.vaultId === vaultId ? 1 : 0);
    }, 0);

  private consumeMessageRate = (socket: VaultSocket) => {
    const now = this.now();
    const current = this.messageRateWindows.get(socket);
    if (!current || now - current.startedAt >= this.rateLimitWindowMs) {
      this.messageRateWindows.set(socket, { startedAt: now, count: 1 });
      return;
    }
    if (current.count >= this.maxMessagesPerMinute) {
      throw new VaultServerError("VAULT_RATE_LIMITED");
    }
    current.count += 1;
  };

  private hasApplicationRoom = (socket: VaultSocket) => {
    if (!socket.rooms) {
      return false;
    }
    for (const roomId of Array.from(socket.rooms)) {
      if (roomId !== socket.id) {
        return true;
      }
    }
    return false;
  };

  private log = (event: VaultLogEvent, metadata: Record<string, unknown>) => {
    this.logger(event, sanitizeVaultLogMetadata(event, metadata));
  };

  private parseNotice = (value: unknown): VaultControlPlaneNotice => {
    if (
      !isRecord(value) ||
      typeof value.vaultId !== "string" ||
      !UUID_RE.test(value.vaultId)
    ) {
      throw new VaultServerError("VAULT_CAPABILITY_REVOKED");
    }
    if (value.reason === "vault-revoked" || value.reason === "vault-deleted") {
      if (!hasExactKeys(value, ["vaultId", "reason"])) {
        throw new VaultServerError("VAULT_CAPABILITY_REVOKED");
      }
      return {
        vaultId: value.vaultId,
        reason: value.reason,
      };
    }
    if (
      !hasExactKeys(value, [
        "vaultId",
        "invitationId",
        "authorizationVersion",
        "reason",
      ]) ||
      typeof value.invitationId !== "string" ||
      !UUID_RE.test(value.invitationId) ||
      !isSafeIntegerAtLeast(value.authorizationVersion, 1) ||
      (value.reason !== "expired" && value.reason !== "revoked")
    ) {
      throw new VaultServerError("VAULT_CAPABILITY_REVOKED");
    }
    return {
      vaultId: value.vaultId,
      invitationId: value.invitationId as string,
      authorizationVersion: value.authorizationVersion as number,
      reason: value.reason as "revoked" | "expired",
    };
  };

  private matchesNotice = (
    admission: VaultAdmission,
    notice: VaultControlPlaneNotice,
  ) => {
    if (!("invitationId" in notice)) {
      return notice.vaultId === admission.vaultId;
    }
    return (
      notice.vaultId === admission.vaultId &&
      notice.invitationId === admission.invitationId &&
      (notice.reason === "revoked"
        ? notice.authorizationVersion > admission.authorizationVersion
        : notice.authorizationVersion >= admission.authorizationVersion)
    );
  };

  private emitDisconnectAndClose = (
    socket: VaultSocket,
    notice: VaultCapabilityDisconnectNotice,
  ) => {
    const event =
      notice.reason === "expired"
        ? VAULT_SOCKET_EVENTS.capabilityExpired
        : VAULT_SOCKET_EVENTS.capabilityRevoked;
    socket.emit(event, notice);
    this.clearSocket(socket);
    socket.disconnect(true);
  };
}

const SUPABASE_RESOLVE_PATH = "/rest/v1/rpc/resolve_vault_capability";
const MAX_RESOLVER_RESPONSE_BYTES = 64 * 1024;
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const createSupabaseResolverUrl = (
  supabaseUrl: string,
  allowDockerHostHttp = false,
) => {
  let url: URL;
  try {
    url = new URL(supabaseUrl);
  } catch {
    throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
  }
  const isLocalHttp =
    url.protocol === "http:" &&
    (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      (allowDockerHostHttp && url.hostname === "host.docker.internal"));
  if (
    (url.protocol !== "https:" && !isLocalHttp) ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  ) {
    throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
  }
  url.pathname = SUPABASE_RESOLVE_PATH;
  return url;
};

const parseJson = (buffer: Buffer) => {
  try {
    return JSON.parse(buffer.toString("utf8")) as unknown;
  } catch {
    throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
  }
};

const vaultErrorCodeFromResponse = (value: unknown) => {
  if (!isRecord(value)) {
    return null;
  }
  for (const candidate of [value.message, value.code]) {
    if (typeof candidate === "string" && VAULT_ERROR_CODES.has(candidate)) {
      return candidate;
    }
  }
  return null;
};

const requestSupabaseResolution = (
  url: URL,
  body: unknown,
  anonKey: string,
  timeoutMs: number,
): Promise<unknown> =>
  new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const request = transport.request(
      url,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${anonKey}`,
          "Content-Type": "application/json",
          "Content-Length": payload.length,
          apikey: anonKey,
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        let oversized = false;
        response.on("data", (chunk) => {
          if (oversized) {
            return;
          }
          const buffer = Buffer.from(chunk);
          bytes += buffer.length;
          if (bytes > MAX_RESOLVER_RESPONSE_BYTES) {
            oversized = true;
            reject(new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE"));
            return;
          }
          chunks.push(buffer);
        });
        response.on("end", () => {
          if (oversized) {
            return;
          }
          let parsed: unknown;
          try {
            parsed = parseJson(Buffer.concat(chunks));
          } catch (error) {
            reject(error);
            return;
          }
          if (
            !response.statusCode ||
            response.statusCode < 200 ||
            response.statusCode >= 300
          ) {
            reject(
              new VaultServerError(
                vaultErrorCodeFromResponse(parsed) ??
                  "VAULT_PERSISTENCE_UNAVAILABLE",
              ),
            );
            return;
          }
          resolve(parsed);
        });
      },
    );
    request.setTimeout(timeoutMs, () => {
      request.destroy();
      reject(new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE"));
    });
    request.on("error", () =>
      reject(new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE")),
    );
    request.end(payload);
  });

const mapSupabaseCapabilityResolution = (value: unknown) => {
  if (!isRecord(value)) {
    throw new VaultServerError("VAULT_CAPABILITY_INVALID");
  }
  let expiresAt: number | null = null;
  if (value.expiresAt !== null) {
    if (
      typeof value.expiresAt !== "string" ||
      !ISO_TIMESTAMP_RE.test(value.expiresAt)
    ) {
      throw new VaultServerError("VAULT_CAPABILITY_INVALID");
    }
    expiresAt = Date.parse(value.expiresAt);
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
      throw new VaultServerError("VAULT_CAPABILITY_INVALID");
    }
  }
  const resolution = { ...value, expiresAt };
  assertVaultCapabilityResolution(resolution);
  return resolution;
};

export const createSupabaseVaultCapabilityResolver = (
  options: SupabaseVaultCapabilityResolverOptions,
): VaultCapabilityResolver => {
  const url = createSupabaseResolverUrl(
    options.supabaseUrl,
    options.allowDockerHostHttp === true,
  );
  const timeoutMs = options.timeoutMs ?? 5000;
  if (
    typeof options.anonKey !== "string" ||
    options.anonKey.length === 0 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1
  ) {
    throw new VaultServerError("VAULT_PERSISTENCE_UNAVAILABLE");
  }
  return async (request) => {
    assertVaultSocketJoinRequest(request);
    const response = await requestSupabaseResolution(
      url,
      {
        p_vault_id: request.vaultId,
        p_capability: request.invitationCapability,
      },
      options.anonKey,
      timeoutMs,
    );
    const resolution = mapSupabaseCapabilityResolution(response);
    if (resolution.vaultId !== request.vaultId) {
      throw new VaultServerError("VAULT_CAPABILITY_INVALID");
    }
    return resolution;
  };
};

export const createBearerTokenChecker = (expected: string) => {
  const expectedBytes = Buffer.from(expected, "utf8");
  return (authorization: unknown) => {
    if (
      typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")
    ) {
      return false;
    }
    const actualBytes = Buffer.from(authorization.slice(7), "utf8");
    return (
      actualBytes.length === expectedBytes.length &&
      timingSafeEqual(actualBytes, expectedBytes)
    );
  };
};
