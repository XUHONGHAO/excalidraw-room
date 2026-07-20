import assert from "assert";
import http from "http";

import {
  assertVaultRealtimeEnvelope,
  assertVaultRoomProvisionRequest,
  assertVaultSocketJoinRequest,
  createSupabaseVaultCapabilityResolver,
  isVaultInternalRoomName,
  issueVaultRoomProvision,
  getVaultHttpCorsHeaders,
  parseVaultAllowedOrigins,
  sanitizeVaultLogMetadata,
  VAULT_DEPLOYMENT_VERSION,
  VAULT_ROOM_SERVER_VERSION,
  VAULT_SOCKET_EVENTS,
  vaultRoomName,
  VaultRoomServer,
  VaultServerError,
} from "./vault";

import type { VaultCapabilityResolver, VaultSocket } from "./vault";

const vaultId = "123e4567-e89b-42d3-a456-426614174000";
const editorInvitationId = "123e4567-e89b-42d3-a456-426614174001";
const viewerInvitationId = "123e4567-e89b-42d3-a456-426614174005";
const senderA = "123e4567-e89b-42d3-a456-426614174002";
const senderB = "123e4567-e89b-42d3-a456-426614174003";
const roomId = "vault-room-123456";
const editorCapability = `${"C".repeat(42)}A`;
const viewerCapability = `${"V".repeat(42)}A`;
const MAX_TIMER_DELAY = 2_147_483_647;

const envelope = (
  senderSessionId: string,
  messageType: "realtime.content" | "realtime.presence" = "realtime.presence",
  overrides: Record<string, unknown> = {},
) => ({
  version: 1,
  vaultId,
  purpose: "realtime",
  messageType,
  messageId: "123e4567-e89b-42d3-a456-426614174004",
  senderSessionId,
  sequence: 1,
  iv: "AAAAAAAAAAAAAAAA",
  ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
  ...overrides,
});

function testVaultHttpCors() {
  assert.equal(VAULT_DEPLOYMENT_VERSION, "p4a-f4-v1");
  assert.equal(VAULT_ROOM_SERVER_VERSION, 1);
  assert.deepEqual(
    parseVaultAllowedOrigins(
      "https://vault.example,https://admin.example",
      false,
    ),
    ["https://vault.example", "https://admin.example"],
  );
  assert.throws(
    () => parseVaultAllowedOrigins("*", false),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PERSISTENCE_UNAVAILABLE",
  );
  assert.throws(
    () => parseVaultAllowedOrigins("http://vault.lan", false),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PERSISTENCE_UNAVAILABLE",
  );
  assert.deepEqual(
    getVaultHttpCorsHeaders(
      "http://localhost:3001",
      "http://localhost:3000,http://localhost:3001",
    ),
    {
      "Access-Control-Allow-Origin": "http://localhost:3001",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      Vary: "Origin",
    },
  );
  assert.equal(
    "Access-Control-Allow-Origin" in
      getVaultHttpCorsHeaders(
        "https://attacker.example",
        "http://localhost:3001",
      ),
    false,
  );
  assert.equal(
    "Access-Control-Allow-Origin" in
      getVaultHttpCorsHeaders("https://vault.example", undefined),
    false,
  );
}

class FakeSocket implements VaultSocket {
  readonly emitted: Array<{ event: string; args: any[] }> = [];
  readonly rooms: Set<string>;
  readonly listeners = new Map<string, (...args: any[]) => any>();
  disconnected = false;

  constructor(readonly id: string, private readonly io: FakeIo) {
    this.rooms = new Set([id]);
  }

  on(event: string, listener: (...args: any[]) => any) {
    this.listeners.set(event, listener);
    return this;
  }

  off(event: string) {
    this.listeners.delete(event);
    return this;
  }

  emit(event: string, ...args: any[]) {
    this.emitted.push({ event, args });
    return true;
  }

  async join(room: string) {
    this.rooms.add(room);
    this.io.sockets.set(this.id, this);
  }

  disconnect() {
    this.disconnected = true;
    const listener = this.listeners.get("disconnect");
    listener?.();
    return this;
  }

  broadcast = {
    to: (room: string) => ({
      emit: (event: string, ...args: any[]) =>
        this.io.broadcast(this, room, event, args),
    }),
  };

  volatile = {
    broadcast: {
      to: (room: string) => ({
        emit: (event: string, ...args: any[]) =>
          this.io.broadcast(this, room, event, args),
      }),
    },
  };

  async trigger(event: string, ...args: any[]) {
    return await this.listeners.get(event)?.(...args);
  }
}

class FakeIo {
  readonly sockets = new Map<string, FakeSocket>();
  readonly broadcasts: Array<{
    room: string;
    event: string;
    recipients: Array<{ id: string; isSender: boolean; hasRoom: boolean }>;
  }> = [];
  private connectionListener: ((socket: VaultSocket) => void) | null = null;

  on(_event: "connection", listener: (socket: VaultSocket) => void) {
    this.connectionListener = listener;
    return this;
  }

  connect(id: string) {
    const socket = new FakeSocket(id, this);
    this.sockets.set(id, socket);
    this.connectionListener?.(socket);
    return socket;
  }

  broadcast(sender: FakeSocket, room: string, event: string, args: any[]) {
    this.broadcasts.push({
      room,
      event,
      recipients: Array.from(this.sockets.values()).map((socket) => ({
        id: socket.id,
        isSender: socket === sender,
        hasRoom: socket.rooms.has(room),
      })),
    });
    for (const socket of Array.from(this.sockets.values())) {
      if (socket !== sender && socket.rooms.has(room)) {
        socket.emit(event, ...args);
      }
    }
    return true;
  }
}

const resolver: VaultCapabilityResolver = async (request) => {
  const viewer = request.invitationCapability === viewerCapability;
  return {
    vaultId: request.vaultId,
    invitationId: viewer ? viewerInvitationId : editorInvitationId,
    role: viewer ? "viewer" : "editor",
    authorizationVersion: 1,
    activeRoomId: roomId,
    snapshotGeneration: 0,
    expiresAt: null,
  };
};

const joinRequest = (
  senderSessionId: string,
  invitationCapability: string,
) => ({
  protocolVersion: 1 as const,
  vaultId,
  invitationCapability,
  senderSessionId,
});

const closeServer = (server: http.Server) =>
  new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });

async function testSupabaseResolver() {
  const requests: Array<{
    url?: string;
    headers: http.IncomingHttpHeaders;
    body: unknown;
  }> = [];
  let errorResponse = false;
  const rpcServer = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    request.on("end", () => {
      requests.push({
        url: request.url,
        headers: request.headers,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
      });
      response.setHeader("Content-Type", "application/json");
      if (errorResponse) {
        response.statusCode = 400;
        response.end(
          JSON.stringify({
            code: "P0001",
            message: "VAULT_CAPABILITY_REVOKED",
          }),
        );
        return;
      }
      response.end(
        JSON.stringify({
          vaultId,
          invitationId: editorInvitationId,
          role: "editor",
          authorizationVersion: 3,
          activeRoomId: roomId,
          snapshotGeneration: 7,
          expiresAt: "2099-07-14T12:34:56.789+00:00",
        }),
      );
    });
  });
  await new Promise<void>((resolve) =>
    rpcServer.listen(0, "127.0.0.1", resolve),
  );
  const address = rpcServer.address();
  assert.ok(address && typeof address === "object");
  const anonKey = "test-anon-key";
  const supabaseResolver = createSupabaseVaultCapabilityResolver({
    supabaseUrl: `http://127.0.0.1:${address.port}`,
    anonKey,
  });

  try {
    const resolution = await supabaseResolver(
      joinRequest(senderA, editorCapability),
    );
    assert.equal(
      resolution.expiresAt,
      Date.parse("2099-07-14T12:34:56.789+00:00"),
    );
    assert.equal(requests[0].url, "/rest/v1/rpc/resolve_vault_capability");
    assert.deepEqual(requests[0].body, {
      p_vault_id: vaultId,
      p_capability: editorCapability,
    });
    assert.equal(requests[0].headers.apikey, anonKey);
    assert.equal(requests[0].headers.authorization, `Bearer ${anonKey}`);

    errorResponse = true;
    await assert.rejects(
      () => supabaseResolver(joinRequest(senderA, editorCapability)),
      (error: unknown) =>
        error instanceof VaultServerError &&
        error.code === "VAULT_CAPABILITY_REVOKED" &&
        !error.message.includes(editorCapability),
    );
  } finally {
    await closeServer(rpcServer);
  }

  assert.throws(
    () =>
      createSupabaseVaultCapabilityResolver({
        supabaseUrl: "http://supabase.example.com",
        anonKey,
      }),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PERSISTENCE_UNAVAILABLE",
  );
  assert.doesNotThrow(() =>
    createSupabaseVaultCapabilityResolver({
      supabaseUrl: "http://host.docker.internal:54321",
      anonKey: "local-anon-key",
      allowDockerHostHttp: true,
    }),
  );
  assert.throws(
    () =>
      createSupabaseVaultCapabilityResolver({
        supabaseUrl: "http://host.docker.internal:54321",
        anonKey: "local-anon-key",
      }),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PERSISTENCE_UNAVAILABLE",
  );
}

function testRoomProvisionContracts() {
  const request = {
    protocolVersion: 1 as const,
    vaultId,
    invitationId: editorInvitationId,
  };
  assertVaultRoomProvisionRequest(request);

  for (const extraField of ["key", "capability", "roomKey"]) {
    assert.throws(
      () =>
        assertVaultRoomProvisionRequest({
          ...request,
          [extraField]: "forbidden",
        }),
      (error: unknown) =>
        error instanceof VaultServerError &&
        error.code === "VAULT_ROOM_PROTOCOL_UNSUPPORTED",
    );
  }
  assert.throws(
    () => assertVaultRoomProvisionRequest({ ...request, protocolVersion: 2 }),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PROTOCOL_UNSUPPORTED",
  );
  assert.throws(
    () => assertVaultRoomProvisionRequest({ ...request, invitationId: "bad" }),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_ROOM_PROTOCOL_UNSUPPORTED",
  );

  const first = issueVaultRoomProvision();
  const second = issueVaultRoomProvision();
  assert.deepEqual(Object.keys(first).sort(), [
    "activeRoomId",
    "protocolVersion",
  ]);
  assert.equal(first.protocolVersion, 1);
  assert.match(first.activeRoomId, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(first.activeRoomId, second.activeRoomId);
  assert.equal(JSON.stringify(first).includes(vaultId), false);
  assert.equal(JSON.stringify(first).includes(editorInvitationId), false);
}

async function testRoomContracts() {
  assertVaultSocketJoinRequest(joinRequest(senderA, editorCapability));
  assertVaultRealtimeEnvelope(envelope(senderA));
  assert.throws(
    () =>
      assertVaultRealtimeEnvelope(
        envelope(senderA, "realtime.presence", {
          ciphertext: `${"A".repeat(21)}B`,
        }),
      ),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_ENVELOPE_INVALID",
  );
  assert.throws(
    () =>
      assertVaultRealtimeEnvelope(
        envelope(senderA, "realtime.presence", { version: 2 }),
      ),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_PROTOCOL_UNSUPPORTED",
  );
  assert.throws(
    () =>
      assertVaultRealtimeEnvelope(
        envelope(senderA, "realtime.presence", {
          messageType: "snapshot.scene",
        }),
      ),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_MESSAGE_TYPE_UNSUPPORTED",
  );
  assert.equal(isVaultInternalRoomName(vaultRoomName(roomId)), true);
  assert.equal(isVaultInternalRoomName(roomId), false);
  assert.throws(
    () =>
      assertVaultSocketJoinRequest({
        ...joinRequest(senderA, editorCapability),
        vaultId: "bad",
      }),
    (error: unknown) =>
      error instanceof VaultServerError &&
      error.code === "VAULT_CAPABILITY_INVALID",
  );

  const io = new FakeIo();
  const logs: Array<{
    event: string;
    metadata: Record<string, unknown>;
  }> = [];
  const server = new VaultRoomServer({
    resolver,
    maxPayloadBytes: 1024,
    logger: (event, metadata) => logs.push({ event, metadata }),
  }).attach(io);
  const editor = io.connect("socket-editor");
  const viewer = io.connect("socket-viewer");
  const editorAck: any[] = [];
  const viewerAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    (value: unknown) => editorAck.push(value),
  );
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderB, viewerCapability),
    (value: unknown) => viewerAck.push(value),
  );
  assert.equal(editorAck[0].ok, true);
  assert.equal(viewerAck[0].ok, true);
  assert.equal(editor.rooms.has(vaultRoomName(roomId)), true);
  assert.equal(viewer.rooms.has(vaultRoomName(roomId)), true);

  const broadcastAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderA, "realtime.content"),
    (value: unknown) => broadcastAck.push(value),
  );
  assert.equal(broadcastAck[0].ok, true);
  const relayed = viewer.emitted.find(
    ({ event }) => event === VAULT_SOCKET_EVENTS.client,
  );
  assert.ok(
    relayed,
    JSON.stringify({ emitted: viewer.emitted, broadcasts: io.broadcasts }),
  );
  assert.equal(relayed.args[0].sourceSocketId, editor.id);
  assert.equal(relayed.args[0].admittedSenderSessionId, senderA);

  const viewerPresenceAck: any[] = [];
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.serverVolatile,
    roomId,
    envelope(senderB),
    (value: unknown) => viewerPresenceAck.push(value),
  );
  assert.equal(viewerPresenceAck[0].ok, true);

  const forbiddenAck: any[] = [];
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderB, "realtime.content"),
    (value: unknown) => forbiddenAck.push(value),
  );
  assert.equal(forbiddenAck[0].code, "VAULT_CAPABILITY_FORBIDDEN");

  const senderSpoofAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderB),
    (value: unknown) => senderSpoofAck.push(value),
  );
  assert.equal(senderSpoofAck[0].code, "VAULT_CAPABILITY_FORBIDDEN");

  const wrongRoomAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    "wrong-room-123456",
    envelope(senderA),
    (value: unknown) => wrongRoomAck.push(value),
  );
  assert.equal(wrongRoomAck[0].code, "VAULT_CAPABILITY_FORBIDDEN");

  const oversizedAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderA, "realtime.content", {
      ciphertext: "A".repeat(2048),
    }),
    (value: unknown) => oversizedAck.push(value),
  );
  assert.equal(oversizedAck[0].code, "VAULT_PAYLOAD_TOO_LARGE");

  const sanitized = sanitizeVaultLogMetadata("vault-admitted", {
    vaultId,
    activeRoomId: roomId,
    invitationCapability: editorCapability,
    ciphertext: "secret",
  });
  assert.deepEqual(sanitized, { vaultId, activeRoomId: roomId });
  assert.ok(
    logs.every(
      ({ metadata }) =>
        !JSON.stringify(metadata).includes(editorCapability) &&
        !Object.keys(metadata).some((key) =>
          ["invitationCapability", "ciphertext", "envelope"].includes(key),
        ),
    ),
  );

  server.disconnectByNotice({
    vaultId,
    invitationId: editorInvitationId,
    authorizationVersion: 1,
    reason: "revoked",
  });
  assert.equal(editor.disconnected, false);

  server.disconnectByNotice({
    vaultId,
    invitationId: editorInvitationId,
    authorizationVersion: 2,
    reason: "revoked",
  });
  assert.equal(editor.disconnected, true);
  assert.equal(viewer.disconnected, false);
  const editorNotice = editor.emitted[editor.emitted.length - 1];
  assert.equal(editorNotice.event, VAULT_SOCKET_EVENTS.capabilityRevoked);
  assert.deepEqual(editorNotice.args[0], {
    vaultId,
    invitationId: editorInvitationId,
    authorizationVersion: 2,
    reason: "revoked",
  });

  server.disconnectByNotice({ vaultId, reason: "vault-revoked" });
  assert.equal(viewer.disconnected, true);
  const viewerNotice = viewer.emitted[viewer.emitted.length - 1];
  assert.equal(viewerNotice.event, VAULT_SOCKET_EVENTS.capabilityRevoked);
  assert.deepEqual(viewerNotice.args[0], {
    vaultId,
    invitationId: viewerInvitationId,
    authorizationVersion: 1,
    reason: "vault-revoked",
  });

  const prejoined = io.connect("socket-prejoined");
  await prejoined.join("ordinary-room");
  const prejoinedAck: any[] = [];
  await prejoined.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    (value: unknown) => prejoinedAck.push(value),
  );
  assert.equal(prejoinedAck[0].code, "VAULT_CAPABILITY_FORBIDDEN");
  assert.equal(prejoined.disconnected, true);
}

async function testLongExpiryAndImmediateExpiry() {
  let now = 1_800_000_000_000;
  const timers: Array<{
    callback: () => void;
    delay: number;
    cancelled: boolean;
  }> = [];
  const io = new FakeIo();
  new VaultRoomServer({
    resolver: async (request) => ({
      vaultId: request.vaultId,
      invitationId: editorInvitationId,
      role: "editor",
      authorizationVersion: 4,
      activeRoomId: roomId,
      snapshotGeneration: 0,
      expiresAt: now + MAX_TIMER_DELAY + 5000,
    }),
    now: () => now,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeout: (timer) => {
      timer.cancelled = true;
    },
  }).attach(io);
  const socket = io.connect("socket-long-expiry");
  await socket.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    () => undefined,
  );
  assert.equal(timers[0].delay, MAX_TIMER_DELAY);
  now += MAX_TIMER_DELAY;
  timers[0].callback();
  assert.equal(timers[1].delay, 5000);
  now += 5000;
  timers[1].callback();
  assert.equal(socket.disconnected, true);
  assert.equal(
    socket.emitted[socket.emitted.length - 1].event,
    VAULT_SOCKET_EVENTS.capabilityExpired,
  );

  const immediateIo = new FakeIo();
  const immediateServer = new VaultRoomServer({ resolver }).attach(immediateIo);
  const immediate = immediateIo.connect("socket-immediate-expiry");
  await immediate.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    () => undefined,
  );
  immediateServer.disconnectByNotice({
    vaultId,
    invitationId: editorInvitationId,
    authorizationVersion: 1,
    reason: "expired",
  });
  assert.equal(immediate.disconnected, true);
  assert.equal(
    immediate.emitted[immediate.emitted.length - 1].event,
    VAULT_SOCKET_EVENTS.capabilityExpired,
  );
}

async function testRateAndConnectionLimits() {
  let now = 1_800_000_000_000;
  const rateIo = new FakeIo();
  new VaultRoomServer({
    resolver,
    now: () => now,
    maxMessagesPerMinute: 1,
    rateLimitWindowMs: 60_000,
  }).attach(rateIo);
  const editor = rateIo.connect("socket-rate-editor");
  await editor.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    () => undefined,
  );
  const firstAck: any[] = [];
  const limitedAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderA, "realtime.content"),
    (value: unknown) => firstAck.push(value),
  );
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderA, "realtime.content", {
      messageId: "223e4567-e89b-42d3-a456-426614174004",
      sequence: 2,
    }),
    (value: unknown) => limitedAck.push(value),
  );
  assert.equal(firstAck[0].ok, true);
  assert.equal(limitedAck[0].code, "VAULT_RATE_LIMITED");

  now += 60_000;
  const resetAck: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelope(senderA, "realtime.content", {
      messageId: "323e4567-e89b-42d3-a456-426614174004",
      sequence: 3,
    }),
    (value: unknown) => resetAck.push(value),
  );
  assert.equal(resetAck[0].ok, true);

  const connectionIo = new FakeIo();
  new VaultRoomServer({
    resolver,
    maxConnectionsPerVault: 1,
  }).attach(connectionIo);
  const first = connectionIo.connect("socket-quota-first");
  const second = connectionIo.connect("socket-quota-second");
  const firstJoinAck: any[] = [];
  const secondJoinAck: any[] = [];
  await first.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderA, editorCapability),
    (value: unknown) => firstJoinAck.push(value),
  );
  await second.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinRequest(senderB, viewerCapability),
    (value: unknown) => secondJoinAck.push(value),
  );
  assert.equal(firstJoinAck[0].ok, true);
  assert.equal(secondJoinAck[0].code, "VAULT_RATE_LIMITED");
  assert.equal(second.disconnected, true);
}

async function run() {
  testVaultHttpCors();
  await testSupabaseResolver();
  testRoomProvisionContracts();
  await testRoomContracts();
  await testLongExpiryAndImmediateExpiry();
  await testRateAndConnectionLimits();
}

void run().then(() => {
  // eslint-disable-next-line no-console
  console.log("vault contract tests passed");
});
