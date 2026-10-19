/**
 * P4c Vault v2 room contract tests (W2 design §7.2 S-1…S-7, negative matrix
 * N1–N4, N13, N15, N19, N20). Run: yarn test:vault
 */
import assert from "assert";

import {
  assertVaultAnySocketJoinRequest,
  assertVaultCapabilityResolution,
  assertVaultRealtimeEnvelopeV2,
  VAULT_ROOM_SERVER_VERSION,
  VAULT_SOCKET_EVENTS,
  VAULT_SUPPORTED_PROTOCOL_VERSIONS,
  vaultRoomName,
  VaultRoomServer,
  VaultServerError,
} from "./vault";

import type { VaultCapabilityResolver, VaultSocket } from "./vault";

const vaultId = "223e4567-e89b-42d3-a456-426614174000";
const v1VaultId = "323e4567-e89b-42d3-a456-426614174000";
const editorInvitationId = "223e4567-e89b-42d3-a456-426614174001";
const viewerInvitationId = "223e4567-e89b-42d3-a456-426614174005";
const roomId = "vault-room-v2-123456";
const editorCapability = `${"E".repeat(42)}A`;
const viewerCapability = `${"W".repeat(42)}A`;
const senderSessionId = "223e4567-e89b-42d3-a456-426614174002";

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

  emit(event: string, ...args: any[]) {
    this.emitted.push({ event, args });
    return true;
  }

  async join(room: string) {
    this.rooms.add(room);
  }

  disconnect() {
    this.disconnected = true;
    this.listeners.get("disconnect")?.();
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
  private listener: ((socket: VaultSocket) => void) | null = null;

  on(_event: "connection", listener: (socket: VaultSocket) => void) {
    this.listener = listener;
    return this;
  }

  connect(id: string) {
    const socket = new FakeSocket(id, this);
    this.sockets.set(id, socket);
    this.listener?.(socket);
    return socket;
  }

  broadcast(sender: FakeSocket, room: string, event: string, args: any[]) {
    for (const socket of Array.from(this.sockets.values())) {
      if (socket !== sender && socket.rooms.has(room)) {
        socket.emit(event, ...args);
      }
    }
    return true;
  }
}

/** v2 resolver: returns the Vault's protocol version (S-2) */
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
    protocolVersion: request.vaultId === v1VaultId ? 1 : 2,
  };
};

const joinV2 = (capability: string, id = vaultId) => ({
  protocolVersion: 2 as const,
  vaultId: id,
  invitationCapability: capability,
});

const envelopeV2 = (overrides: Record<string, unknown> = {}) => ({
  version: 2,
  schemaVersion: 2,
  protocolVersion: 2,
  vaultId,
  roomId,
  purpose: "realtime.content",
  messageType: "sync.update",
  messageId: "223e4567-e89b-42d3-a456-426614174004",
  generation: 0,
  chunkIndex: 0,
  chunkCount: 1,
  iv: "AAAAAAAAAAAAAAAA",
  ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
  ...overrides,
});

const code = (expected: string) => (error: unknown) =>
  error instanceof VaultServerError && error.code === expected;

function testV2Contracts() {
  // S-7: v1 clients still see roomServerVersion 1; v2 is advertised separately
  assert.equal(VAULT_ROOM_SERVER_VERSION, 1);
  assert.deepEqual([...VAULT_SUPPORTED_PROTOCOL_VERSIONS], [1, 2]);

  // S-1: v2 join has no senderSessionId
  assertVaultAnySocketJoinRequest(joinV2(editorCapability));
  assert.throws(
    () =>
      assertVaultAnySocketJoinRequest({
        ...joinV2(editorCapability),
        senderSessionId,
      }),
    code("VAULT_CAPABILITY_INVALID"),
  );
  assert.throws(
    () =>
      assertVaultAnySocketJoinRequest({
        ...joinV2(editorCapability),
        protocolVersion: 3,
      }),
    code("VAULT_PROTOCOL_UNSUPPORTED"),
  );

  // resolution with and without protocolVersion; unknown versions rejected
  assertVaultCapabilityResolution({
    vaultId,
    invitationId: editorInvitationId,
    role: "editor",
    authorizationVersion: 1,
    activeRoomId: roomId,
    snapshotGeneration: 0,
    expiresAt: null,
    protocolVersion: 2,
  });
  assert.throws(
    () =>
      assertVaultCapabilityResolution({
        vaultId,
        invitationId: editorInvitationId,
        role: "editor",
        authorizationVersion: 1,
        activeRoomId: roomId,
        snapshotGeneration: 0,
        expiresAt: null,
        protocolVersion: 7,
      }),
    code("VAULT_CAPABILITY_INVALID"),
  );

  // S-3 / N1–N4
  assertVaultRealtimeEnvelopeV2(envelopeV2());
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ senderSessionId })),
    code("VAULT_ENVELOPE_INVALID"),
  );
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ sequence: 1 })),
    code("VAULT_ENVELOPE_INVALID"),
  );
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ version: 1 })),
    code("VAULT_PROTOCOL_UNSUPPORTED"),
  );
  assert.throws(
    () =>
      assertVaultRealtimeEnvelopeV2(envelopeV2({ messageType: "scene.init" })),
    code("VAULT_MESSAGE_TYPE_UNSUPPORTED"),
  );
  // snapshots never travel over the socket in v2
  assert.throws(
    () =>
      assertVaultRealtimeEnvelopeV2(
        envelopeV2({ purpose: "snapshot", messageType: "snapshot.scene" }),
      ),
    code("VAULT_MESSAGE_TYPE_UNSUPPORTED"),
  );
  // N20: purpose/messageType mismatch
  assert.throws(
    () =>
      assertVaultRealtimeEnvelopeV2(
        envelopeV2({ purpose: "realtime.request" }),
      ),
    code("VAULT_ENVELOPE_INVALID"),
  );
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ chunkIndex: 1 })),
    code("VAULT_ENVELOPE_INVALID"),
  );
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ chunkCount: 65 })),
    code("VAULT_ENVELOPE_INVALID"),
  );
  assert.throws(
    () => assertVaultRealtimeEnvelopeV2(envelopeV2({ iv: "AAAA" })),
    code("VAULT_ENVELOPE_INVALID"),
  );
}

async function testV2Room() {
  const io = new FakeIo();
  new VaultRoomServer({ resolver }).attach(io);
  const editor = io.connect("socket-editor");
  const viewer = io.connect("socket-viewer");
  const acks: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinV2(editorCapability),
    (value: unknown) => acks.push(value),
  );
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinV2(viewerCapability),
    (value: unknown) => acks.push(value),
  );
  assert.equal(acks[0].ok, true);
  assert.equal(acks[1].ok, true);
  assert.equal(editor.rooms.has(vaultRoomName(roomId)), true);

  // S-4: relay frame is exactly { envelope }
  const sendAcks: any[] = [];
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelopeV2(),
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[0].ok, true);
  const received = viewer.emitted.filter(
    (entry) => entry.event === VAULT_SOCKET_EVENTS.client,
  );
  assert.equal(received.length, 1);
  assert.deepEqual(Object.keys(received[0].args[0]), ["envelope"]);

  // S-5 / N15: a viewer cannot send content …
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelopeV2(),
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[1].code, "VAULT_CAPABILITY_FORBIDDEN");
  // … N19: but may send requests and presence
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelopeV2({
      purpose: "realtime.request",
      messageType: "sync.snapshot-request",
    }),
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[2].ok, true);
  await viewer.trigger(
    VAULT_SOCKET_EVENTS.serverVolatile,
    roomId,
    envelopeV2({
      purpose: "realtime.presence",
      messageType: "presence.ephemeral",
    }),
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[3].ok, true);

  // envelope for another room / Vault
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    envelopeV2({ roomId: "vault-room-other-1234" }),
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[4].code, "VAULT_CAPABILITY_FORBIDDEN");

  // a v1 envelope on a v2 admission is rejected (no mixing in a room)
  await editor.trigger(
    VAULT_SOCKET_EVENTS.server,
    roomId,
    {
      version: 1,
      vaultId,
      purpose: "realtime",
      messageType: "realtime.content",
      messageId: "223e4567-e89b-42d3-a456-426614174004",
      senderSessionId,
      sequence: 1,
      iv: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    },
    (value: unknown) => sendAcks.push(value),
  );
  assert.equal(sendAcks[5].code, "VAULT_ENVELOPE_INVALID");
}

async function testProtocolMismatch() {
  const io = new FakeIo();
  new VaultRoomServer({ resolver }).attach(io);
  // N13: v2 client joining a v1 Vault
  const a = io.connect("socket-a");
  const acks: any[] = [];
  await a.trigger(
    VAULT_SOCKET_EVENTS.join,
    joinV2(editorCapability, v1VaultId),
    (value: unknown) => acks.push(value),
  );
  assert.equal(acks[0].code, "VAULT_PROTOCOL_UNSUPPORTED");
  assert.equal(a.disconnected, true);
  // N13: v1 client joining a v2 Vault
  const b = io.connect("socket-b");
  await b.trigger(
    VAULT_SOCKET_EVENTS.join,
    {
      protocolVersion: 1,
      vaultId,
      invitationCapability: editorCapability,
      senderSessionId,
    },
    (value: unknown) => acks.push(value),
  );
  assert.equal(acks[1].code, "VAULT_PROTOCOL_UNSUPPORTED");
  assert.equal(b.disconnected, true);
}

export async function runVaultV2Tests() {
  testV2Contracts();
  await testV2Room();
  await testProtocolMismatch();
}
