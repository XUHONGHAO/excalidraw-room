/* eslint-disable no-console */

const { execFileSync, spawn } = require("child_process");
const { createHash, randomBytes, randomUUID } = require("crypto");
const net = require("net");
const path = require("path");

const { io } = require("socket.io-client");

const ROOM_ROOT = path.resolve(__dirname, "..");
const IS_REMOTE_GATE = process.env.VAULT_ROOM_GATE_TARGET === "remote";
const SOCKET_TIMEOUT_MS = IS_REMOTE_GATE ? 8_000 : 5_000;
const HTTP_TIMEOUT_MS = IS_REMOTE_GATE ? 12_000 : 8_000;
const MAX_LOG_BYTES = 1024 * 1024;

class GateError extends Error {
  constructor(step, code) {
    super(`${step}: ${code}`);
    this.name = "GateError";
  }
}

const assertGate = (condition, step, code = "ASSERTION_FAILED") => {
  if (!condition) {
    throw new GateError(step, code);
  }
};

const parseRemoteSupabaseStatus = () => {
  const projectRef = process.env.VAULT_ROOM_GATE_PROJECT_REF;
  const anonKey = process.env.VAULT_ROOM_GATE_ANON_KEY;
  const serviceRoleKey = process.env.VAULT_ROOM_GATE_SERVICE_ROLE_KEY;
  const rawApiUrl = process.env.VAULT_ROOM_GATE_API_URL;
  assertGate(
    typeof projectRef === "string" && /^[a-z0-9]{20}$/.test(projectRef),
    "remote Supabase configuration",
    "INVALID_PROJECT_REF",
  );
  for (const [name, value] of [
    ["API_URL", rawApiUrl],
    ["ANON_KEY", anonKey],
    ["SERVICE_ROLE_KEY", serviceRoleKey],
  ]) {
    assertGate(
      typeof value === "string" && value.length > 0,
      "remote Supabase configuration",
      `MISSING_${name}`,
    );
  }

  let apiUrl;
  try {
    apiUrl = new URL(rawApiUrl);
  } catch {
    throw new GateError("remote Supabase configuration", "INVALID_API_URL");
  }
  assertGate(
    apiUrl.protocol === "https:" &&
      apiUrl.hostname === `${projectRef}.supabase.co` &&
      (apiUrl.pathname === "/" || apiUrl.pathname === "") &&
      !apiUrl.search &&
      !apiUrl.hash &&
      !apiUrl.username &&
      !apiUrl.password,
    "remote Supabase configuration",
    "PROJECT_URL_MISMATCH",
  );

  return {
    anonKey,
    apiUrl: apiUrl.origin,
    serviceRoleKey,
  };
};

const parseLocalSupabaseStatus = () => {
  let stdout;
  try {
    stdout = execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$ErrorActionPreference='Stop'; supabase status -o json",
      ],
      {
        cwd: path.resolve(ROOM_ROOT, "..", "excalidraw"),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
  } catch {
    throw new GateError("supabase status", "UNAVAILABLE");
  }

  let status;
  try {
    status = JSON.parse(stdout);
  } catch {
    throw new GateError("supabase status", "INVALID_JSON");
  }

  for (const key of ["API_URL", "ANON_KEY", "SERVICE_ROLE_KEY"]) {
    assertGate(
      typeof status[key] === "string" && status[key],
      "supabase status",
      `MISSING_${key}`,
    );
  }

  let apiUrl;
  try {
    apiUrl = new URL(status.API_URL);
  } catch {
    throw new GateError("supabase status", "INVALID_API_URL");
  }
  assertGate(
    apiUrl.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(apiUrl.hostname),
    "supabase status",
    "NOT_LOCAL_STACK",
  );

  return {
    anonKey: status.ANON_KEY,
    apiUrl: apiUrl.origin,
    serviceRoleKey: status.SERVICE_ROLE_KEY,
  };
};

const parseSupabaseStatus = () =>
  IS_REMOTE_GATE ? parseRemoteSupabaseStatus() : parseLocalSupabaseStatus();

const request = async (step, url, options = {}, expectedStatuses = [200]) => {
  let response;
  try {
    response = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
  } catch {
    throw new GateError(step, "NETWORK_ERROR");
  }
  assertGate(
    expectedStatuses.includes(response.status),
    step,
    `HTTP_${response.status}`,
  );
  if (response.status === 204) {
    return null;
  }
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new GateError(step, "INVALID_JSON");
  }
};

const jsonHeaders = (apiKey, bearer = apiKey) => ({
  Accept: "application/json",
  Authorization: `Bearer ${bearer}`,
  "Content-Type": "application/json",
  apikey: apiKey,
});

const capabilityHash = (vaultId, capability) =>
  createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from("excalidraw-vault-capability", "utf8"),
        Buffer.from([0]),
        Buffer.from("1", "utf8"),
        Buffer.from([0]),
        Buffer.from(vaultId.toLowerCase(), "utf8"),
        Buffer.from([0]),
        Buffer.from(capability, "utf8"),
      ]),
    )
    .digest("base64url");

const randomCapability = () => randomBytes(32).toString("base64url");

const getFreePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => {
        if (error || !port) {
          reject(error || new Error("missing port"));
          return;
        }
        resolve(port);
      });
    });
  });

const waitForHttp = async (url) => {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(750),
      });
      if (response.status === 200) {
        const value = await response.json();
        assertGate(
          Array.isArray(value.protocolVersions) &&
            value.protocolVersions.length === 1 &&
            value.protocolVersions[0] === 1,
          "room discovery",
          "PROTOCOL_NOT_ADVERTISED",
        );
        return;
      }
    } catch {
      // Retry while the child process starts.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new GateError("room discovery", "TIMEOUT");
};

const connectSocket = (roomUrl, sockets) =>
  new Promise((resolve, reject) => {
    const socket = io(roomUrl, {
      forceNew: true,
      reconnection: false,
      timeout: SOCKET_TIMEOUT_MS,
      transports: ["websocket"],
    });
    sockets.add(socket);
    const timer = setTimeout(() => {
      socket.close();
      reject(new GateError("socket connect", "TIMEOUT"));
    }, SOCKET_TIMEOUT_MS);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("connect_error", () => {
      clearTimeout(timer);
      reject(new GateError("socket connect", "CONNECT_ERROR"));
    });
  });

const emitAck = (socket, event, ...args) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new GateError(`socket ${event}`, "ACK_TIMEOUT")),
      SOCKET_TIMEOUT_MS,
    );
    socket.emit(event, ...args, (value) => {
      clearTimeout(timer);
      resolve(value);
    });
  });

const waitForEvent = (socket, event, timeoutMs = SOCKET_TIMEOUT_MS) =>
  new Promise((resolve, reject) => {
    const onEvent = (value) => {
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      reject(new GateError(`socket ${event}`, "EVENT_TIMEOUT"));
    }, timeoutMs);
    socket.once(event, onEvent);
  });

const waitForDisconnect = (socket, timeoutMs = SOCKET_TIMEOUT_MS) => {
  if (!socket.connected) {
    return Promise.resolve();
  }
  return waitForEvent(socket, "disconnect", timeoutMs).then(() => undefined);
};

const expectNoEvent = async (socket, event, action, timeoutMs = 350) => {
  let received = false;
  const listener = () => {
    received = true;
  };
  socket.on(event, listener);
  try {
    await action();
    await new Promise((resolve) => setTimeout(resolve, timeoutMs));
  } finally {
    socket.off(event, listener);
  }
  assertGate(!received, `socket ${event}`, "UNEXPECTED_EVENT");
};

const makeEnvelope = ({
  ciphertext,
  messageType,
  senderSessionId,
  sequence,
  vaultId,
}) => ({
  version: 1,
  vaultId,
  purpose: "realtime",
  messageType,
  messageId: randomUUID(),
  senderSessionId,
  sequence,
  iv: randomBytes(12).toString("base64url"),
  ciphertext,
});

const joinVault = async (socket, { capability, senderSessionId, vaultId }) =>
  emitAck(socket, "vault:join", {
    protocolVersion: 1,
    vaultId,
    invitationCapability: capability,
    senderSessionId,
  });

const main = async () => {
  const status = parseSupabaseStatus();
  const roomPort = await getFreePort();
  const roomUrl = `http://127.0.0.1:${roomPort}`;
  const controlPlaneToken = randomBytes(32).toString("base64url");
  const roomLogs = [];
  let roomLogBytes = 0;
  const captureLog = (chunk) => {
    if (roomLogBytes >= MAX_LOG_BYTES) {
      return;
    }
    const value = Buffer.from(chunk).toString("utf8");
    roomLogBytes += Buffer.byteLength(value);
    roomLogs.push(value);
  };

  const roomProcessEnvironment = { ...process.env };
  for (const name of [
    "SUPABASE_ACCESS_TOKEN",
    "VAULT_SUPABASE_DB_URL",
    "VAULT_SUPABASE_SSLROOTCERT_PATH",
    "VAULT_ROOM_GATE_SERVICE_ROLE_KEY",
  ]) {
    delete roomProcessEnvironment[name];
  }
  const roomProcess = spawn(process.execPath, ["dist/index.js"], {
    cwd: ROOM_ROOT,
    env: {
      ...roomProcessEnvironment,
      CORS_ORIGIN: "http://127.0.0.1",
      DEBUG: "server,io,socket",
      NODE_ENV: "development",
      PORT: String(roomPort),
      VAULT_CAPABILITY_RESOLVE_TIMEOUT_MS: "5000",
      VAULT_CONTROL_PLANE_TOKEN: controlPlaneToken,
      VAULT_ENABLED: "true",
      VAULT_MAX_PAYLOAD_BYTES: "1048576",
      VAULT_SUPABASE_ANON_KEY: status.anonKey,
      VAULT_SUPABASE_URL: status.apiUrl,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  roomProcess.stdout.on("data", captureLog);
  roomProcess.stderr.on("data", captureLog);

  const sockets = new Set();
  const sensitiveValues = [
    controlPlaneToken,
    status.anonKey,
    status.serviceRoleKey,
  ];
  const passed = [];
  let ownerId = null;
  let ownerToken = null;
  let vaultId = null;

  const rpc = (name, body) =>
    request(
      `rpc ${name}`,
      `${status.apiUrl}/rest/v1/rpc/${name}`,
      {
        method: "POST",
        headers: jsonHeaders(status.anonKey, ownerToken),
        body: JSON.stringify(body),
      },
      [200],
    );

  try {
    await waitForHttp(`${roomUrl}/vault/capabilities`);
    passed.push("room capability discovery");

    const ownerEmail = `vault-room-gate-${randomUUID()}@example.invalid`;
    const ownerPassword = `${randomBytes(24).toString("base64url")}Aa1!`;
    sensitiveValues.push(ownerPassword);

    const createdOwner = await request(
      "create isolated owner",
      `${status.apiUrl}/auth/v1/admin/users`,
      {
        method: "POST",
        headers: jsonHeaders(status.serviceRoleKey),
        body: JSON.stringify({
          email: ownerEmail,
          email_confirm: true,
          password: ownerPassword,
        }),
      },
      [200],
    );
    ownerId = createdOwner && createdOwner.id;
    assertGate(
      typeof ownerId === "string",
      "create isolated owner",
      "INVALID_USER",
    );

    const login = await request(
      "login isolated owner",
      `${status.apiUrl}/auth/v1/token?grant_type=password`,
      {
        method: "POST",
        headers: jsonHeaders(status.anonKey),
        body: JSON.stringify({ email: ownerEmail, password: ownerPassword }),
      },
      [200],
    );
    ownerToken = login && login.access_token;
    assertGate(
      typeof ownerToken === "string",
      "login isolated owner",
      "NO_TOKEN",
    );
    sensitiveValues.push(ownerToken);

    vaultId = randomUUID();
    const activeRoomId = `roomgate_${randomBytes(16).toString("base64url")}`;
    const editorCapability = randomCapability();
    const viewerCapability = randomCapability();
    const editor2Capability = randomCapability();
    const sentinelCiphertext = randomBytes(24).toString("base64url");
    sensitiveValues.push(
      editorCapability,
      viewerCapability,
      editor2Capability,
      sentinelCiphertext,
    );

    const createdVault = await rpc("create_vault", {
      p_editor_capability_hash: capabilityHash(vaultId, editorCapability),
      p_editor_expires_at: null,
      p_protocol_version: 1,
      p_vault_id: vaultId,
    });
    const editorInvitationId = createdVault && createdVault.invitationId;
    assertGate(
      typeof editorInvitationId === "string",
      "create vault",
      "NO_EDITOR_INVITATION",
    );
    await rpc("activate_vault", {
      p_active_room_id: activeRoomId,
      p_vault_id: vaultId,
    });
    const viewerInvitation = await rpc("create_vault_invitation", {
      p_capability_hash: capabilityHash(vaultId, viewerCapability),
      p_expires_at: null,
      p_role: "viewer",
      p_vault_id: vaultId,
    });
    const viewerInvitationId =
      viewerInvitation && viewerInvitation.invitationId;
    assertGate(
      typeof viewerInvitationId === "string",
      "create viewer invitation",
      "NO_INVITATION",
    );
    passed.push("isolated Vault lifecycle setup");

    const wrongCapability = randomCapability();
    sensitiveValues.push(wrongCapability);
    const idOnlySocket = await connectSocket(roomUrl, sockets);
    const idOnlyAck = await joinVault(idOnlySocket, {
      capability: wrongCapability,
      senderSessionId: randomUUID(),
      vaultId,
    });
    assertGate(
      idOnlyAck &&
        idOnlyAck.ok === false &&
        idOnlyAck.code === "VAULT_CAPABILITY_INVALID",
      "id-only admission",
      "NOT_REJECTED",
    );
    passed.push("vault ID alone rejected");

    const editorSender = randomUUID();
    const viewerSender = randomUUID();
    const editor = await connectSocket(roomUrl, sockets);
    const viewer = await connectSocket(roomUrl, sockets);
    const editorAck = await joinVault(editor, {
      capability: editorCapability,
      senderSessionId: editorSender,
      vaultId,
    });
    const viewerAck = await joinVault(viewer, {
      capability: viewerCapability,
      senderSessionId: viewerSender,
      vaultId,
    });
    assertGate(
      editorAck &&
        editorAck.ok === true &&
        editorAck.resolution.role === "editor",
      "editor admission",
      "FAILED",
    );
    assertGate(
      viewerAck &&
        viewerAck.ok === true &&
        viewerAck.resolution.role === "viewer",
      "viewer admission",
      "FAILED",
    );
    passed.push("real Supabase editor/viewer admission");

    const ordinaryRoom = `ordinary_${randomBytes(12).toString("base64url")}`;
    const ordinaryA = await connectSocket(roomUrl, sockets);
    const ordinaryB = await connectSocket(roomUrl, sockets);
    ordinaryA.emit("join-room", ordinaryRoom);
    const legacyNewUser = waitForEvent(ordinaryA, "new-user");
    ordinaryB.emit("join-room", ordinaryRoom);
    await legacyNewUser;

    const internalRoomAttacker = await connectSocket(roomUrl, sockets);
    internalRoomAttacker.emit("join-room", `vault@${activeRoomId}`);
    editor.emit("join-room", ordinaryRoom);
    await expectNoEvent(editor, "client-broadcast", async () => {
      ordinaryA.emit(
        "server-broadcast",
        ordinaryRoom,
        Buffer.from([1, 2, 3]),
        Buffer.alloc(12),
      );
    });
    passed.push("legacy room and Vault namespace isolated");

    const viewerContent = makeEnvelope({
      ciphertext: sentinelCiphertext,
      messageType: "realtime.content",
      senderSessionId: viewerSender,
      sequence: 1,
      vaultId,
    });
    await expectNoEvent(editor, "vault:server", async () => {
      const ack = await emitAck(
        viewer,
        "vault:server",
        activeRoomId,
        viewerContent,
      );
      assertGate(
        ack && ack.ok === false && ack.code === "VAULT_CAPABILITY_FORBIDDEN",
        "viewer content",
        "NOT_REJECTED",
      );
    });
    passed.push("viewer content rejected");

    const viewerPresence = makeEnvelope({
      ciphertext: sentinelCiphertext,
      messageType: "realtime.presence",
      senderSessionId: viewerSender,
      sequence: 2,
      vaultId,
    });
    const presenceReceived = waitForEvent(editor, "vault:server");
    const presenceAck = await emitAck(
      viewer,
      "vault:server-volatile",
      activeRoomId,
      viewerPresence,
    );
    const presence = await presenceReceived;
    assertGate(
      presenceAck && presenceAck.ok === true,
      "viewer presence",
      "REJECTED",
    );
    assertGate(
      presence &&
        presence.admittedSenderSessionId === viewerSender &&
        presence.envelope.senderSessionId === viewerSender,
      "viewer presence",
      "SOURCE_NOT_BOUND",
    );
    passed.push("viewer encrypted presence allowed");

    const editorContent = makeEnvelope({
      ciphertext: sentinelCiphertext,
      messageType: "realtime.content",
      senderSessionId: editorSender,
      sequence: 1,
      vaultId,
    });
    let editorContentAck;
    let editorContentRelay;
    await expectNoEvent(internalRoomAttacker, "vault:server", async () => {
      const editorContentReceived = waitForEvent(viewer, "vault:server");
      editorContentAck = await emitAck(
        editor,
        "vault:server",
        activeRoomId,
        editorContent,
      );
      editorContentRelay = await editorContentReceived;
    });
    assertGate(
      editorContentAck && editorContentAck.ok === true,
      "editor content",
      "REJECTED",
    );
    assertGate(
      editorContentRelay &&
        editorContentRelay.admittedSenderSessionId === editorSender &&
        editorContentRelay.envelope.messageId === editorContent.messageId,
      "editor content",
      "RELAY_MISMATCH",
    );
    passed.push("editor content allowed and internal room hidden");

    const spoofedEnvelope = makeEnvelope({
      ciphertext: sentinelCiphertext,
      messageType: "realtime.content",
      senderSessionId: randomUUID(),
      sequence: 2,
      vaultId,
    });
    await expectNoEvent(viewer, "vault:server", async () => {
      const ack = await emitAck(
        editor,
        "vault:server",
        activeRoomId,
        spoofedEnvelope,
      );
      assertGate(
        ack && ack.ok === false && ack.code === "VAULT_CAPABILITY_FORBIDDEN",
        "sender session spoof",
        "NOT_REJECTED",
      );
    });
    passed.push("sender session spoof rejected");

    const revoked = await rpc("revoke_vault_invitation", {
      p_invitation_id: viewerInvitationId,
      p_vault_id: vaultId,
    });
    assertGate(
      revoked && revoked.authorizationVersion === 2,
      "revoke viewer invitation",
      "VERSION_NOT_INCREMENTED",
    );

    const rejectedViewer = await connectSocket(roomUrl, sockets);
    const rejectedViewerAck = await joinVault(rejectedViewer, {
      capability: viewerCapability,
      senderSessionId: randomUUID(),
      vaultId,
    });
    assertGate(
      rejectedViewerAck &&
        rejectedViewerAck.ok === false &&
        rejectedViewerAck.code === "VAULT_CAPABILITY_REVOKED",
      "revoked viewer reconnect",
      "NOT_REJECTED",
    );

    const viewerRevokedNotice = waitForEvent(
      viewer,
      "vault:capability-revoked",
    );
    const viewerDisconnected = waitForDisconnect(viewer);
    const invitationDisconnectStarted = Date.now();
    await request(
      "invitation disconnect notice",
      `${roomUrl}/vault/control-plane/disconnect`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${controlPlaneToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          authorizationVersion: revoked.authorizationVersion,
          invitationId: viewerInvitationId,
          reason: "revoked",
          vaultId,
        }),
      },
      [204],
    );
    const revokedNotice = await viewerRevokedNotice;
    await viewerDisconnected;
    assertGate(
      Date.now() - invitationDisconnectStarted < 1_500,
      "invitation disconnect notice",
      "NOT_IMMEDIATE",
    );
    assertGate(
      revokedNotice &&
        revokedNotice.invitationId === viewerInvitationId &&
        revokedNotice.authorizationVersion === 2 &&
        revokedNotice.reason === "revoked",
      "invitation disconnect notice",
      "NOTICE_MISMATCH",
    );
    assertGate(
      editor.connected,
      "invitation disconnect notice",
      "WRONG_SOCKET_CLOSED",
    );
    passed.push("invitation revoke blocks reconnect and closes live socket");

    const expiringCapability = randomCapability();
    sensitiveValues.push(expiringCapability);
    const expiresAt = Date.now() + 4_500;
    const expiringInvitation = await rpc("create_vault_invitation", {
      p_capability_hash: capabilityHash(vaultId, expiringCapability),
      p_expires_at: new Date(expiresAt).toISOString(),
      p_role: "viewer",
      p_vault_id: vaultId,
    });
    assertGate(
      expiringInvitation && typeof expiringInvitation.invitationId === "string",
      "create expiring invitation",
      "FAILED",
    );
    const expiringSocket = await connectSocket(roomUrl, sockets);
    const expiringAck = await joinVault(expiringSocket, {
      capability: expiringCapability,
      senderSessionId: randomUUID(),
      vaultId,
    });
    assertGate(
      expiringAck && expiringAck.ok === true,
      "expiry admission",
      "FAILED",
    );
    const expiryNotice = await waitForEvent(
      expiringSocket,
      "vault:capability-expired",
      8_000,
    );
    await waitForDisconnect(expiringSocket);
    assertGate(
      expiryNotice && expiryNotice.reason === "expired",
      "expiry timer",
      "NOTICE_MISMATCH",
    );
    assertGate(Date.now() <= expiresAt + 2_000, "expiry timer", "TOO_LATE");
    passed.push("database expiry closes live socket");

    const editor2Invitation = await rpc("create_vault_invitation", {
      p_capability_hash: capabilityHash(vaultId, editor2Capability),
      p_expires_at: null,
      p_role: "editor",
      p_vault_id: vaultId,
    });
    assertGate(
      editor2Invitation && typeof editor2Invitation.invitationId === "string",
      "create second editor",
      "FAILED",
    );
    const editor2 = await connectSocket(roomUrl, sockets);
    const editor2Ack = await joinVault(editor2, {
      capability: editor2Capability,
      senderSessionId: randomUUID(),
      vaultId,
    });
    assertGate(
      editor2Ack && editor2Ack.ok === true,
      "second editor admission",
      "FAILED",
    );

    const vaultRevoked = await rpc("revoke_vault", { p_vault_id: vaultId });
    assertGate(
      vaultRevoked && vaultRevoked.reason === "vault-revoked",
      "revoke vault",
      "FAILED",
    );
    const rejectedAfterVaultRevoke = await connectSocket(roomUrl, sockets);
    const rejectedAfterVaultRevokeAck = await joinVault(
      rejectedAfterVaultRevoke,
      {
        capability: editor2Capability,
        senderSessionId: randomUUID(),
        vaultId,
      },
    );
    assertGate(
      rejectedAfterVaultRevokeAck &&
        rejectedAfterVaultRevokeAck.ok === false &&
        rejectedAfterVaultRevokeAck.code === "VAULT_NOT_ACTIVE",
      "vault revoked reconnect",
      "NOT_REJECTED",
    );

    const editor1VaultNotice = waitForEvent(editor, "vault:capability-revoked");
    const editor2VaultNotice = waitForEvent(
      editor2,
      "vault:capability-revoked",
    );
    const editor1Disconnected = waitForDisconnect(editor);
    const editor2Disconnected = waitForDisconnect(editor2);
    const vaultDisconnectStarted = Date.now();
    await request(
      "vault-wide disconnect notice",
      `${roomUrl}/vault/control-plane/disconnect`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${controlPlaneToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reason: "vault-revoked", vaultId }),
      },
      [204],
    );
    const [editor1Notice, editor2Notice] = await Promise.all([
      editor1VaultNotice,
      editor2VaultNotice,
      editor1Disconnected,
      editor2Disconnected,
    ]);
    assertGate(
      Date.now() - vaultDisconnectStarted < 1_500,
      "vault-wide disconnect notice",
      "NOT_IMMEDIATE",
    );
    assertGate(
      editor1Notice.reason === "vault-revoked" &&
        editor2Notice.reason === "vault-revoked",
      "vault-wide disconnect notice",
      "NOTICE_MISMATCH",
    );
    assertGate(
      ordinaryA.connected && ordinaryB.connected,
      "vault-wide disconnect notice",
      "LEGACY_SOCKET_CLOSED",
    );
    passed.push("vault-wide revoke fans out without closing legacy sockets");

    const logs = roomLogs.join("");
    assertGate(
      sensitiveValues.every((value) => !value || !logs.includes(value)),
      "room log scan",
      "SENSITIVE_VALUE_FOUND",
    );
    passed.push(
      "room logs contain no capability, token, key, or sentinel ciphertext",
    );

    console.log(
      `vault room ${IS_REMOTE_GATE ? "remote" : "local"} real gate passed (${
        passed.length
      } checks)`,
    );
    for (const name of passed) {
      console.log(`- ${name}`);
    }
  } finally {
    for (const socket of sockets) {
      socket.removeAllListeners();
      socket.close();
    }

    if (ownerToken && vaultId) {
      try {
        await rpc("soft_delete_vault", { p_vault_id: vaultId });
      } catch {
        // Deleting the isolated auth user below cascades any remaining Vault rows.
      }
    }

    if (ownerId) {
      try {
        await request(
          "delete isolated owner",
          `${status.apiUrl}/auth/v1/admin/users/${ownerId}?should_soft_delete=false`,
          {
            method: "DELETE",
            headers: jsonHeaders(status.serviceRoleKey),
          },
          [200],
        );
      } catch {
        console.error("cleanup: isolated owner deletion failed");
        process.exitCode = 1;
      }
    }

    if (!roomProcess.killed) {
      roomProcess.kill();
    }
  }
};

main().catch((error) => {
  const message =
    error instanceof GateError ? error.message : "unexpected failure";
  console.error(`vault room real gate failed: ${message}`);
  process.exitCode = 1;
});
