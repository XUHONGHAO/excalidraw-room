import debug from "debug";
import express from "express";
import http from "http";
import { Server as SocketIO } from "socket.io";

import {
  assertVaultRoomProvisionRequest,
  createBearerTokenChecker,
  createSupabaseVaultCapabilityResolver,
  getVaultHttpCorsHeaders,
  isVaultInternalRoomName,
  issueVaultRoomProvision,
  parseVaultAllowedOrigins,
  VAULT_DEPLOYMENT_VERSION,
  VAULT_PROTOCOL_VERSION,
  VAULT_ROOM_SERVER_VERSION,
  VaultRoomServer,
  VaultServerError,
} from "./vault";

type UserToFollow = {
  socketId: string;
  username: string;
};
type OnUserFollowedPayload = {
  userToFollow: UserToFollow;
  action: "FOLLOW" | "UNFOLLOW";
};

const serverDebug = debug("server");
const ioDebug = debug("io");
const socketDebug = debug("socket");

require("dotenv").config(
  process.env.NODE_ENV !== "development"
    ? { path: ".env.production" }
    : { path: ".env.development" },
);

const app = express();
const port =
  process.env.PORT || (process.env.NODE_ENV !== "development" ? 80 : 3002); // default port to listen

const vaultEnabled = process.env.VAULT_ENABLED === "true";
const vaultSupabaseUrl = process.env.VAULT_SUPABASE_URL;
const vaultSupabaseAnonKey = process.env.VAULT_SUPABASE_ANON_KEY;
const vaultControlPlaneToken = process.env.VAULT_CONTROL_PLANE_TOKEN;
const production = process.env.NODE_ENV === "production";
const readPositiveInteger = (value: string | undefined, fallback: number) => {
  if (!value) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0;
};
let vaultAllowedOrigins: readonly string[] = [];
try {
  vaultAllowedOrigins = parseVaultAllowedOrigins(
    process.env.CORS_ORIGIN,
    !production,
  );
} catch {
  vaultAllowedOrigins = [];
}
const vaultMaxPayloadBytes = readPositiveInteger(
  process.env.VAULT_MAX_PAYLOAD_BYTES,
  1024 * 1024,
);
const vaultMaxMessagesPerMinute = readPositiveInteger(
  process.env.VAULT_MAX_MESSAGES_PER_MINUTE,
  1200,
);
const vaultMaxConnectionsPerVault = readPositiveInteger(
  process.env.VAULT_MAX_CONNECTIONS_PER_VAULT,
  64,
);
const vaultConfigured = Boolean(
  vaultEnabled &&
    vaultSupabaseUrl &&
    vaultSupabaseAnonKey &&
    vaultControlPlaneToken &&
    vaultControlPlaneToken.length >= 32 &&
    vaultAllowedOrigins.length > 0 &&
    vaultMaxPayloadBytes > 0 &&
    vaultMaxMessagesPerMinute > 0 &&
    vaultMaxConnectionsPerVault > 0,
);
let vaultRoomServer: VaultRoomServer | null = null;

const applyVaultBrowserCors = (req: express.Request, res: express.Response) => {
  const headers = getVaultHttpCorsHeaders(
    req.headers.origin,
    process.env.CORS_ORIGIN,
  );
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined) {
      res.setHeader(name, value);
    }
  }
};

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("Excalidraw collaboration server is up :)");
});

app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.get("/readyz", (_req, res) => {
  if (vaultEnabled && !vaultConfigured) {
    res.status(503).json({ status: "not-ready" });
    return;
  }
  res.status(200).json({ status: "ready" });
});

app.options("/vault/capabilities", (req, res) => {
  applyVaultBrowserCors(req, res);
  res.status(204).end();
});
app.get("/vault/capabilities", (req, res) => {
  applyVaultBrowserCors(req, res);
  res.setHeader("Cache-Control", "no-store");
  if (!vaultRoomServer) {
    res.status(503).json({
      deploymentVersion: VAULT_DEPLOYMENT_VERSION,
      roomServerVersion: VAULT_ROOM_SERVER_VERSION,
      protocolVersions: [],
    });
    return;
  }
  res.json({
    deploymentVersion: VAULT_DEPLOYMENT_VERSION,
    roomServerVersion: VAULT_ROOM_SERVER_VERSION,
    protocolVersions: [VAULT_PROTOCOL_VERSION],
  });
});

const vaultRoomProvisionBody = express.json({ limit: "1kb", strict: true });
app.options("/vault/rooms", (req, res) => {
  applyVaultBrowserCors(req, res);
  res.status(204).end();
});
app.post("/vault/rooms", (req, res) => {
  applyVaultBrowserCors(req, res);
  res.setHeader("Cache-Control", "no-store");
  if (!vaultRoomServer) {
    res.status(503).json({ code: "VAULT_PERSISTENCE_UNAVAILABLE" });
    return;
  }
  vaultRoomProvisionBody(req, res, (bodyError?: unknown) => {
    if (bodyError) {
      const bodyErrorType =
        typeof bodyError === "object" && bodyError !== null
          ? (bodyError as { type?: unknown }).type
          : null;
      const code =
        bodyErrorType === "entity.too.large"
          ? "VAULT_PAYLOAD_TOO_LARGE"
          : "VAULT_ROOM_PROTOCOL_UNSUPPORTED";
      res.status(code === "VAULT_PAYLOAD_TOO_LARGE" ? 413 : 400).json({ code });
      return;
    }
    try {
      assertVaultRoomProvisionRequest(req.body);
      res.status(201).json(issueVaultRoomProvision());
    } catch (error) {
      res.status(400).json({
        code:
          error instanceof VaultServerError
            ? error.code
            : "VAULT_ROOM_PROTOCOL_UNSUPPORTED",
      });
    }
  });
});

const vaultControlPlaneBody = express.json({ limit: "16kb", strict: true });
app.post(
  "/vault/control-plane/disconnect",
  vaultControlPlaneBody,
  (req, res) => {
    if (!vaultRoomServer || !vaultControlPlaneToken) {
      res.status(503).json({ code: "VAULT_PERSISTENCE_UNAVAILABLE" });
      return;
    }
    const hasValidToken = createBearerTokenChecker(vaultControlPlaneToken);
    if (!hasValidToken(req.headers.authorization)) {
      res.status(401).json({ code: "VAULT_CAPABILITY_FORBIDDEN" });
      return;
    }
    try {
      vaultRoomServer.disconnectByNotice(req.body);
      res.status(204).end();
    } catch (error) {
      res.status(400).json({
        code: error instanceof VaultServerError ? error.code : "VAULT_INTERNAL",
      });
    }
  },
);

const server = http.createServer(app);

server.listen(port, () => {
  serverDebug(`listening on port: ${port}`);
});

try {
  const io = new SocketIO(server, {
    transports: ["websocket", "polling"],
    cors: {
      allowedHeaders: ["Content-Type", "Authorization"],
      origin: vaultAllowedOrigins.length > 0 ? [...vaultAllowedOrigins] : "*",
      credentials: true,
    },
    allowEIO3: true,
  });

  if (vaultConfigured && vaultSupabaseUrl && vaultSupabaseAnonKey) {
    vaultRoomServer = new VaultRoomServer({
      resolver: createSupabaseVaultCapabilityResolver({
        supabaseUrl: vaultSupabaseUrl,
        anonKey: vaultSupabaseAnonKey,
        timeoutMs:
          Number(process.env.VAULT_CAPABILITY_RESOLVE_TIMEOUT_MS) || 5000,
        allowDockerHostHttp:
          process.env.VAULT_ALLOW_DOCKER_HOST_HTTP === "true",
      }),
      maxPayloadBytes: vaultMaxPayloadBytes,
      maxMessagesPerMinute: vaultMaxMessagesPerMinute,
      maxConnectionsPerVault: vaultMaxConnectionsPerVault,
      logger: (event, metadata) => {
        process.stdout.write(
          `${JSON.stringify({
            level: "info",
            component: "vault-room",
            event,
            ...metadata,
          })}\n`,
        );
      },
    }).attach(io);
  }

  io.on("connection", (socket) => {
    ioDebug("connection established!");
    io.to(`${socket.id}`).emit("init-room");
    socket.on("join-room", async (roomID) => {
      if (
        vaultRoomServer?.isVaultSocketReserved(socket) ||
        typeof roomID !== "string" ||
        isVaultInternalRoomName(roomID)
      ) {
        return;
      }
      socketDebug(`${socket.id} has joined ${roomID}`);
      await socket.join(roomID);
      const sockets = await io.in(roomID).fetchSockets();
      if (sockets.length <= 1) {
        io.to(`${socket.id}`).emit("first-in-room");
      } else {
        socketDebug(`${socket.id} new-user emitted to room ${roomID}`);
        socket.broadcast.to(roomID).emit("new-user", socket.id);
      }

      io.in(roomID).emit(
        "room-user-change",
        sockets.map((socket) => socket.id),
      );
    });

    socket.on(
      "server-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (
          vaultRoomServer?.isVaultSocketReserved(socket) ||
          typeof roomID !== "string" ||
          isVaultInternalRoomName(roomID)
        ) {
          return;
        }
        socketDebug(`${socket.id} sends update to ${roomID}`);
        socket.broadcast.to(roomID).emit("client-broadcast", encryptedData, iv);
      },
    );

    socket.on(
      "server-volatile-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (
          vaultRoomServer?.isVaultSocketReserved(socket) ||
          typeof roomID !== "string" ||
          isVaultInternalRoomName(roomID)
        ) {
          return;
        }
        socketDebug(`${socket.id} sends volatile update to ${roomID}`);
        socket.volatile.broadcast
          .to(roomID)
          .emit("client-broadcast", encryptedData, iv);
      },
    );

    socket.on("user-follow", async (payload: OnUserFollowedPayload) => {
      if (vaultRoomServer?.isVaultSocketReserved(socket)) {
        return;
      }
      const roomID = `follow@${payload.userToFollow.socketId}`;

      switch (payload.action) {
        case "FOLLOW": {
          await socket.join(roomID);

          const sockets = await io.in(roomID).fetchSockets();
          const followedBy = sockets.map((socket) => socket.id);

          io.to(payload.userToFollow.socketId).emit(
            "user-follow-room-change",
            followedBy,
          );

          break;
        }
        case "UNFOLLOW": {
          await socket.leave(roomID);

          const sockets = await io.in(roomID).fetchSockets();
          const followedBy = sockets.map((socket) => socket.id);

          io.to(payload.userToFollow.socketId).emit(
            "user-follow-room-change",
            followedBy,
          );

          break;
        }
      }
    });

    socket.on("disconnecting", async () => {
      socketDebug(`${socket.id} has disconnected`);
      for (const roomID of Array.from(socket.rooms)) {
        const otherClients = (await io.in(roomID).fetchSockets()).filter(
          (_socket) => _socket.id !== socket.id,
        );

        const isFollowRoom = roomID.startsWith("follow@");
        const isVaultRoom = roomID.startsWith("vault@");

        if (isVaultRoom) {
          continue;
        }

        if (!isFollowRoom && otherClients.length > 0) {
          socket.broadcast.to(roomID).emit(
            "room-user-change",
            otherClients.map((socket) => socket.id),
          );
        }

        if (isFollowRoom && otherClients.length === 0) {
          const socketId = roomID.replace("follow@", "");
          io.to(socketId).emit("broadcast-unfollow");
        }
      }
    });

    socket.on("disconnect", () => {
      socket.removeAllListeners();
      socket.disconnect();
    });
  });
} catch {
  process.stderr.write("room-server-startup-failed\n");
  process.exitCode = 1;
}
