# Example of excalidraw collaboration server

Collaboration server for Excalidraw

If you need to use cluster mode with pm2. Checkout: https://socket.io/docs/v4/pm2/

If you are not familiar with pm2: https://pm2.keymetrics.io/docs/usage/quick-start/

# Development

- install

  ```sh
  yarn
  ```

- run development server

  ```sh
  yarn start:dev
  ```

## Vault Online (protocol v1)

Vault support is disabled by default. The ordinary Excalidraw collaboration events remain unchanged. Vault sockets use separate fail-closed events and are never admitted through `join-room`:

- `vault:join`
- `vault:server`
- `vault:server-volatile`
- `vault:capability-revoked`
- `vault:capability-expired`

Set all required variables before the room capability endpoint advertises protocol v1:

```sh
VAULT_ENABLED=true
VAULT_SUPABASE_URL=https://project-ref.supabase.co
VAULT_SUPABASE_ANON_KEY=<project-anon-key>
VAULT_CONTROL_PLANE_TOKEN=<control-plane-token>
VAULT_CAPABILITY_RESOLVE_TIMEOUT_MS=5000
VAULT_MAX_PAYLOAD_BYTES=1048576
VAULT_MAX_MESSAGES_PER_MINUTE=1200
VAULT_MAX_CONNECTIONS_PER_VAULT=64
CORS_ORIGIN=https://vault.example.com
```

Production Vault readiness additionally requires an explicit HTTPS
`CORS_ORIGIN` allowlist and a control-plane token of at least 32 characters.
Wildcards and ordinary HTTP LAN origins keep Vault fail-closed. The optional
`VAULT_ALLOW_DOCKER_HOST_HTTP=true` escape hatch accepts only
`http://host.docker.internal` and is reserved for the documented local Docker
smoke; it must not be enabled in production.

The room server calls the Supabase `/rest/v1/rpc/resolve_vault_capability` endpoint with only the frozen `p_vault_id` and `p_capability` parameters. It sends the anon key in the `apikey` and bearer headers and converts the RPC ISO `expiresAt` timestamp to epoch milliseconds for the socket contract. Plain HTTP is accepted only for localhost Supabase. Neither the request body nor the raw invitation capability is logged, and the room server never accepts a Vault root/content key.

Runtime endpoints:

- `GET /vault/capabilities` returns protocol v1 only when all required Vault gates are configured. The exact F4 document includes `deploymentVersion=p4a-f4-v1`, `roomServerVersion=1`, and `protocolVersions=[1]`.
- `POST /vault/rooms` accepts only `{ protocolVersion, vaultId, invitationId }` and returns a fresh random `{ protocolVersion, activeRoomId }`. It does not create persistent room state, activate a Vault, validate access, or accept a key/capability. The authenticated owner must bind the returned channel through the separate Vault activation RPC before capability-based socket admission can succeed.
- `POST /vault/control-plane/disconnect` requires the control-plane bearer token and accepts only the frozen revoke/expire notice metadata. Matching sockets receive the dedicated control event and are disconnected immediately.

Viewer admissions may relay only `realtime.presence`. Editor admissions may also relay `realtime.content`. The server validates the envelope class, Vault/session binding, exact active room, and payload size, then injects its own `sourceSocketId` and admitted sender session before broadcasting. It never falls back to the ordinary room events or persistence paths.

The production server also enforces bounded per-socket message rates and a
maximum number of active sockets per Vault. `/healthz` is liveness;
`/readyz` returns 503 when Vault was requested but its production configuration
is incomplete. Vault structured logs pass through the frozen metadata
allowlist and never include capabilities, keys, envelopes, Authorization
headers, or request bodies.

Admitted sockets are placed only in the internal `vault@<activeRoomId>` room. Legacy joins and broadcasts reject that namespace, and a socket already joined to an ordinary application room cannot later be admitted as a Vault socket.

Run the Vault contract tests with:

```sh
yarn test:vault
```

The production Dockerfile uses Node 20, a multi-stage build, a non-root runtime
user, an unprivileged port, and `/readyz` health checks. TLS termination and
public access logs belong at the reverse proxy described by the main
repository's `deploy/vault-self-hosted/` package.

Run the 13-check real Socket.IO gate against the local Supabase CLI stack with:

```sh
yarn test:vault:real
```

For the disposable hosted Supabase acceptance project, keep its project ref and personal access token only in the main repository's ignored `scripts/vault/remote.local.env`, then run:

```sh
yarn test:vault:remote
```

The remote wrapper requires the same exact disposable-project confirmations as the main repository workflow. It obtains the hosted project's legacy anon and service-role keys through the Supabase CLI, keeps them only in process memory, and binds the gate to the exact `https://<project-ref>.supabase.co` origin. It does not deploy schema, reset the project, persist a Supabase link, or write API keys to disk. Each run uses a random room-server port, Vault, room, capabilities, and auth user, and removes its isolated fixtures in `finally`.

# Start with pm2

```
pm2 start pm2.production.json
```
