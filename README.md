# Signal CLI REST API Service (Native Go + Alpine)

A lightweight, custom-built Signal CLI REST and WebSocket API service written in **Go** and packaged on **Alpine Linux** with native `signal-cli`.

Built from scratch without relying on third-party prepackaged images.

---

### Key Capabilities
- **Unified Admin UI & API (`/admin`)**: Built-in Admin UI (`/admin`) to configure Signal account profiles (First Name, optional Last Name, and Profile Photo via `/api/accounts/profile`) and issue or revoke scoped API keys for client services (`/api/keys`).
- **Strict Short-Lived Admin Sessions (< 5 Minutes)**: The Admin UI issues short-lived ephemeral session tokens that strictly expire in **3 minutes** (with a 2-minute inactivity auto-lock). Once expired, fresh authentication with `API_KEY_MGMT` is required. The UI displays an active countdown timer badge (`🔒 Session: 02:45`).
- **Root Admin Key (`API_KEY_MGMT`)**: The environment variable `API_KEY_MGMT` serves as the root master key. Only this key is authorized to access the Admin UI, update account profiles, and generate new client keys.
- **Native Go Architecture**: Statically compiled Go server (~9 MB) with zero external dependencies, handling HTTP routing, WebSocket streaming, and JSON-RPC daemon orchestration.
- **Ultra-lightweight Hardened Container**: Runs as an unprivileged user (`10001:10001`) on Alpine Linux (`alpine:3.24.4`) with `read_only` root filesystem, `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit`, and native `signal-cli` (`musl`-compiled `libsignal-client`).
- **Security-First (Terminal Registration Only)**: Initial registration (including numberless `--recovery-key`) is strictly performed via terminal commands inside the container (`./register.sh`). HTTP registration routes are blocked with `403 Forbidden` to prevent credential exposure over the network.
- **OpenAPI 3.0 & Swagger UI**: Built-in canonical OpenAPI specification (`/openapi.json`) and interactive documentation UI (`/docs`).
- **Persistent Storage**: Cryptographic keys, account state, and issued client API keys are persisted in the `signal-data` Docker volume (`/home/.local/share/signal-cli`).

---

## Web UI & Documentation Endpoints

Once the container is running:

- **Admin UI**: [`http://localhost:8080/admin`](http://localhost:8080/admin) (authenticate using `API_KEY_MGMT`, auto-expires after 3 minutes; `/keys` redirects to `/admin`)
- **Interactive Swagger UI**: [`http://localhost:8080/docs`](http://localhost:8080/docs) (or `/swagger`)
- **OpenAPI 3.0 JSON Specification**: [`http://localhost:8080/openapi.json`](http://localhost:8080/openapi.json) (or `/swagger.json`)

---

## Configuration & Deployment

### 1. Configure `.env`

```bash
cp .env.example .env
```

Review [.env.example](.env.example):
```dotenv
PORT=8080

# Root Administration Key (min 16 chars; generate with: openssl rand -hex 32)
API_KEY_MGMT=
```

> **TLS & Reverse Proxy Note:** In production, deploy behind a TLS-terminating reverse proxy (e.g., Caddy, Nginx, or Traefik) and keep the container bound to `127.0.0.1:8080`. By default, the server trusts **no** proxy headers (`X-Forwarded-Proto`, `X-Forwarded-Host`, or `TRUSTED_PROXY_HEADER`) unless `TRUSTED_PROXIES` is explicitly configured with the proxy's IP/CIDR. If browser WebSocket clients pass `?token=` on `/v1/receive/<ACCOUNT>`, configure your reverse proxy to omit query strings from access logs so tokens are not written to disk.

### 2. Start the Container (Persistent Volume)

All persistent state lives under `/home/.local/share/signal-cli` inside the container:
- **Signal account registrations & cryptographic keys** (`data/accounts.json` and per-account identity/session stores) — so you **never** have to re-register or re-link your Signal account when the container restarts or is updated.
- **Issued client API keys** (`api_keys.json`, stored as SHA-256 hashes with metadata).

[`docker-compose.yml`](docker-compose.yml) pulls `ghcr.io/timcappalli/signal-cli-api:latest` and mounts a named Docker volume (`signal-data:/home/.local/share/signal-cli`) by default. Docker automatically initializes the volume with `0700` permissions and `10001:10001` ownership from the image:

```bash
docker compose up -d
```

*(If you instead use a host bind mount like `./data:/home/.local/share/signal-cli`, create it first with `mkdir -p data && chmod 700 data && sudo chown -R 10001:10001 data` so the unprivileged `10001:10001` container user can write to it.)*

### 3. Running Behind Caddy (TLS & WebSocket Considerations)

Caddy 2 proxies WebSockets (`Upgrade: websocket`) automatically without special header rules, but because `signal-api` enforces strict `Host`, `Origin` (scheme + host + port), and proxy-trust checks on both HTTP routes and WebSocket upgrades (`/v1/receive/<ACCOUNT>`), configure the following:

1. **Required `.env` Settings Behind Caddy**
   - **`ALLOWED_HOSTS`**: Must include your public domain (e.g., `ALLOWED_HOSTS=signal.example.com`). Requests with any other `Host` header are rejected with `403 Forbidden`.
   - **`TRUSTED_PROXIES`**: Must explicitly list the source IP/CIDR that `signal-api` sees for Caddy (e.g., `127.0.0.1/32,::1/128` when Caddy runs on the host, or the Docker bridge subnet/container IP when Caddy runs in Docker).
     - **Why this matters for WebSockets & `POST` requests**: Browsers send `Origin: https://signal.example.com` on WebSocket handshakes and `POST` requests, while Caddy connects to `signal-api` over plain `http://127.0.0.1:8080` and sets `X-Forwarded-Proto: https`. Since `signal-api` trusts **no** proxy IPs by default, omitting `TRUSTED_PROXIES` causes `signal-api` to ignore `X-Forwarded-Proto: https` and reject browser WebSocket upgrades and Admin UI logins with `403 Forbidden` (`https` Origin vs. `http` backend).
   - **`TRUSTED_PROXY_HEADER=X-Forwarded-For`**: Allows `signal-api`'s login throttle to bucket failed attempts by the real client IP rather than Caddy's IP.
   - **`ALLOWED_ORIGINS`** *(optional)*: Only needed if browser WebSocket or API clients connect cross-origin from a different frontend origin (e.g., `ALLOWED_ORIGINS=https://app.example.com`).

2. **WebSocket Keepalive & Timeouts**
   - `signal-api` sends RFC 6455 `Ping` control frames every **25 seconds** and closes connections that do not answer with a `Pong` within **35 seconds** (`429 Too Many Requests` is returned if a single key exceeds **8** concurrent sockets or the server exceeds **128** total).
   - Caddy's `reverse_proxy` has no stream timeout by default, which works out of the box. If you customize `transport http` timeouts in your `Caddyfile`, keep `read_timeout` >= `60s` (above the 25s ping interval) so idle WebSocket streams are not closed prematurely by Caddy.

3. **Redacting `?token=` from Caddy Access Logs**
   - Non-browser WebSocket clients should authenticate with `Authorization: Bearer sig_...` or `X-API-Key: sig_...` during the handshake.
   - If browser WebSocket clients use `wss://signal.example.com/v1/receive/<ACCOUNT>?token=sig_...`, use Caddy's `log` `filter` directive to redact the `token` query parameter so keys are never written to access logs:

```caddyfile
signal.example.com {
	log {
		output file /var/log/caddy/signal-access.log
		format filter {
			wrap json
			fields {
				uri query {
					replace token REDACTED
				}
			}
		}
	}

	reverse_proxy 127.0.0.1:8080
}
```

---

## Admin UI: Account Profile & API Keys

### Via Web UI (`/admin`)
1. Navigate to `http://localhost:8080/admin` in your browser.
2. Enter your root admin key (`API_KEY_MGMT`).
3. A secure **3-minute session** is initialized with a live countdown display in the header (`🔒 Session: 03:00`). Both the server and UI enforce a **3-minute hard expiration** and a **2-minute inactivity auto-lock**.
4. **Account Profile**: Select or enter an Account ID (`+15551234567` or ACI UUID), enter a **First Name** (required), an optional **Last Name**, and optionally upload a **Profile Photo** (PNG, JPEG, WebP, or GIF, up to 3 MB), then click **Save Profile**. This runs `signal-cli -a <ACCOUNT_ID> updateProfile --given-name <GIVEN_NAME> [--family-name <FAMILY_NAME>] [--avatar <IMAGE_PATH>]`.
5. **API Keys**: Enter a Service Name (e.g. `IETF Moderator`), Allowed Accounts (e.g. `+15551234567`), select permissions (`send`, `receive`, `admin`), and click **Generate Key**.
6. Copy the generated key (e.g. `sig_8a3f2b...`) and paste it into the client service's configuration (`SIGNAL_API_KEY`).

### Via REST API
Authenticate with `API_KEY_MGMT` at `/api/auth/login` to obtain a short-lived admin session token (`adm_sess_...`):

```bash
# 1. Exchange root admin key for a 3-minute session token
SESSION_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"admin_key": "<API_KEY_MGMT>"}' | jq -r .token)

# 2. Update an account's profile name and optional avatar
curl -X POST http://localhost:8080/api/accounts/profile \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account": "+15551234567", "given_name": "IETF", "family_name": "Moderator"}'

# 3. List all active client keys
curl -H "Authorization: Bearer $SESSION_TOKEN" http://localhost:8080/api/keys

# 4. Create a new scoped key for a service
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "IETF Moderator Bot", "accounts": ["+15551234567"], "permissions": ["send", "receive"]}'

# 5. Revoke a key
curl -X DELETE http://localhost:8080/api/keys/<KEY_ID> \
  -H "Authorization: Bearer $SESSION_TOKEN"
```

---

## Signal Account Registration & Linking (Terminal Only)

Account credentials and recovery keys are kept out of environment variables. Use the provided [`register.sh`](register.sh) helper to manage accounts:

### Option A: Register a Numberless Account via Recovery Key (Recommended)
```bash
# Prompts securely (never pass the recovery key as a CLI argument, which exposes it in ps and shell history):
./register.sh recovery "<ACCOUNT_ID>"

# Or pipe via stdin:
printf '%s\n' "$RECOVERY_KEY" | ./register.sh recovery "<ACCOUNT_ID>"
```

### Option B: Link a Secondary Device via QR Code
```bash
./register.sh link "my-bot-device"
```

### Option C: Set or Update a Signal Username
```bash
./register.sh username <ACCOUNT_UUID> <DESIRED_USERNAME>
```

### Option D: Register a Phone Number via SMS
```bash
# Request SMS code
./register.sh register +15551234567

# Verify with code
./register.sh verify +15551234567 123456
```

---

## Client Service Authentication

Client services connect to the Signal API using their assigned service API key:

### 1. HTTP Authorization Header (Recommended)
```bash
curl -H "Authorization: Bearer sig_8a3f2b..." \
  http://localhost:8080/v1/accounts
```

### 2. X-API-Key Header
```bash
curl -H "X-API-Key: sig_8a3f2b..." \
  http://localhost:8080/v1/accounts
```

### 3. WebSocket Real-time Event Stream
```
ws://localhost:8080/v1/receive/<ACCOUNT>?token=sig_8a3f2b...
```
*(Prefer sending `Authorization: Bearer sig_...` during the WebSocket HTTP handshake for non-browser clients; when browser clients use `?token=`, ensure your reverse proxy does not log URL query strings).*

---

## Node.js / TypeScript Example: Send a Message & Act on the User's Reply

> **Try it directly:** A ready-to-run zero-dependency CLI script is included in [`samples/message.ts`](samples/message.ts) (see [`samples/README.md`](samples/README.md)):
> ```bash
> SIGNAL_ACCOUNT="+15550001111" SIGNAL_API_KEY="sig_..." \
>   node samples/message.ts --message="Approve action?" --destphone="+15559876543"
> ```

Below is a library-style example (Node.js 22+ or TypeScript with [`ws`](https://github.com/websockets/ws)) showing how a calling service can:
1. Open a WebSocket stream to `/v1/receive/<ACCOUNT>` using a scoped API key (`send` + `receive` permissions).
2. Send an interactive prompt to a user via `POST /v2/send`.
3. Listen for the user's text reply (or emoji reaction to the prompt) and trigger an action in response.

```typescript
import WebSocket from "ws";

const SIGNAL_API_URL = process.env.SIGNAL_API_URL ?? "http://localhost:8080";
const SIGNAL_WS_URL = SIGNAL_API_URL.replace(/^http/, "ws");
const SIGNAL_API_KEY = process.env.SIGNAL_API_KEY!; // Scoped key with ["send", "receive"]
const BOT_ACCOUNT = process.env.SIGNAL_ACCOUNT!;    // e.g. "+15551234567" or account UUID

interface SignalReceiveNotification {
  jsonrpc: "2.0";
  method: "receive";
  params?: {
    account?: string;
    envelope?: {
      source?: string;
      sourceNumber?: string;
      sourceUuid?: string;
      timestamp?: number;
      dataMessage?: {
        timestamp?: number;
        message?: string;
        quote?: { id?: number; author?: string; text?: string };
        reaction?: {
          emoji?: string;
          targetAuthor?: string;
          targetSentTimestamp?: number;
          isRemove?: boolean;
        };
      };
    };
  };
}

async function sendSignalMessage(recipient: string, message: string): Promise<number> {
  const res = await fetch(`${SIGNAL_API_URL}/v2/send`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SIGNAL_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      number: BOT_ACCOUNT,
      recipients: [recipient],
      message,
    }),
  });

  if (!res.ok) {
    throw new Error(`Failed to send message (${res.status}): ${await res.text()}`);
  }

  const data = (await res.json()) as { timestamp?: number };
  return data.timestamp ?? Date.now();
}

async function requestUserApproval(targetUser: string, actionDescription: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const wsUrl = `${SIGNAL_WS_URL}/v1/receive/${encodeURIComponent(BOT_ACCOUNT)}`;

    // Pass the Bearer key in the HTTP upgrade header (keeps the token out of URLs/logs)
    // `ws` automatically responds to the server's 25-second RFC 6455 Ping frames with Pong.
    const ws = new WebSocket(wsUrl, {
      headers: { Authorization: `Bearer ${SIGNAL_API_KEY}` },
    });

    let promptTimestamp = 0;

    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error("Timed out waiting for user response"));
    }, 5 * 60_000);

    ws.on("open", async () => {
      try {
        promptTimestamp = await sendSignalMessage(
          targetUser,
          `Action requested: ${actionDescription}\n\nReply "YES" (or 👍) to approve, or "NO" (or 👎) to reject.`
        );
      } catch (err) {
        clearTimeout(timeout);
        ws.close();
        reject(err);
      }
    });

    ws.on("message", (raw) => {
      let evt: SignalReceiveNotification;
      try {
        evt = JSON.parse(raw.toString()) as SignalReceiveNotification;
      } catch {
        return;
      }

      const env = evt.params?.envelope;
      const dm = env?.dataMessage;
      if (!env || !dm) return;

      // Match messages from the target user (by E.164 number or UUID)
      const sender = env.sourceNumber ?? env.sourceUuid ?? env.source;
      if (sender !== targetUser) return;

      // Case 1: User reacted with 👍 / 👎 to the prompt message
      if (dm.reaction && !dm.reaction.isRemove && dm.reaction.targetSentTimestamp === promptTimestamp) {
        if (dm.reaction.emoji === "👍") {
          clearTimeout(timeout);
          ws.close();
          resolve(true);
          return;
        }
        if (dm.reaction.emoji === "👎") {
          clearTimeout(timeout);
          ws.close();
          resolve(false);
          return;
        }
      }

      // Case 2: User sent a text reply ("yes" / "no")
      const text = dm.message?.trim().toLowerCase();
      if (text === "yes" || text === "y" || text === "approve") {
        clearTimeout(timeout);
        ws.close();
        resolve(true);
      } else if (text === "no" || text === "n" || text === "reject") {
        clearTimeout(timeout);
        ws.close();
        resolve(false);
      }
    });

    ws.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

// Example usage:
const user = "+15559876543";
const approved = await requestUserApproval(user, "Deploy release v1.4.2 to production");

if (approved) {
  await sendSignalMessage(user, "✅ Approved — starting production deployment.");
  // ... perform action ...
} else {
  await sendSignalMessage(user, "❌ Deployment cancelled.");
}
```
