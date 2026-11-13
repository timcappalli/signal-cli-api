# Signal CLI API — Node.js / TypeScript Sample

[`message.ts`](message.ts) is a zero-dependency Node.js / TypeScript CLI script (uses Node 22.6+ built-in TypeScript execution) that:
1. Opens a WebSocket stream to `/v1/receive/<ACCOUNT>` using an `Authorization: Bearer <SIGNAL_API_KEY>` header (and automatically answers the server's 25-second RFC 6455 `Ping` frames with `Pong`).
2. Sends a message to a target phone number (`--destphone`) or Signal username (`--destusername`) via `POST /v2/send`.
3. If Signal returns `429` with a `challenge_token`, prompts interactively for a solved `signalcaptcha://...` token, submits it via `POST /v1/accounts/rate-limit-challenge`, and retries sending.
4. Waits for the recipient's reply or emoji reaction, prints the structured JSON response, and exits cleanly.

## Prerequisites

- **Node.js 22.6+** (supports running `.ts` files directly via `node message.ts` with no build step or `npm install`).
- A scoped client API key (`sig_...`) generated in `/admin` with `send` and `receive` permissions (and optionally `challenge` to resolve 429 rate-limit challenges) for your Signal account.

## Usage

1. Copy [`.env.example`](.env.example) to `.env` or `.env.local` (in `samples/` or the repo root):

```bash
cp samples/.env.example samples/.env.local
```

2. Set `SIGNAL_API_URL` and `SIGNAL_API_KEY` in `.env.local` (`SIGNAL_ACCOUNT` is optional when your key is scoped to a single account or only one account is registered), then run:

```bash
# Send to a phone number and wait for their reply or reaction:
node samples/message.ts --message="Approve deployment? Reply YES or react 👍" --destphone="+15559876543"

# Send to a Signal username and wait for their reply or reaction:
node samples/message.ts --message="Hello from signal-cli-api!" --destusername="alice.01"
```

You can also pass `--account`, `--api-key`, `--url`, and `--timeout` directly as flags instead of environment variables:

```bash
node samples/message.ts \
  --url="http://localhost:8080" \
  --account="+15550001111" \
  --api-key="sig_..." \
  --message="Ping! Reply anything to test." \
  --destphone="+15559876543" \
  --timeout="120"
```
