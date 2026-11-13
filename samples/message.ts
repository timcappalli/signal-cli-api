#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import readline from "node:readline/promises";
import type { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

function loadEnvFiles(): void {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const searchDirs = Array.from(new Set([process.cwd(), scriptDir]));
  const parsedVars: Record<string, string> = {};

  // Load .env first, then allow .env.local to override .env values
  for (const fileName of [".env", ".env.local"]) {
    for (const dir of searchDirs) {
      const filePath = path.join(dir, fileName);
      if (!fs.existsSync(filePath)) continue;
      const content = fs.readFileSync(filePath, "utf8");
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        const cleaned = line.startsWith("export ") ? line.slice(7).trim() : line;
        const eqIdx = cleaned.indexOf("=");
        if (eqIdx <= 0) continue;
        const key = cleaned.slice(0, eqIdx).trim();
        let val = cleaned.slice(eqIdx + 1).trim();
        if (
          (val.startsWith('"') && val.endsWith('"')) ||
          (val.startsWith("'") && val.endsWith("'"))
        ) {
          val = val.slice(1, -1);
        }
        parsedVars[key] = val;
      }
    }
  }

  // Existing environment variables in process.env take precedence over .env / .env.local
  for (const [k, v] of Object.entries(parsedVars)) {
    if (process.env[k] === undefined || process.env[k] === "") {
      process.env[k] = v;
    }
  }
}

loadEnvFiles();

interface SignalEnvelope {
  source?: string;
  sourceNumber?: string;
  sourceUuid?: string;
  sourceName?: string;
  timestamp?: number;
  dataMessage?: {
    timestamp?: number;
    message?: string;
    reaction?: {
      emoji?: string;
      targetAuthor?: string;
      targetSentTimestamp?: number;
      isRemove?: boolean;
    };
  };
}

interface SignalReceiveNotification {
  jsonrpc?: string;
  method?: string;
  params?: {
    account?: string;
    envelope?: SignalEnvelope;
  };
}

function printUsage(): void {
  console.log(`Usage:
  node samples/message.ts --message="Hello!" (--destphone="+15551234567" | --destusername="alice.01") [options]

Options & Environment Variables:
  --message="<text>"          Message text to send (required)
  --destphone="<+E164>"       Destination phone number in E.164 format
  --destusername="<user.01>"  Destination Signal username (e.g. alice.01)
  --account="<account>"       Sender Signal account phone or UUID (optional if only 1 account or single-account key)
  --api-key="<sig_...>"       Scoped client API key with send+receive (and optionally challenge) (or set SIGNAL_API_KEY)
  --admin-key="<key>"         Optional challenge/admin API key (sig_...) or API_KEY_MGMT for resolving rate-limit challenges (or set SIGNAL_ADMIN_KEY)
  --url="<http://...>"        Signal API base URL (default: SIGNAL_API_URL or http://localhost:8080)
  --timeout="<seconds>"       Seconds to wait for a reply before exiting (default: 300)
  --help                      Show this help message
`);
}

// Normalize arguments like `destphone="..."` (without leading `--`) so both `--destphone=...` and `destphone=...` work
const normalizedArgv = process.argv.slice(2).map((arg) => {
  if (!arg.startsWith("-") && /^(message|mesage|destphone|destusername|account|api-key|admin-key|url|timeout)=/.test(arg)) {
    return `--${arg}`;
  }
  return arg;
});

const { values } = parseArgs({
  args: normalizedArgv,
  options: {
    message: { type: "string", short: "m" },
    mesage: { type: "string" }, // alias for common typo
    destphone: { type: "string" },
    destusername: { type: "string" },
    account: { type: "string", short: "a" },
    "api-key": { type: "string", short: "k" },
    "admin-key": { type: "string" },
    url: { type: "string", short: "u" },
    timeout: { type: "string", short: "t" },
    help: { type: "boolean", short: "h" },
  },
  strict: false,
});

if (values.help) {
  printUsage();
  process.exit(0);
}

const messageText = String(values.message ?? values.mesage ?? "").trim();
const destPhone = String(values.destphone ?? "").trim();
const destUsername = String(values.destusername ?? "").trim();
const recipient = destPhone || destUsername;
const account = String(values.account ?? process.env.SIGNAL_ACCOUNT ?? "").trim();
const apiKey = String(values["api-key"] ?? process.env.SIGNAL_API_KEY ?? "").trim();
const adminKey = String(values["admin-key"] ?? process.env.SIGNAL_ADMIN_KEY ?? "").trim();
const baseUrl = String(values.url ?? process.env.SIGNAL_API_URL ?? "http://localhost:8080").replace(/\/+$/, "");
const timeoutSec = Number.parseInt(String(values.timeout ?? "300"), 10) || 300;

if (!messageText || !recipient) {
  console.error("Error: --message and either --destphone or --destusername are required.\n");
  printUsage();
  process.exit(1);
}

if (!apiKey) {
  console.error("Error: Client API key is required via --api-key or SIGNAL_API_KEY environment variable.\n");
  printUsage();
  process.exit(1);
}

interface RateLimitErrorBody {
  error?: string;
  challenge_token?: string;
  retry_after_seconds?: number;
}

async function resolveAdminBearerToken(candidateKey: string): Promise<string> {
  if (candidateKey.startsWith("sig_")) {
    return candidateKey;
  }
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ admin_key: candidateKey }),
  });
  if (!loginRes.ok) {
    const body = await loginRes.text();
    throw new Error(`Admin login failed (${loginRes.status}): ${body}`);
  }
  const data = (await loginRes.json()) as { token?: string };
  if (!data.token) {
    throw new Error("Admin login succeeded but did not return a session token.");
  }
  return data.token;
}

async function submitRateLimitChallenge(challenge: string, captcha: string, keyForChallenge: string): Promise<boolean> {
  const bearer = await resolveAdminBearerToken(keyForChallenge);
  const payload: Record<string, string> = { challenge, captcha };
  if (account) {
    payload.account = account;
  }

  const res = await fetch(`${baseUrl}/v1/accounts/rate-limit-challenge`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${bearer}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (res.status === 401 || res.status === 403) {
    return false;
  }
  const rawBody = await res.text();
  if (!res.ok) {
    throw new Error(`POST /v1/accounts/rate-limit-challenge failed (${res.status}): ${rawBody}`);
  }
  return true;
}

async function promptAndResolveRateLimitChallenge(errBody: RateLimitErrorBody): Promise<boolean> {
  const challenge = errBody.challenge_token ?? "";
  if (!challenge) {
    return false;
  }

  console.warn("\nSignal returned a rate-limit challenge (429 Too Many Requests).");
  if (errBody.retry_after_seconds) {
    console.warn(`Cooldown without solving challenge: ${errBody.retry_after_seconds}s`);
  }
  console.warn(`Challenge token: ${challenge}`);
  console.warn("Solve a CAPTCHA at https://signalcaptchas.org/challenge/generate.html");
  console.warn("and copy the resulting signalcaptcha://... URL from the 'Open Signal' link.\n");

  if (!process.stdin.isTTY) {
    return false;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const captcha = (await rl.question("Paste signalcaptcha:// token (or press Enter to cancel): ")).trim();
    if (!captcha) {
      return false;
    }

    let candidateKey = adminKey || apiKey;
    let submitted = await submitRateLimitChallenge(challenge, captcha, candidateKey);
    if (!submitted) {
      const enteredAdmin = (
        await rl.question("Current key lacks challenge/admin permission. Enter challenge/admin API key (sig_...) or API_KEY_MGMT: ")
      ).trim();
      if (!enteredAdmin) {
        return false;
      }
      submitted = await submitRateLimitChallenge(challenge, captcha, enteredAdmin);
      if (!submitted) {
        throw new Error("Provided key is not authorized to submit rate-limit challenges.");
      }
    }

    console.log("Rate-limit challenge submitted. Retrying message send...");
    return true;
  } finally {
    rl.close();
  }
}

async function sendMessage(allowChallengeRetry = true): Promise<{ timestamp?: number; recipientUuid?: string }> {
  const payload: Record<string, unknown> = {
    recipients: [recipient],
    message: messageText,
  };
  if (account) {
    payload.number = account;
  }

  const res = await fetch(`${baseUrl}/v2/send`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const rawBody = await res.text();
  if (res.status === 429 && allowChallengeRetry) {
    let errBody: RateLimitErrorBody = {};
    try {
      errBody = JSON.parse(rawBody) as RateLimitErrorBody;
    } catch {
      // fall through to generic error
    }
    if (await promptAndResolveRateLimitChallenge(errBody)) {
      return sendMessage(false);
    }
  }

  if (!res.ok) {
    throw new Error(`POST /v2/send failed (${res.status}): ${rawBody}`);
  }

  try {
    const parsed = JSON.parse(rawBody) as {
      timestamp?: number;
      results?: Array<{ recipientAddress?: { uuid?: string; number?: string } }>;
    };
    const recipientUuid = parsed.results?.[0]?.recipientAddress?.uuid;
    return { timestamp: parsed.timestamp, recipientUuid };
  } catch {
    return {};
  }
}

function sendMaskedControlFrame(socket: Duplex, opcode: number, payload: Buffer): void {
  const maskKey = crypto.randomBytes(4);
  const len = Math.min(payload.length, 125);
  const frame = Buffer.alloc(2 + 4 + len);
  frame[0] = 0x80 | (opcode & 0x0f);
  frame[1] = 0x80 | len;
  maskKey.copy(frame, 2);
  for (let i = 0; i < len; i++) {
    frame[6 + i] = payload[i] ^ maskKey[i % 4];
  }
  socket.write(frame);
}

async function main(): Promise<void> {
  const receivePath = account ? `/v1/receive/${encodeURIComponent(account)}` : "/v1/receive";
  const parsedUrl = new URL(`${baseUrl}${receivePath}`);
  const isHttps = parsedUrl.protocol === "https:";
  const requestMod = isHttps ? https : http;
  const wsKey = crypto.randomBytes(16).toString("base64");

  console.log(`Connecting WebSocket stream to ${parsedUrl.origin}${parsedUrl.pathname} ...`);

  await new Promise<void>((resolve, reject) => {
    const req = requestMod.request({
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: "GET",
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": wsKey,
        Authorization: `Bearer ${apiKey}`,
      },
    });

    const timer = setTimeout(() => {
      req.destroy();
      reject(new Error(`Timed out after ${timeoutSec}s waiting for a response from ${recipient}`));
    }, timeoutSec * 1000);

    req.on("response", (res) => {
      clearTimeout(timer);
      let body = "";
      res.on("data", (chunk) => {
        body += chunk.toString();
      });
      res.on("end", () => {
        reject(new Error(`WebSocket upgrade rejected (${res.statusCode}): ${body.trim()}`));
      });
    });

    req.on("upgrade", async (_res, socket, head) => {
      let sentTimestamp: number | undefined;
      let expectedUuid: string | undefined;

      try {
        console.log(`Sending message to ${recipient}${account ? ` from ${account}` : ""} ...`);
        const sendResult = await sendMessage();
        sentTimestamp = sendResult.timestamp;
        expectedUuid = sendResult.recipientUuid;
        console.log(
          `Message sent${sentTimestamp ? ` (timestamp: ${sentTimestamp})` : ""}. Waiting up to ${timeoutSec}s for a reply or reaction...`
        );
      } catch (err) {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
        return;
      }

      let buffer: Buffer = head.length > 0 ? Buffer.from(head) : Buffer.alloc(0);

      const handleTextFrame = (text: string): void => {
        let evt: SignalReceiveNotification;
        try {
          evt = JSON.parse(text) as SignalReceiveNotification;
        } catch {
          return;
        }

        const env = evt.params?.envelope;
        const dm = env?.dataMessage;
        if (!env || !dm) {
          return;
        }

        const senderNumber = env.sourceNumber ?? env.source ?? "";
        const senderUuid = env.sourceUuid ?? "";
        const matchesPhone = Boolean(destPhone && senderNumber === destPhone);
        const matchesResolvedUuid = Boolean(expectedUuid && senderUuid === expectedUuid);
        const matchesReactionTimestamp = Boolean(
          sentTimestamp && dm.reaction && dm.reaction.targetSentTimestamp === sentTimestamp
        );
        // If destination was a username and signal-cli didn't return a resolved UUID on send,
        // accept the next incoming direct message/reaction that isn't from our own account.
        const matchesUsernameFallback = Boolean(
          destUsername && !expectedUuid && (senderNumber || senderUuid) && senderNumber !== account && senderUuid !== account
        );

        if (!matchesPhone && !matchesResolvedUuid && !matchesReactionTimestamp && !matchesUsernameFallback) {
          return;
        }

        if (dm.reaction && !dm.reaction.isRemove) {
          console.log("\nReceived reaction from user:");
          console.log(
            JSON.stringify(
              {
                from: senderNumber || senderUuid,
                fromName: env.sourceName,
                emoji: dm.reaction.emoji,
                targetSentTimestamp: dm.reaction.targetSentTimestamp,
              },
              null,
              2
            )
          );
          clearTimeout(timer);
          sendMaskedControlFrame(socket, 0x08, Buffer.alloc(0));
          socket.end();
          resolve();
          return;
        }

        if (typeof dm.message === "string" && dm.message.length > 0) {
          console.log("\nReceived reply from user:");
          console.log(
            JSON.stringify(
              {
                from: senderNumber || senderUuid,
                fromName: env.sourceName,
                message: dm.message,
                timestamp: dm.timestamp ?? env.timestamp,
              },
              null,
              2
            )
          );
          clearTimeout(timer);
          sendMaskedControlFrame(socket, 0x08, Buffer.alloc(0));
          socket.end();
          resolve();
        }
      };

      const parseFrames = (): void => {
        while (buffer.length >= 2) {
          const b1 = buffer[0];
          const b2 = buffer[1];
          const opcode = b1 & 0x0f;
          const isMasked = (b2 & 0x80) !== 0;
          let payloadLen = b2 & 0x7f;
          let offset = 2;

          if (payloadLen === 126) {
            if (buffer.length < 4) return;
            payloadLen = buffer.readUInt16BE(2);
            offset = 4;
          } else if (payloadLen === 127) {
            if (buffer.length < 10) return;
            payloadLen = Number(buffer.readBigUInt64BE(2));
            offset = 10;
          }

          const maskBytes = isMasked ? 4 : 0;
          if (buffer.length < offset + maskBytes + payloadLen) {
            return;
          }

          let payload = buffer.subarray(offset + maskBytes, offset + maskBytes + payloadLen);
          if (isMasked) {
            const mask = buffer.subarray(offset, offset + 4);
            payload = Buffer.from(payload);
            for (let i = 0; i < payload.length; i++) {
              payload[i] ^= mask[i % 4];
            }
          }

          buffer = buffer.subarray(offset + maskBytes + payloadLen);

          if (opcode === 0x01) {
            handleTextFrame(payload.toString("utf8"));
          } else if (opcode === 0x09) {
            // Answer server Ping (0x09) with a masked Pong (0x0A) to extend the server's 35s read deadline
            sendMaskedControlFrame(socket, 0x0a, payload);
          } else if (opcode === 0x08) {
            clearTimeout(timer);
            socket.end();
            reject(new Error("Server closed the WebSocket connection"));
            return;
          }
        }
      };

      if (buffer.length > 0) {
        parseFrames();
      }

      socket.on("data", (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        parseFrames();
      });

      socket.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    req.end();
  });
}

main().catch((err: unknown) => {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
