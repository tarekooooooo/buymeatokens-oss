// A creator's webhook endpoints: add, list, rotate the secret, delete, send a test event. Every function takes the
// creator's id and only touches that creator's rows, so a crafted endpoint id for someone else's endpoint changes nothing.
// The secret is shown once, when it is created or rotated; only its encrypted form is stored and it is never read back
// out to a page.

import { decrypt, encrypt, newId, randomToken } from "./crypto";
import { isUniqueViolation, num, query, str } from "./db";
import { sendWebhook, type SendDeps } from "./webhook-send";
import { webhookHeaders } from "./webhook-sign";
import { chatWebhookRefusal, checkWebhookUrl, type Resolver } from "./webhook-url";

export const MAX_ENDPOINTS = 3;
export const SECRET_PREFIX = "bmtwh_";
/** After a rotation the previous secret keeps signing for this long. */
export const ROTATION_GRACE_MS = 24 * 3_600_000;
export const TEST_LIMIT = 5;
export const TEST_WINDOW_MS = 10 * 60_000;

export const newSecret = () => `${SECRET_PREFIX}${randomToken(24)}`;

export type EndpointView = {
  id: string;
  /** Host only; the path and query can hold a token and are not shown. */
  maskedUrl: string;
  status: "active" | "failing" | "disabled";
  failStreak: number;
  createdAt: number;
};

export function maskUrl(url: string): string {
  try {
    const u = new URL(url);
    return `https://${u.hostname}/${u.pathname.length > 1 || u.search ? "…" : ""}`;
  } catch {
    return "https://…";
  }
}

export async function listEndpoints(creatorId: string): Promise<EndpointView[]> {
  const rs = await query(
    "SELECT id, url, enabled, fail_streak, created_at FROM webhook_endpoints WHERE creator_id = ? ORDER BY slot",
    [creatorId],
  );
  return rs.rows.map((r) => ({
    id: String(r.id),
    maskedUrl: maskUrl(String(r.url)),
    status: !r.enabled ? "disabled" : (num(r.fail_streak) ?? 0) > 0 ? "failing" : "active",
    failStreak: num(r.fail_streak) ?? 0,
    createdAt: num(r.created_at) ?? 0,
  }));
}

/** Saves an endpoint after the same URL checks every send makes. The secret in the result is shown once. */
export async function addEndpoint(
  creatorId: string,
  urlInput: string,
  deps: { resolve?: Resolver; now?: number } = {},
): Promise<{ id: string; secret: string } | { error: string }> {
  const checked = await checkWebhookUrl(urlInput, deps.resolve);
  if ("error" in checked) return checked;
  const chat = chatWebhookRefusal(checked.url);
  if (chat) return { error: chat };
  const id = newId();
  const secret = newSecret();
  const limit = { error: `You can have up to ${MAX_ENDPOINTS} endpoints. Delete one first.` };
  try {
    // The lowest free slot, and UNIQUE (creator_id, slot) with slot <= 3 holds the limit even for concurrent adds.
    const rs = await query(
      `INSERT INTO webhook_endpoints (id, creator_id, slot, url, secret_enc, created_at)
       SELECT ?::text, ?::text, s.slot, ?::text, ?::text, ?::bigint
       FROM (SELECT MIN(n) AS slot FROM generate_series(1, ${MAX_ENDPOINTS}) n
             WHERE NOT EXISTS (SELECT 1 FROM webhook_endpoints WHERE creator_id = ? AND slot = n)) s
       WHERE s.slot IS NOT NULL
       RETURNING id`,
      [id, creatorId, checked.url.toString(), encrypt(secret), deps.now ?? Date.now(), creatorId],
    );
    return rs.rows.length ? { id, secret } : limit;
  } catch (error) {
    if (isUniqueViolation(error)) return limit;
    throw error;
  }
}

/**
 * A new secret; the old one keeps signing for 24 hours. Returns the new secret once, null if it isn't theirs, or
 * "too_soon" during the 24 hours after a rotation: a second one would drop the secret receivers may still be using.
 */
export async function rotateSecret(creatorId: string, id: string, now = Date.now()): Promise<string | "too_soon" | null> {
  const secret = newSecret();
  const rs = await query(
    `UPDATE webhook_endpoints SET prev_secret_enc = secret_enc, prev_expires_at = ?, secret_enc = ?
     WHERE id = ? AND creator_id = ? AND (prev_expires_at IS NULL OR prev_expires_at <= ?) RETURNING id`,
    [now + ROTATION_GRACE_MS, encrypt(secret), id, creatorId, now],
  );
  if (rs.rows.length) return secret;
  const mine = await query("SELECT 1 FROM webhook_endpoints WHERE id = ? AND creator_id = ?", [id, creatorId]);
  return mine.rows.length ? "too_soon" : null;
}

export async function deleteEndpoint(creatorId: string, id: string): Promise<boolean> {
  const rs = await query("DELETE FROM webhook_endpoints WHERE id = ? AND creator_id = ? RETURNING id", [id, creatorId]);
  return rs.rows.length > 0;
}

/** The secrets that sign right now: the current one, and the previous one until its grace ends. */
export function signingSecrets(row: Record<string, unknown>, now: number): string[] {
  const secrets = [decrypt(String(row.secret_enc))];
  const prev = str(row.prev_secret_enc);
  if (prev && (num(row.prev_expires_at) ?? 0) > now) secrets.push(decrypt(prev));
  return secrets;
}

/** One fixed window per creator: true if this test may go ahead. */
export async function takeTestSlot(creatorId: string, now: number): Promise<boolean> {
  const rs = await query(
    `INSERT INTO webhook_test_limits (creator_id, window_start, count) VALUES (?, ?, 1)
     ON CONFLICT (creator_id) DO UPDATE SET
       window_start = CASE WHEN webhook_test_limits.window_start <= ?::bigint - ${TEST_WINDOW_MS} THEN excluded.window_start ELSE webhook_test_limits.window_start END,
       count = CASE WHEN webhook_test_limits.window_start <= ?::bigint - ${TEST_WINDOW_MS} THEN 1 ELSE webhook_test_limits.count + 1 END
     WHERE webhook_test_limits.window_start <= ?::bigint - ${TEST_WINDOW_MS} OR webhook_test_limits.count < ${TEST_LIMIT}
     RETURNING count`,
    [creatorId, now, now, now, now],
  );
  return rs.rows.length > 0;
}

export type TestOutcome = "delivered" | "limited" | "missing" | { failedStatus: number } | "could_not_connect";

/**
 * Sends a sample `webhook.test` event through the same checks and limits as real deliveries. The answer is only
 * delivered / failed with status N / could not connect: no body, no timing, no difference between "refused" and "blocked".
 * A delivered test also puts a disabled endpoint back in service.
 */
export async function sendTestEvent(creatorId: string, id: string, deps: SendDeps & { now?: number } = {}): Promise<TestOutcome> {
  const now = deps.now ?? Date.now();
  const rs = await query(
    "SELECT url, secret_enc, prev_secret_enc, prev_expires_at FROM webhook_endpoints WHERE id = ? AND creator_id = ?",
    [id, creatorId],
  );
  const row = rs.rows[0];
  if (!row) return "missing";
  if (!(await takeTestSlot(creatorId, now))) return "limited";
  const eventId = `evt_test_${randomToken(12)}`;
  const body = JSON.stringify({
    id: eventId,
    type: "webhook.test",
    created: Math.floor(now / 1000),
    livemode: false,
    data: {
      support: {
        id: "test", units: 1, amount_cents: 500, currency: "usd", method: "stripe",
        supporter_name: "Test supporter", message: "This is a test event.", paid_at: new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z"),
      },
    },
  });
  const headers = webhookHeaders({ eventId, eventType: "webhook.test", body, secrets: signingSecrets(row, now), now });
  const result = await sendWebhook(String(row.url), headers, body, deps);
  if (result.status === null) return "could_not_connect";
  if (result.status >= 200 && result.status < 300) {
    await query(
      "UPDATE webhook_endpoints SET fail_streak = 0, enabled = true, disabled_at = NULL WHERE id = ? AND creator_id = ?",
      [id, creatorId],
    );
    return "delivered";
  }
  return { failedStatus: result.status };
}
