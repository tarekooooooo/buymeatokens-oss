import { createHash, createHmac } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

process.env.ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");

const mocks = vi.hoisted(() => ({ db: null as unknown as PGlite }));

vi.mock("../src/lib/db", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/lib/db")>();
  return {
    ...original,
    query: async (sql: string, args: unknown[] = []) => {
      let index = 0;
      const result = await mocks.db.query(sql.replace(/\?/g, () => `$${++index}`), args);
      return { rows: result.rows, rowsAffected: result.affectedRows ?? 0 };
    },
  };
});

import { deleteAccount } from "../src/lib/account-deletion";
import { decrypt } from "../src/lib/crypto";
import { SCHEMA, query } from "../src/lib/db";
import { markPaid, markPaypalPaid, markPaypalReversed, recordUsdcDonation } from "../src/lib/donations";
import {
  FAIL_LIMIT, LEASE_MS, MAX_ATTEMPTS, PER_TICK, RETRY_DELAYS, processWebhooks, pruneWebhookDeliveries,
} from "../src/lib/webhook-delivery";
import type { HttpsPost } from "../src/lib/webhook-send";
import {
  MAX_ENDPOINTS, ROTATION_GRACE_MS, TEST_LIMIT, TEST_WINDOW_MS, addEndpoint, deleteEndpoint, listEndpoints, rotateSecret,
  sendTestEvent,
} from "../src/lib/webhooks";

const NOW = 1_800_000_000_000;
const PUBLIC = async () => ["93.184.216.34"];
const MIN = 60_000;
let seq = 0;

async function creator(id: string) {
  await query(
    "INSERT INTO users (id, auth_id, login, email, username, display_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [id, `github:${id}`, id, `${id}@example.com`, id, id, NOW],
  );
}

async function donation(input: Partial<{ id: string; creatorId: string; status: string; method: string; mode: string; name: string; message: string; tx: string | null }> = {}) {
  const id = input.id ?? `don-${++seq}`;
  await query(
    `INSERT INTO donations (id, creator_id, stripe_mode, method, tx_hash, units, amount_cents, supporter_name, message, status, created_at, stripe_session_id)
     VALUES (?, ?, ?, ?, ?, 3, 1500, ?, ?, ?, ?, ?)`,
    [id, input.creatorId ?? "maker", input.mode ?? "live", input.method ?? "stripe", input.tx ?? null, input.name ?? "Grace",
      input.message ?? "Love it", input.status ?? "pending", NOW - MIN, `cs_${id}`],
  );
  return id;
}

async function endpoint(creatorId = "maker", url = "https://hooks.example.com/bmt") {
  const added = await addEndpoint(creatorId, url, { resolve: PUBLIC, now: NOW });
  if ("error" in added) throw new Error(added.error);
  return added;
}

type Delivery = { id: string; endpoint_id: string; event_id: string; event_type: string; payload: string; status: string; attempt_count: number; next_attempt_at: string; last_status: number | null };
const deliveries = async () =>
  (await query("SELECT * FROM webhook_deliveries ORDER BY created_at, event_type, id")).rows as unknown as Delivery[];
const statusOf = async (id: string) => (await query("SELECT status FROM donations WHERE id = ?", [id])).rows[0]?.status;

const sent = (status: number | null = 200) => vi.fn<HttpsPost>(async () => ({ status }));
const deps = (post: HttpsPost, extra: object = {}) => ({ resolve: PUBLIC, post, ...extra });

describe("signed webhooks", () => {
  beforeAll(async () => {
    mocks.db = new PGlite();
    await mocks.db.exec(SCHEMA);
  });
  beforeEach(async () => {
    await mocks.db.exec("TRUNCATE users CASCADE; TRUNCATE ops_events; DROP TRIGGER IF EXISTS boom ON webhook_deliveries");
    await creator("maker");
    await creator("other");
  });
  afterAll(async () => {
    await mocks.db.close();
  });

  describe("enqueueing with the confirmation", () => {
    it("changes nothing when the creator has no endpoint", async () => {
      const id = await donation();
      expect(await markPaid(id)).toBe(true);
      expect(await markPaid(id)).toBe(false);
      expect(await statusOf(id)).toBe("paid");
      expect(await deliveries()).toEqual([]);
    });

    it("queues one event per enabled endpoint of that creator only", async () => {
      await endpoint("maker", "https://a.example.com/x");
      await endpoint("maker", "https://b.example.com/x");
      const off = await endpoint("maker", "https://c.example.com/x");
      await query("UPDATE webhook_endpoints SET enabled = false WHERE id = ?", [off.id]);
      await endpoint("other", "https://z.example.com/x");
      await markPaid(await donation());
      const rows = await deliveries();
      expect(rows).toHaveLength(2);
      expect(new Set(rows.map((r) => r.event_id)).size).toBe(1);
      expect(rows.every((r) => r.event_type === "support.confirmed" && r.status === "pending")).toBe(true);
    });

    it("queues once however often, or however concurrently, the same payment is confirmed", async () => {
      await endpoint();
      const id = await donation();
      const results = await Promise.all([markPaid(id), markPaid(id), markPaid(id)]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await markPaid(id)).toBe(false);
      expect(await deliveries()).toHaveLength(1);
    });

    it("queues for an expired payment that is confirmed late, once", async () => {
      await endpoint();
      const id = await donation({ status: "expired" });
      expect(await markPaid(id)).toBe(true);
      expect(await deliveries()).toHaveLength(1);
    });

    it("queues nothing for a payment that can't be confirmed", async () => {
      await endpoint();
      const id = await donation({ status: "failed" });
      expect(await markPaid(id)).toBe(false);
      expect(await deliveries()).toHaveLength(0);
    });

    it("rolls the confirmation back when the event can't be written (one statement, all or nothing)", async () => {
      await endpoint();
      const id = await donation();
      await mocks.db.exec(`
        CREATE OR REPLACE FUNCTION boom() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'no outbox'; END $$ LANGUAGE plpgsql;
        CREATE TRIGGER boom BEFORE INSERT ON webhook_deliveries FOR EACH ROW EXECUTE FUNCTION boom();`);
      await expect(markPaid(id)).rejects.toThrow();
      expect(await statusOf(id)).toBe("pending");
      await mocks.db.exec("DROP TRIGGER boom ON webhook_deliveries");
      expect(await markPaid(id)).toBe(true);
      expect(await deliveries()).toHaveLength(1);
    });

    it("PayPal: a replayed IPN queues once; a txn that is already taken queues nothing", async () => {
      await endpoint();
      const id = await donation({ method: "paypal" });
      expect(await markPaypalPaid(id, "TXN-1", 1500, 3)).toBe(true);
      expect(await markPaypalPaid(id, "TXN-1", 1500, 3)).toBe(false);
      expect(await Promise.all([markPaypalPaid(id, "TXN-1", 1500, 3), markPaypalPaid(id, "TXN-1", 1500, 3)])).toEqual([false, false]);
      const second = await donation({ method: "paypal" });
      expect(await markPaypalPaid(second, "TXN-1", 1500, 3)).toBe(false);
      expect(await deliveries()).toHaveLength(1);
    });

    it("PayPal: a reversal queues support.reversed once, and only for a paid payment", async () => {
      await endpoint();
      const id = await donation({ method: "paypal" });
      await markPaypalReversed("TXN-9"); // unknown txn
      await markPaypalPaid(id, "TXN-9", 1500, 3);
      await markPaypalReversed("TXN-9");
      await markPaypalReversed("TXN-9");
      const rows = await deliveries();
      expect(rows.map((r) => r.event_type).sort()).toEqual(["support.confirmed", "support.reversed"]);
      expect(rows[0].event_id).not.toBe(rows[1].event_id);
      expect(await statusOf(id)).toBe("failed");
    });

    it("USDC: recording the same transfer twice or at once queues once", async () => {
      await endpoint();
      const input = { creatorId: "maker", txHash: "0xabc", units: 2, amountCents: 1000, supporterName: "Ada", message: "hi" };
      const results = await Promise.all([recordUsdcDonation(input), recordUsdcDonation(input)]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await recordUsdcDonation(input)).toBe(false);
      const rows = await deliveries();
      expect(rows).toHaveLength(1);
      expect(JSON.parse(rows[0].payload).data.support).toMatchObject({ method: "usdc", currency: "usdc", amount_cents: 1000 });
    });

    it("derives the event id from the donation and the type", async () => {
      await endpoint();
      const id = await donation();
      await markPaid(id);
      expect((await deliveries())[0].event_id).toBe(`evt_${createHash("sha256").update(`${id}:support.confirmed`).digest("hex")}`);
    });

    it("has exactly the documented payload, with nothing else in it", async () => {
      await endpoint();
      const id = await donation({ method: "paypal", name: "  ", message: "hello" });
      await markPaypalPaid(id, "SECRET-TXN-ID", 1500, 3);
      const row = (await deliveries())[0];
      const payload = JSON.parse(row.payload);
      expect(Object.keys(payload)).toEqual(["id", "type", "created", "livemode", "data"]);
      expect(Object.keys(payload.data)).toEqual(["support"]);
      expect(Object.keys(payload.data.support)).toEqual(["id", "units", "amount_cents", "currency", "method", "supporter_name", "message", "paid_at"]);
      expect(payload).toMatchObject({
        id: row.event_id, type: "support.confirmed", livemode: true,
        data: { support: { id, units: 3, amount_cents: 1500, currency: "usd", method: "paypal", supporter_name: null, message: "hello" } },
      });
      expect(payload.created).toBeTypeOf("number");
      expect(payload.data.support.paid_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
      expect(row.payload).not.toMatch(/SECRET-TXN-ID|example\.com|cs_don|creator_id|maker/);
    });

    it("marks test-mode payments livemode false, and still delivers them", async () => {
      await endpoint();
      await markPaid(await donation({ mode: "test" }));
      expect(JSON.parse((await deliveries())[0].payload).livemode).toBe(false);
    });

    it("snapshots the payload when it is queued", async () => {
      await endpoint();
      const id = await donation({ name: "Grace", message: "before" });
      await markPaid(id);
      await query("UPDATE donations SET message = 'after', supporter_name = 'Someone else' WHERE id = ?", [id]);
      expect(JSON.parse((await deliveries())[0].payload).data.support).toMatchObject({ message: "before", supporter_name: "Grace" });
    });
  });

  describe("delivery", () => {
    async function queued() {
      const ep = await endpoint();
      await markPaid(await donation());
      return { ep, row: (await deliveries())[0] };
    }

    it("sends a signed request, marks it delivered and resets the failure count", async () => {
      const { ep, row } = await queued();
      await query("UPDATE webhook_endpoints SET fail_streak = 4 WHERE id = ?", [ep.id]);
      const post = sent(200);
      expect(await processWebhooks(NOW, deps(post))).toEqual({ claimed: 1, delivered: 1 });
      const req = post.mock.calls[0][0];
      expect(req.body).toBe(row.payload);
      expect(req.address).toBe("93.184.216.34");
      expect(req.headers["BMT-Event-Id"]).toBe(row.event_id);
      expect(req.headers["BMT-Event-Type"]).toBe("support.confirmed");
      const [t, v1] = req.headers["BMT-Signature"].split(",");
      expect(t).toBe(`t=${NOW / 1000}`);
      expect(v1).toBe(`v1=${createHmac("sha256", ep.secret).update(`${NOW / 1000}.${row.payload}`).digest("hex")}`);
      expect((await deliveries())[0]).toMatchObject({ status: "delivered", attempt_count: 1, last_status: 200 });
      expect((await listEndpoints("maker"))[0]).toMatchObject({ status: "active", failStreak: 0 });
      expect(await processWebhooks(NOW + MIN, deps(post))).toEqual({ claimed: 0, delivered: 0 });
    });

    it("retries on the schedule with a fresh signature and the same event id, then goes dead", async () => {
      const { row } = await queued();
      const post = sent(500);
      let now = NOW;
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        expect(await processWebhooks(now, deps(post))).toMatchObject({ claimed: 1, delivered: 0 });
        const d = (await deliveries())[0];
        expect(d.attempt_count).toBe(attempt);
        if (attempt < MAX_ATTEMPTS) {
          expect(d.status).toBe("pending");
          expect(Number(d.next_attempt_at)).toBe(now + RETRY_DELAYS[attempt - 1]);
          expect(await processWebhooks(now + RETRY_DELAYS[attempt - 1] - 1, deps(post))).toMatchObject({ claimed: 0 }); // not yet
          now += RETRY_DELAYS[attempt - 1];
        } else {
          expect(d.status).toBe("dead");
        }
      }
      expect(RETRY_DELAYS).toEqual([1, 5, 30, 120, 360, 720].map((m) => m * MIN));
      expect(post).toHaveBeenCalledTimes(MAX_ATTEMPTS);
      const sigs = post.mock.calls.map((c) => c[0].headers["BMT-Signature"]);
      expect(new Set(sigs).size).toBe(MAX_ATTEMPTS);
      expect(new Set(post.mock.calls.map((c) => c[0].headers["BMT-Event-Id"]))).toEqual(new Set([row.event_id]));
      expect(await processWebhooks(now + 99 * 3_600_000, deps(post))).toMatchObject({ claimed: 0 });
    });

    it("treats a timeout or connection failure like any other failure", async () => {
      await queued();
      await processWebhooks(NOW, deps(sent(null)));
      expect((await deliveries())[0]).toMatchObject({ status: "pending", attempt_count: 1, last_status: null });
    });

    it("treats a redirect as a failure and doesn't follow it", async () => {
      await queued();
      const post = sent(301);
      await processWebhooks(NOW, deps(post));
      expect(post).toHaveBeenCalledTimes(1);
      expect((await deliveries())[0]).toMatchObject({ status: "pending", last_status: 301 });
    });

    it("checks the address again on every send", async () => {
      await queued();
      const post = sent(200);
      await processWebhooks(NOW, { resolve: async () => ["10.0.0.7"], post });
      expect(post).not.toHaveBeenCalled();
      expect((await deliveries())[0]).toMatchObject({ status: "pending", attempt_count: 1 });
    });

    it("gives each endpoint one slot per batch, so one creator's backlog can't hold up everyone else", async () => {
      await endpoint("maker");
      for (let i = 0; i < 12; i++) await markPaid(await donation());
      await endpoint("other", "https://hooks.example.org/other");
      await markPaid(await donation({ creatorId: "other" }));
      const post = sent(200);
      await processWebhooks(NOW, deps(post, { budgetMs: 100_000 }));
      // The first batch already carried the other creator's event, although it was queued after all twelve.
      const firstTwo = post.mock.calls.slice(0, 2).map(([req]) => req.url.hostname);
      expect(firstTwo).toContain("hooks.example.org");
    });

    it("drops what a slower worker put back after the endpoint was disabled", async () => {
      const ep = await endpoint();
      await markPaid(await donation());
      await query("UPDATE webhook_endpoints SET enabled = false, disabled_at = ? WHERE id = ?", [NOW - MIN, ep.id]);
      // A worker from an earlier tick still holds this row and finishes it now, with a failure.
      await query("UPDATE webhook_deliveries SET status = 'sending', attempted_at = ?, attempt_count = 1", [NOW]);
      await markPaid(await donation()); // nothing is queued for a disabled endpoint
      await query(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload, next_attempt_at, created_at)
         VALUES ('late', ?, 'evt_late', 'support.confirmed', '{}', ?, ?)`,
        [ep.id, NOW, NOW],
      );
      const { finishDelivery } = await import("../src/lib/webhook-delivery");
      const [held] = (await query("SELECT * FROM webhook_deliveries WHERE status = 'sending'")).rows as unknown as Delivery[];
      await finishDelivery({ ...held, attempt_count: 1 }, 500, NOW + MIN);
      expect((await deliveries()).map((r) => r.status)).toEqual(["dead", "dead"]);
    });

    it(`disables the endpoint after ${FAIL_LIMIT} failures in a row, drops what is waiting and records an ops event`, async () => {
      const { ep } = await queued();
      await markPaid(await donation());
      await query("UPDATE webhook_endpoints SET fail_streak = ? WHERE id = ?", [FAIL_LIMIT - 1, ep.id]);
      await processWebhooks(NOW, deps(sent(500), { budgetMs: 100_000 }));
      expect((await listEndpoints("maker"))[0].status).toBe("disabled");
      const rows = await deliveries();
      expect(rows.filter((r) => r.status === "dead").length).toBeGreaterThanOrEqual(1);
      expect(rows.some((r) => r.status === "pending")).toBe(false);
      const ops = await query("SELECT tag, detail FROM ops_events");
      expect(ops.rows).toHaveLength(1);
      expect(String(ops.rows[0].tag)).toContain("endpoint disabled");
      // A disabled endpoint receives no new events and no retries.
      await markPaid(await donation());
      expect(await deliveries()).toHaveLength(2);
      const post = sent(200);
      expect(await processWebhooks(NOW + 99 * 3_600_000, deps(post))).toMatchObject({ claimed: 0 });
    });

    it("counts a failing endpoint as failing, and a success resets it", async () => {
      await queued();
      await processWebhooks(NOW, deps(sent(500)));
      expect((await listEndpoints("maker"))[0]).toMatchObject({ status: "failing", failStreak: 1 });
      await processWebhooks(NOW + RETRY_DELAYS[0], deps(sent(200)));
      expect((await listEndpoints("maker"))[0]).toMatchObject({ status: "active", failStreak: 0 });
    });

    it("lets two workers run at once without sending anything twice", async () => {
      await endpoint();
      for (let i = 0; i < 12; i++) await markPaid(await donation());
      const post = sent(200);
      const [a, b] = await Promise.all([processWebhooks(NOW, deps(post)), processWebhooks(NOW, deps(post))]);
      expect(a.claimed + b.claimed).toBe(12);
      expect(post).toHaveBeenCalledTimes(12);
      expect(new Set(post.mock.calls.map((c) => c[0].headers["BMT-Event-Id"])).size).toBe(12);
    });

    it("reclaims a row stuck in sending after the lease, and leaves a fresh claim alone", async () => {
      const { row } = await queued();
      await query("UPDATE webhook_deliveries SET status = 'sending', attempt_count = 1, attempted_at = ? WHERE id = ?", [NOW, row.id]);
      const post = sent(200);
      expect(await processWebhooks(NOW + LEASE_MS - 1, deps(post))).toMatchObject({ claimed: 0 });
      expect(await processWebhooks(NOW + LEASE_MS, deps(post))).toMatchObject({ claimed: 1, delivered: 1 });
      expect((await deliveries())[0]).toMatchObject({ status: "delivered", attempt_count: 2 });
    });

    it("sends at most one tick's worth of rows", async () => {
      await endpoint();
      for (let i = 0; i < PER_TICK + 5; i++) await markPaid(await donation());
      const post = sent(200);
      expect(await processWebhooks(NOW, deps(post))).toEqual({ claimed: PER_TICK, delivered: PER_TICK });
      expect(await processWebhooks(NOW, deps(post))).toEqual({ claimed: 5, delivered: 5 });
    });

    it("stops claiming when the time budget can't fit another batch", async () => {
      await endpoint();
      for (let i = 0; i < 12; i++) await markPaid(await donation());
      const slow = vi.fn<HttpsPost>(() => new Promise((resolve) => setTimeout(() => resolve({ status: 200 }), 700)));
      const result = await processWebhooks(NOW, deps(slow, { budgetMs: 2500, timeoutMs: 1000 }));
      // One batch fit (it needs 2 s of the 2.5 s); after 0.7 s the next did not. One endpoint gets one slot per batch.
      expect(result.claimed).toBe(1);
      expect((await deliveries()).filter((r) => r.status === "pending")).toHaveLength(11);
      expect(await processWebhooks(NOW, deps(slow, { budgetMs: 10, timeoutMs: 1000 }))).toEqual({ claimed: 0, delivered: 0 });
    });

    it("signs with both secrets while a rotation's grace lasts, then with the new one only", async () => {
      const ep = await endpoint();
      const fresh = (await rotateSecret("maker", ep.id, NOW))!;
      await markPaid(await donation());
      const post = sent(500);
      await processWebhooks(NOW + MIN, deps(post));
      const [, ...entries] = post.mock.calls[0][0].headers["BMT-Signature"].split(",");
      const body = post.mock.calls[0][0].body;
      const t = (NOW + MIN) / 1000;
      const mac = (s: string) => `v1=${createHmac("sha256", s).update(`${t}.${body}`).digest("hex")}`;
      expect(entries).toEqual([mac(fresh), mac(ep.secret)]);
      await processWebhooks(NOW + ROTATION_GRACE_MS + MIN, deps(post));
      expect(post.mock.calls[1][0].headers["BMT-Signature"].split(",").slice(1)).toEqual([
        `v1=${createHmac("sha256", fresh).update(`${(NOW + ROTATION_GRACE_MS + MIN) / 1000}.${body}`).digest("hex")}`,
      ]);
    });

    it("prunes finished deliveries after 30 days", async () => {
      await queued();
      await processWebhooks(NOW, deps(sent(200)));
      await query("UPDATE webhook_deliveries SET created_at = ?", [NOW]);
      await pruneWebhookDeliveries(NOW + 29 * 86_400_000);
      expect(await deliveries()).toHaveLength(1);
      await pruneWebhookDeliveries(NOW + 31 * 86_400_000);
      expect(await deliveries()).toHaveLength(0);
    });
  });

  describe("endpoints", () => {
    it("allows 3 per creator, also when added at once", async () => {
      const results = await Promise.all(Array.from({ length: 5 }, (_, i) => addEndpoint("maker", `https://h${i}.example.com/`, { resolve: PUBLIC, now: NOW })));
      expect(results.filter((r) => "secret" in r)).toHaveLength(MAX_ENDPOINTS);
      expect(results.filter((r) => "error" in r)).toHaveLength(2);
      expect(await listEndpoints("maker")).toHaveLength(3);
      expect(await addEndpoint("other", "https://x.example.com/", { resolve: PUBLIC })).toHaveProperty("secret");
      await deleteEndpoint("maker", (await listEndpoints("maker"))[0].id);
      expect(await addEndpoint("maker", "https://again.example.com/", { resolve: PUBLIC })).toHaveProperty("secret");
    });

    it("refuses URLs that fail the checks, without saving them", async () => {
      for (const url of ["http://example.com/", "https://127.0.0.1/", "https://example.com:8443/"]) {
        expect(await addEndpoint("maker", url, { resolve: PUBLIC })).toHaveProperty("error");
      }
      expect(await addEndpoint("maker", "https://evil.example.com/", { resolve: async () => ["169.254.169.254"] })).toHaveProperty("error");
      expect(await addEndpoint("maker", "https://mixed.example.com/", { resolve: async () => ["93.184.216.34", "10.0.0.1"] })).toHaveProperty("error");
      expect(await listEndpoints("maker")).toEqual([]);
    });

    it("stores the secret encrypted, shows it once, and never returns it from a list", async () => {
      const ep = await endpoint("maker", "https://hooks.example.com/token/abc?key=1");
      expect(ep.secret).toMatch(/^bmtwh_[A-Za-z0-9_-]{30,}$/);
      const row = (await query("SELECT * FROM webhook_endpoints WHERE id = ?", [ep.id])).rows[0];
      expect(JSON.stringify(row)).not.toContain(ep.secret);
      expect(decrypt(String(row.secret_enc))).toBe(ep.secret);
      const list = await listEndpoints("maker");
      expect(JSON.stringify(list)).not.toContain(ep.secret);
      expect(JSON.stringify(list)).not.toContain("token");
      expect(list[0]).toMatchObject({ maskedUrl: "https://hooks.example.com/…", status: "active" });
    });

    it("refuses a second rotation inside the 24 hours, which would drop the secret receivers may still use", async () => {
      const ep = await endpoint();
      const fresh = await rotateSecret("maker", ep.id, NOW);
      expect(typeof fresh).toBe("string");
      expect(await rotateSecret("maker", ep.id, NOW + 60 * MIN)).toBe("too_soon");
      const row = (await query("SELECT * FROM webhook_endpoints WHERE id = ?", [ep.id])).rows[0];
      expect(decrypt(String(row.prev_secret_enc))).toBe(ep.secret);
      expect(await rotateSecret("maker", ep.id, NOW + ROTATION_GRACE_MS)).not.toBe("too_soon");
      expect(await rotateSecret("other", ep.id, NOW + ROTATION_GRACE_MS * 3)).toBeNull();
    });

    it("keeps the previous secret for 24 hours after a rotation", async () => {
      const ep = await endpoint();
      const fresh = await rotateSecret("maker", ep.id, NOW);
      expect(fresh).not.toBe(ep.secret);
      const row = (await query("SELECT * FROM webhook_endpoints WHERE id = ?", [ep.id])).rows[0];
      expect(decrypt(String(row.secret_enc))).toBe(fresh);
      expect(decrypt(String(row.prev_secret_enc))).toBe(ep.secret);
      expect(Number(row.prev_expires_at)).toBe(NOW + 24 * 3_600_000);
    });

    it("lets only the owner rotate, test or delete an endpoint", async () => {
      const ep = await endpoint("maker");
      const post = sent(200);
      expect(await rotateSecret("other", ep.id)).toBeNull();
      expect(await deleteEndpoint("other", ep.id)).toBe(false);
      expect(await sendTestEvent("other", ep.id, deps(post, { now: NOW }))).toBe("missing");
      expect(post).not.toHaveBeenCalled();
      const row = (await query("SELECT prev_secret_enc FROM webhook_endpoints WHERE id = ?", [ep.id])).rows;
      expect(row).toHaveLength(1);
      expect(row[0].prev_secret_enc).toBeNull();
      expect(await listEndpoints("other")).toEqual([]);
    });

    it("deleting an endpoint removes its queued events", async () => {
      const ep = await endpoint();
      await markPaid(await donation());
      expect(await deleteEndpoint("maker", ep.id)).toBe(true);
      expect(await deliveries()).toEqual([]);
    });
  });

  describe("test events", () => {
    it("answers only delivered, failed with a status, or could not connect", async () => {
      const ep = await endpoint();
      expect(await sendTestEvent("maker", ep.id, deps(sent(200), { now: NOW }))).toBe("delivered");
      expect(await sendTestEvent("maker", ep.id, deps(sent(503), { now: NOW }))).toEqual({ failedStatus: 503 });
      expect(await sendTestEvent("maker", ep.id, deps(sent(null), { now: NOW }))).toBe("could_not_connect");
      expect(await sendTestEvent("maker", ep.id, { resolve: async () => ["10.0.0.1"], post: sent(200), now: NOW })).toBe("could_not_connect");
      expect(await deliveries()).toEqual([]); // a test never enters the outbox
    });

    it("goes through the same checks as a real delivery", async () => {
      const ep = await endpoint();
      const post = sent(200);
      await sendTestEvent("maker", ep.id, { resolve: async () => ["93.184.216.34", "169.254.169.254"], post, now: NOW });
      expect(post).not.toHaveBeenCalled();
      await sendTestEvent("maker", ep.id, deps(post, { now: NOW }));
      const req = post.mock.calls[0][0];
      expect(JSON.parse(req.body)).toMatchObject({ type: "webhook.test", livemode: false });
      expect(req.headers["BMT-Signature"]).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    });

    it(`is limited to ${TEST_LIMIT} per creator in ${TEST_WINDOW_MS / MIN} minutes`, async () => {
      const ep = await endpoint();
      const other = await endpoint("other", "https://o.example.com/");
      const post = sent(200);
      for (let i = 0; i < TEST_LIMIT; i++) expect(await sendTestEvent("maker", ep.id, deps(post, { now: NOW + i }))).toBe("delivered");
      expect(await sendTestEvent("maker", ep.id, deps(post, { now: NOW + 10 }))).toBe("limited");
      expect(post).toHaveBeenCalledTimes(TEST_LIMIT);
      expect(await sendTestEvent("other", other.id, deps(post, { now: NOW + 10 }))).toBe("delivered");
      expect(await sendTestEvent("maker", ep.id, deps(post, { now: NOW + TEST_WINDOW_MS }))).toBe("delivered");
    });

    it("limits tests that run at once, and counts failed ones", async () => {
      const ep = await endpoint();
      const results = await Promise.all(Array.from({ length: TEST_LIMIT + 3 }, () => sendTestEvent("maker", ep.id, deps(sent(500), { now: NOW }))));
      expect(results.filter((r) => r === "limited")).toHaveLength(3);
    });

    it("puts a disabled endpoint back in service when a test is delivered", async () => {
      const ep = await endpoint();
      await query("UPDATE webhook_endpoints SET enabled = false, fail_streak = 20 WHERE id = ?", [ep.id]);
      await sendTestEvent("maker", ep.id, deps(sent(200), { now: NOW }));
      expect((await listEndpoints("maker"))[0]).toMatchObject({ status: "active", failStreak: 0 });
    });
  });

  describe("account deletion and the schema", () => {
    it("removes endpoints, deliveries and the test counter with the account, and nobody else's", async () => {
      const ep = await endpoint("maker");
      await endpoint("other", "https://o.example.com/");
      await markPaid(await donation());
      await markPaid(await donation({ creatorId: "other" }));
      await sendTestEvent("maker", ep.id, deps(sent(200), { now: NOW }));
      expect(await deleteAccount("maker", "self_service", NOW)).toBe(true);
      const count = async (table: string, where = "TRUE") => Number((await query(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`)).rows[0].n);
      expect(await count("webhook_endpoints", "creator_id = 'maker'")).toBe(0);
      expect(await count("webhook_test_limits", "creator_id = 'maker'")).toBe(0);
      expect(await count("webhook_deliveries")).toBe(1);
      expect(await count("webhook_endpoints")).toBe(1);
    });

    it("applies twice without error or data loss", async () => {
      await endpoint();
      await mocks.db.exec(SCHEMA);
      await mocks.db.exec(SCHEMA);
      expect(await listEndpoints("maker")).toHaveLength(1);
    });
  });
});

describe("chat webhook URLs", () => {
  beforeAll(async () => {
    mocks.db = new PGlite();
    await mocks.db.exec(SCHEMA);
  });

  beforeEach(async () => {
    await mocks.db.exec("TRUNCATE users CASCADE; TRUNCATE ops_events; DROP TRIGGER IF EXISTS boom ON webhook_deliveries;");
    await creator("maker");
  });

  afterAll(async () => {
    await mocks.db.close();
  });

  it("refuses Discord and Slack webhook URLs on save, without saving them", async () => {
    for (const url of [
      "https://discord.com/api/webhooks/123/abc",
      "https://canary.discord.com/api/webhooks/123/abc",
      "https://hooks.slack.com/services/T123/B123/abc",
    ]) {
      expect(await addEndpoint("maker", url, { resolve: PUBLIC })).toEqual({
        error: expect.stringContaining("your own server"),
      });
    }
    expect(await listEndpoints("maker")).toEqual([]);
  });
});
