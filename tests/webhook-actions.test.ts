import { PGlite } from "@electric-sql/pglite";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

process.env.ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");

const mocks = vi.hoisted(() => ({
  db: null as unknown as PGlite,
  revalidatePath: vi.fn(),
  addEndpoint: vi.fn(),
  rotateSecret: vi.fn(),
  deleteEndpoint: vi.fn(),
  sendTestEvent: vi.fn(),
}));

vi.mock("next/cache", () => ({ revalidatePath: mocks.revalidatePath }));
vi.mock("../src/lib/session", async () => {
  const { TERMS_VERSION } = await import("../src/lib/legal/config");
  return {
    requireCreator: async () => ({ id: "creator", username: "maker", termsVersion: TERMS_VERSION, termsAcceptedAt: 1, ageConfirmedAt: 1 }),
  };
});
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
vi.mock("../src/lib/webhooks", () => ({
  addEndpoint: mocks.addEndpoint,
  rotateSecret: mocks.rotateSecret,
  deleteEndpoint: mocks.deleteEndpoint,
  sendTestEvent: mocks.sendTestEvent,
}));

import { SCHEMA, query } from "../src/lib/db";
import {
  addWebhookAction,
  deleteWebhookAction,
  rotateWebhookAction,
  testWebhookAction,
} from "../src/app/dashboard/account/webhook-actions";

describe("webhook actions", () => {
  beforeAll(async () => {
    mocks.db = new PGlite();
    await mocks.db.exec(SCHEMA);
  });

  beforeEach(async () => {
    await mocks.db.exec("TRUNCATE ops_events;");
    vi.clearAllMocks();
  });

  it("reports a failed save and still shows the short message", async () => {
    mocks.addEndpoint.mockRejectedValueOnce(new Error("db down"));
    mocks.rotateSecret.mockRejectedValueOnce(new Error("db down"));
    mocks.deleteEndpoint.mockRejectedValueOnce(new Error("db down"));
    mocks.sendTestEvent.mockRejectedValueOnce(new Error("db down"));
    const form = new FormData();
    form.set("url", "https://hooks.example.com/hook");
    expect(await addWebhookAction({}, form)).toEqual({ error: "Couldn't save that. Try again." });
    expect(await rotateWebhookAction("endpoint-id")).toEqual({ error: "Couldn't save that. Try again." });
    expect(await deleteWebhookAction("endpoint-id")).toEqual({ error: "Couldn't save that. Try again." });
    expect(await testWebhookAction("endpoint-id")).toEqual({ error: "Test failed: could not connect." });
    const events = await query("SELECT tag FROM ops_events");
    expect(events.rows.map((row) => (row as { tag: string }).tag).sort()).toEqual(
      ["[webhooks] add endpoint", "[webhooks] delete endpoint", "[webhooks] rotate secret", "[webhooks] test event"].sort(),
    );
  });

  it("says a 4xx test answer means the receiver rejected the event", async () => {
    mocks.sendTestEvent.mockResolvedValueOnce({ failedStatus: 400 });
    expect(await testWebhookAction("endpoint-id")).toEqual({
      error: "Test failed: the receiver rejected the event (status 400).",
    });
    mocks.sendTestEvent.mockResolvedValueOnce({ failedStatus: 503 });
    expect(await testWebhookAction("endpoint-id")).toEqual({ error: "Test failed with status 503." });
  });
});
