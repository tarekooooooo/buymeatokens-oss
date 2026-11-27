"use server";

import { revalidatePath } from "next/cache";
import { assertConsent } from "@/lib/consent";
import { reportError   from "@/lib/ops";
import { requireCreator } from "@/lib/session";
import { addEndpoint, deleteEndpoint, rotateSecret, sendTestEvent } from "@/lib/webhooks";

/** `secret` is only ever set in the answer to the call that created it. */
export type WebhookResult = { error?: string; message?: string; secret?: string };

const SAVE_FAILED = "Couldn't save that. Try again.";

export async function addWebhookAction(_prev: WebhookResult, formData: FormData): Promise<WebhookResult> {
  const user = await requireCreator();
  assertConsent(user);
  const added = await addEndpoint(user.id, String(formData.get("url") ?? ""))).catch(async (error) => {
    await reportError("[webhooks] add endpoint", error).catch(() => undefined);
    return { error: SAVE_FAILED };
  });
  if ("error" in added) return { error: added.error };
  revalidatePath("/dashboard/account");
  return { message: "Endpoint added. Copy the signing secret now; it isn't shown again.", secret: added.secret };
}

export async function rotateWebhookAction(id: string): Promise<WebhookResult> {
  const user = await requireCreator();
  assertConsent(user);
  const secret = await rotateSecret(user.id, String(id)).catch(async (error) => {
    await reportError("[webhooks] rotate secret", error).catch(() => undefined);
    return null;
  });
  if (secret === "too_soon") {
    return { error: "This secret was replaced less than 24 hours ago. To start over now, delete the endpoint and add it again." };
  }
  if (!secret) return { error: SAVE_FAILED };
  revalidatePath("/dashboard/account");
  return { message: "New secret. The old one keeps working for 24 hours. Copy this one now.", secret };
}

export async function deleteWebhookAction(id: string): Promise<WebhookResult> {
  const user = await requireCreator();
  assertConsent(user);
  const gone = await deleteEndpoint(user.id, String(id)).catch(async (error) => {
    await reportError("[webhooks] delete endpoint", error).catch(() => undefined);
    return false;
  });
  revalidatePath("/dashboard/account");
  return gone ? { message: "Endpoint deleted." } : { error: SAVE_FAILED };
}

export async function testWebhookAction(id: string): Promise<WebhookResult> {
  const user = await requireCreator();
  assertConsent(user);
  const outcome = await sendTestEvent(user.id, String(id)).catch(async (error) => {
    await reportError("[webhooks] test event", error).catch(() => undefined);
    return "could_not_connect" as const;
  });
  revalidatePath("/dashboard/account");
  if (outcome === "delivered") return { message: "Test event delivered." };
  if (outcome === "limited") return { error: "Too many tests. Try again in a few minutes." };
  if (outcome === "missing") return { error: SAVE_FAILED };
  if (outcome === "could_not_connect") return { error: "Test failed: could not connect." };
  if (outcome.failedStatus >= 400 && outcome.failedStatus < 500) {
    return { error: "Test failed: the receiver rejected the event (status " + outcome.failedStatus + ")." };
  }
    return { error: `Test failed with status ${outcome.failedStatus}.` };
}
