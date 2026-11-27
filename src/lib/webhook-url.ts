// SSRF defence for webhook URLs. The server makes requests to addresses creators type in, so every check here runs
// when a URL is saved and again before every send (src/lib/webhook-send.ts), and the address that passes is the one
// that is connected to.

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export const URL_MAX_LENGTH = 500;
const BLOCKED_SUFFIXES = [".local", ".internal", ".localhost", ".lan", ".home.arpa", ".localdomain", ".intranet", ".corp"];
// A DNS name: 2+ labels, the last one starting with a letter (so no number in any notation is ever a host).
const DNS_NAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$/;

/** Step 1, no network: the URL's shape. Returns the normalised URL, or why it was refused. */
export function parseWebhookUrl(input: string): { url: URL } | { error: string } {
  const text = input.trim();
  if (!text || text.length > URL_MAX_LENGTH) return { error: "Enter an https:// URL of at most 500 characters." };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { error: "That isn't a valid URL." };
  }
  if (url.protocol !== "https:") return { error: "The URL must start with https://." };
  if (url.username || url.password) return { error: "The URL can't contain a username or password." };
  if (url.port !== "") return { error: "Only the standard https port (443) is allowed." };
  let host = url.hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[") || isIP(host)) return { error: "Use a domain name, not an IP address." };
  if (!DNS_NAME.test(host) || host.length > 253) return { error: "Use a public domain name, like hooks.example.com." };
  if (host === "localhost" || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return { error: "That host name isn't allowed." };
  url.hash = "";
  return { url };
}

function v4Bytes(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

function blockedV4([a, b, c]: number[]): boolean {
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 || // this network, private, loopback, multicast and reserved (incl. broadcast)
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local, incl. the cloud metadata address
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) || // IETF protocol assignments, documentation
    (a === 192 && b === 88 && c === 99) || // 6to4 relay
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

/** Expands an IPv6 text address to 16 bytes, or null if it isn't one. A zone id (%eth0) is refused. */
function v6Bytes(ip: string): number[] | null {
  if (!isIP(ip) || ip.includes("%")) return null;
  let text = ip;
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const v4 = v4Bytes(dotted[2]);
    if (!v4) return null;
    text = `${dotted[1]}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const [head, tail, extra] = text.split("::");
  if (extra !== undefined) return null;
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const fill = tail === undefined ? 0 : 8 - left.length - right.length;
  if (fill < 0 || (tail === undefined && left.length !== 8)) return null;
  const groups = [...left, ...Array(fill).fill("0"), ...right].map((g) => parseInt(g, 16));
  if (groups.length !== 8 || groups.some((g) => !(g >= 0 && g <= 0xffff))) return null;
  return groups.flatMap((g) => [g >> 8, g & 255]);
}

/** True for any address a webhook must never reach. Anything that can't be parsed counts as blocked. */
export function isBlockedAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const bytes = v4Bytes(ip);
    return !bytes || blockedV4(bytes);
  }
  const b = v6Bytes(ip);
  if (!b) return true;
  const g0 = (b[0] << 8) | b[1];
  const g1 = (b[2] << 8) | b[3];
  // Allowlist: global unicast 2000::/3 only. That drops ::, ::1, mapped and compatible v4 (::/96, ::ffff:0:0/96),
  // NAT64 (64:ff9b::/96), unique-local fc00::/7, link-local fe80::/10, site-local, multicast and discard.
  if ((b[0] & 0xe0) !== 0x20) return true;
  if (g0 === 0x2001 && g1 < 0x200) return true; // 2001::/23: Teredo, benchmarking, ORCHID, other IETF assignments
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  if (g0 === 0x2002) return blockedV4(b.slice(2, 6)); // 6to4 embeds an IPv4 address
  if (g0 === 0x3fff && g1 < 0x1000) return true; // documentation
  return false;
}

export type Resolver = (host: string) => Promise<string[]>;

export const resolveAll: Resolver = async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

/**
 * Steps 1 to 3: shape, resolve every address, refuse if ANY is blocked. Returns the first address, which is the one
 * the sender connects to. The reason is for the creator's form when saving; sends and tests never show it.
 */
export async function checkWebhookUrl(input: string, resolve: Resolver = resolveAll): Promise<
  { url: URL; address: string } | { error: string }
> {
  const parsed = parseWebhookUrl(input);
  if ("error" in parsed) return parsed;
  // One answer for "doesn't resolve" and "resolves somewhere private", so saving can't be used to map names.
  const refused = { error: "That address can't receive webhooks. It has to be a public HTTPS server." };
  let addresses: string[];
  try {
    addresses = await resolve(parsed.url.hostname.replace(/\.$/, ""));
  } catch {
    return refused;
  }
  if (!addresses.length || addresses.some(isBlockedAddress)) return refused;
  return { url: parsed.url, address: addresses[0] };
}

/** Chat webhook URLs: a Discord or Slack webhook is a chat endpoint, not an own server. Signed webhooks go to the
 * creator's own server, so addEndpoint refuses these when a URL is saved; sends never show this reason. */
const DISCORD_HOSTS = new Set([
  "discord.com",
  "discordapp.com",
  "canary.discord.com",
  "ptb.discord.com",
  "canary.discordapp.com",
  "ptb.discordapp.com",
]);

export function chatWebhookRefusal(url: URL): string | null {
  let host = url.hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (DISCORD_HOSTS.has(host) && url.pathname.startsWith("/api/webhooks/")) {
    return "This is a Discord webhook. Signed webhooks go to your own server; use Discord notifications for a Discord channel.";
  }
  if (host === "hooks.slack.com" && url.pathname.startsWith("/services/")) {
    return "This is a Slack webhook. Signed webhooks go to your own server, not to Slack.";
  }
  return null;
}
