import { describe, expect, it, vi } from "vitest";
import { chatWebhookRefusal, checkWebhookUrl, isBlockedAddress, parseWebhookUrl } from "../src/lib/webhook-url";

const rejected = [
  "http://example.com/hook",
  "ftp://example.com/",
  "javascript:alert(1)",
  "https://user@example.com/",
  "https://user:pass@example.com/",
  "https://example.com:8443/",
  "https://example.com:444/",
  "https://example.com:80/",
  "https://127.0.0.1/",
  "https://127.1/",
  "https://2130706433/", // decimal
  "https://0177.0.0.1/", // octal
  "https://0x7f.0.0.1/", // hex
  "https://0x7f000001/",
  "https://017700000001/",
  "https://1.2.3/", // shorthand IPv4
  "https://169.254.169.254/latest/meta-data/",
  "https://10.0.0.1/",
  "https://[::1]/",
  "https://[::ffff:127.0.0.1]/",
  "https://[2606:4700:4700::1111]/", // a public IPv6 literal is still a literal
  "https://localhost/",
  "https://LOCALHOST./",
  "https://foo.localhost/",
  "https://intranet/",
  "https://printer.local/",
  "https://db.internal/",
  "https://router.lan/",
  "https://nas.home.arpa/",
  "https://a b.example.com/",
  "https://example/",
  "https://example.123/",
  "",
  "   ",
  `https://example.com/${"a".repeat(500)}`,
];

const allowed = [
  "https://hooks.example.com/path?x=1",
  "https://example.com:443/hook",
  "https://EXAMPLE.com./a",
  "https://bücher.example/hook",
  "https://hooks.example.co.uk/a/b",
];

const blockedAddresses = [
  // IPv4
  "127.0.0.1", "127.1.2.3", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
  "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "224.0.0.1",
  "239.255.255.255", "255.255.255.255", "240.0.0.1", "192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1",
  "198.19.255.255", "198.51.100.1", "203.0.113.1",
  // IPv6
  "::1", "::", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1", "100::1",
  "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:8.8.8.8", // mapped: all refused
  "::127.0.0.1", "::10.0.0.1", "::8.8.8.8", // compatible
  "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::808:808", // NAT64
  "2002:7f00:1::1", "2002:a9fe:a9fe::1", "2002:c0a8:101::1", "2002:a00:1::1", // 6to4 embedding private v4
  "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
  "2001:db8::1", "2001:2::1", "2001:10::1", "3fff::1",
  "fe80::1%eth0", "garbage", "1.2.3", "",
];

const allowedAddresses = [
  "93.184.216.34", "8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.0.3.1",
  "2606:4700:4700::1111", "2001:4860:4860::8888", "2002:5db8:d822::1", // 6to4 of a public address
];

describe("webhook URL shape", () => {
  it.each(rejected)("rejects %s", (url) => {
    expect(parseWebhookUrl(url)).toHaveProperty("error");
  });

  it.each(allowed)("accepts %s", (url) => {
    expect(parseWebhookUrl(url)).toHaveProperty("url");
  });
});

describe("blocked addresses", () => {
  it.each(blockedAddresses)("blocks %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(allowedAddresses)("allows %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
});

describe("resolving a webhook URL", () => {
  const resolver = (...addresses: string[]) => vi.fn(async () => addresses);

  it("returns the first checked address", async () => {
    const resolve = resolver("93.184.216.34", "2606:4700:4700::1111");
    expect(await checkWebhookUrl("https://hooks.example.com/x", resolve)).toMatchObject({ address: "93.184.216.34" });
    expect(resolve).toHaveBeenCalledWith("hooks.example.com");
  });

  it("refuses a name that resolves to a mix of public and private addresses, in any order", async () => {
    expect(await checkWebhookUrl("https://a.example.com/", resolver("93.184.216.34", "10.0.0.5"))).toHaveProperty("error");
    expect(await checkWebhookUrl("https://a.example.com/", resolver("127.0.0.1", "93.184.216.34"))).toHaveProperty("error");
    expect(await checkWebhookUrl("https://a.example.com/", resolver("93.184.216.34", "::ffff:169.254.169.254"))).toHaveProperty("error");
  });

  it("refuses names that point at the metadata address or loopback", async () => {
    for (const ip of ["169.254.169.254", "127.0.0.1", "::1", "100.64.0.1", "fd00::1"]) {
      expect(await checkWebhookUrl("https://sneaky.example.com/", resolver(ip))).toHaveProperty("error");
    }
  });

  it("refuses an empty answer and a failed lookup", async () => {
    expect(await checkWebhookUrl("https://a.example.com/", resolver())).toHaveProperty("error");
    expect(await checkWebhookUrl("https://a.example.com/", vi.fn(async () => { throw new Error("ENOTFOUND"); }))).toHaveProperty("error");
  });

  it("doesn't resolve a URL whose shape is already wrong", async () => {
    const resolve = resolver("93.184.216.34");
    expect(await checkWebhookUrl("http://example.com/", resolve)).toHaveProperty("error");
    expect(resolve).not.toHaveBeenCalled();
  });
});

describe("chat webhook URLs", () => {
  it.each([
    ["Discord", "https://discord.com/api/webhooks/123/abc"],
    ["Discord", "https://discordapp.com/api/webhooks/123/abc"],
    ["Discord", "https://canary.discord.com/api/webhooks/123/abc"],
    ["Discord", "https://ptb.discordapp.com/api/webhooks/123/abc"],
    ["Slack", "https://hooks.slack.com/services/T123/B123/abc"],
  ])("refuses a %s webhook URL and says where it belongs", (name, raw) => {
    const refusal = chatWebhookRefusal(new URL(raw));
    expect(refusal ?? "").toContain(name);
    expect(refusal ?? "").toContain("your own server");
  });

  it.each([
    "https://discord.com/channels/123/456",
    "https://hooks.slack.com/",
    "https://evil-discord.com/api/webhooks/123/abc",
    "https://discord.com.evil.example/api/webhooks/123/abc",
    "https://hooks.example.com/hook",
  ])("accepts %s", (raw) => {
    expect(chatWebhookRefusal(new URL(raw))).toBeNull();
  });
});
