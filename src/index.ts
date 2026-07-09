import PostalMime from "postal-mime";
import { MailboxDO } from "./mailbox-do";
import { InboxMCP } from "./mcp";

// Durable Object classes must be exported from the entry module.
export { MailboxDO, InboxMCP };

// Ingest limits. Bodies are truncated so a huge/attacker email can't blow through
// the DO SQLite row limit or flood the agent's context window on retrieval.
const MAX_RAW_BYTES = 1_000_000;
const MAX_SUBJECT = 998;
const MAX_TEXT = 32_000;
const MAX_HTML = 128_000;

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "\n…[truncated]" : s;
}

/** host === domain or a subdomain of it. */
function domainMatch(host: string, domain: string): boolean {
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith("." + d);
}

/** Extract the domain from an address or "Name <addr@dom>" string. */
function domainOf(addressLike: string): string {
  const m = addressLike.match(/[<\s]?([^\s<>]+@[^\s<>]+)>?/);
  const addr = m ? m[1] : addressLike;
  return addr.split("@").pop()?.toLowerCase().replace(/[>\s].*$/, "") || "";
}

/**
 * Parse Cloudflare's `Authentication-Results` header into SPF/DKIM/DMARC verdicts.
 * Email Routing runs these upstream; we use them so a spoofed envelope on a domain
 * without a strict DMARC policy doesn't silently satisfy the sender pin.
 */
function parseAuthResults(header: string | null): { spf: string | null; dkim: string | null; dmarc: string | null } {
  if (!header) return { spf: null, dkim: null, dmarc: null };
  const grab = (k: string) => header.match(new RegExp(`\\b${k}=(\\w+)`, "i"))?.[1]?.toLowerCase() ?? null;
  return { spf: grab("spf"), dkim: grab("dkim"), dmarc: grab("dmarc") };
}

async function sha256(s: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
}

/**
 * Constant-time bearer check against MCP_TOKEN. Supports a comma-separated list
 * so tokens can be rotated without downtime. Comparing SHA-256 digests keeps it
 * constant-time and independent of token length. Fails closed.
 */
async function authorized(request: Request, env: Env): Promise<boolean> {
  const tokens = (env.MCP_TOKEN || "").split(",").map((t) => t.trim()).filter(Boolean);
  if (!tokens.length) return false;
  const m = (request.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  const presented = await sha256(m[1]);
  for (const t of tokens) {
    if (crypto.subtle.timingSafeEqual(presented, await sha256(t))) return true;
  }
  return false;
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response("ok\n", { headers: { "content-type": "text/plain" } });
    }

    if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
      if (!(await authorized(request, env))) {
        return new Response("Unauthorized\n", {
          status: 401,
          headers: { "www-authenticate": "Bearer" },
        });
      }
      return InboxMCP.serve("/mcp", { binding: "INBOX_MCP" }).fetch(request, env, ctx);
    }

    return new Response("agent-email: headless MCP inbox. Connect an MCP client to /mcp (bearer auth).\n", {
      headers: { "content-type": "text/plain" },
    });
  },

  async email(message, env, ctx): Promise<void> {
    const to = (message.to || "").toLowerCase();
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName("global"));

    // Allowlist: only retain mail addressed to a registered, unexpired address.
    // Everything else (the open-catch-all attack surface) is silently dropped.
    const reg = await stub.lookupAddress(to, Date.now());
    if (!reg) return;

    const auth = parseAuthResults(message.headers.get("authentication-results"));
    const envelopeDomain = domainOf(message.from || "");
    const headerFromRaw = message.headers.get("from") || "";
    const pinned = !!reg.expected_sender;

    let subject: string;
    let text: string;
    let html: string;
    let headerFrom = headerFromRaw;
    let truncated = false;

    if (message.rawSize > MAX_RAW_BYTES) {
      // Don't parse an oversized message; keep a small stub so wait_for_email
      // still resolves but the body can't flood context.
      subject = truncate(message.headers.get("subject") || "(no subject)", MAX_SUBJECT);
      text = `[Email omitted: ${message.rawSize} bytes exceeds the ${MAX_RAW_BYTES}-byte ingest limit.]`;
      html = "";
      truncated = true;
    } else {
      const raw = await new Response(message.raw).arrayBuffer();
      const parsed = await PostalMime.parse(raw);
      subject = truncate(parsed.subject || "", MAX_SUBJECT);
      const fullText = parsed.text || "";
      const fullHtml = parsed.html || "";
      text = truncate(fullText, MAX_TEXT);
      html = truncate(fullHtml, MAX_HTML);
      truncated = fullText.length > MAX_TEXT || fullHtml.length > MAX_HTML;
      if (parsed.from?.address) headerFrom = parsed.from.address;
    }

    // Sender pin: the pinned domain must align with the (auth-checked) sender.
    // Prefer the header From domain (what DMARC aligns), fall back to envelope.
    const headerFromDomain = domainOf(headerFrom) || envelopeDomain;
    const authOk = (auth.dmarc === "pass" || auth.spf === "pass") && auth.dmarc !== "fail" && auth.spf !== "fail";
    const senderAligned =
      !!reg.expected_sender &&
      (domainMatch(headerFromDomain, reg.expected_sender) || domainMatch(envelopeDomain, reg.expected_sender));
    const senderOk = pinned && senderAligned && authOk;

    await stub.store({
      address: to,
      sender: message.from || "",
      sender_domain: headerFromDomain,
      header_from: headerFrom,
      pinned,
      sender_ok: senderOk,
      expected_sender: reg.expected_sender,
      spf: auth.spf,
      dkim: auth.dkim,
      dmarc: auth.dmarc,
      subject,
      text,
      html,
      truncated,
      message_id: message.headers.get("message-id") || "",
    });
  },
} satisfies ExportedHandler<Env>;
