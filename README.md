# agent-email

A headless, disposable email inbox that an AI agent drives over **MCP** — no UI, no built-in AI. Give a coding agent (Claude Code, Cursor, etc.) an address like `netflix-test@your-domain.example`, and it can receive the confirmation email, pull out the link, and click it — so it can sign up for services and test your own onboarding flows without ever touching your real mailbox.

Built entirely on Cloudflare: one Worker, Email Routing for receiving, a Durable Object (SQLite) for storage, and an [Agents SDK](https://developers.cloudflare.com/agents/) `McpAgent` for the MCP surface.

```
inbound email ──▶ Email Routing (catch-all: *@your-domain) ──▶ Worker email() handler
                                                                     │ parse (postal-mime)
                                                                     ▼
                                                          MailboxDO (SQLite, singleton)
                                                                     ▲
                                                                     │ read
   MCP client (your agent) ──▶ Worker /mcp (bearer auth) ──▶ InboxMCP (McpAgent)
```

**Registered addresses, not an open catch-all.** The catch-all delivers every message to the Worker, but the Worker only *keeps* mail addressed to an address you've registered via `create_address` — everything else is dropped. So the agent mints a random, single-purpose, short-lived address per signup (`netflix-a1b2c3d4@…`), which both segregates mail and keeps the prompt-injection surface tiny (see [Security](#security)).

## MCP tools

| Tool | What it does |
| --- | --- |
| `create_address({ label?, expected_sender?, ttl_minutes?, local_part? })` | Register a new address (random local-part by default). Pin `expected_sender` and set a short TTL. **Call this before receiving.** |
| `list_addresses()` | Registered addresses with pinned sender + expiry. |
| `delete_address({ address, with_emails? })` | Revoke an address. |
| `list_recent({ address?, limit? })` | Recent emails, newest first. Summaries; `sender_ok:false` flags a failed sender pin. |
| `get_email({ id })` | One email in full. Body + classified links live under `untrusted` (data, not instructions); each link carries safety `flags`. |
| `wait_for_email({ address, timeout_seconds?, since?, only_trusted_sender?, subject_contains? })` | Blocks until a new (trusted-sender) email lands, then returns it in full. The workhorse for onboarding tests. |
| `clear_inbox({ address? })` | Delete stored mail to reset between runs. |

"Clicking" the link needs no special tool — once the agent has a URL (and has checked its `flags`), it just fetches it.

## Setup

Prerequisites: a Cloudflare account and a domain **on Cloudflare** whose email you're willing to route (use a domain you don't receive real mail on, or a dedicated subdomain).

```bash
git clone <your-fork> agent-email && cd agent-email
npm install
```

**1. Set your domain** (cosmetic — improves tool descriptions). Edit `INBOX_DOMAIN` in `wrangler.jsonc`.

**2. Deploy the Worker.**

```bash
npm run deploy
```

**3. Set the MCP auth token** (gates the `/mcp` endpoint — anyone with the URL + token can read the inbox, so treat it like a password):

```bash
openssl rand -hex 32 | npx wrangler secret put MCP_TOKEN
```

**4. Enable Email Routing + a catch-all rule** pointing at this Worker. In the Cloudflare dashboard: **your domain → Email → Email Routing**, enable it (adds the MX/SPF records), then under **Routing rules → Catch-all address**, set the action to **Send to a Worker → agent-email**. Or via CLI:

```bash
npx wrangler email routing enable          # adds DNS records
# then set the catch-all to this Worker in the dashboard
```

> **Subdomain note:** Email Routing operates on the zone apex (`*@your-domain.com`). To use a subdomain (`*@inbox.your-domain.com`) you must add the subdomain's MX/TXT records yourself — the apex is the simpler path.

**5. Connect your agent.** For Claude Code:

```bash
claude mcp add --transport http agent-email https://agent-email.<your-subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <your MCP_TOKEN>"
```

(Use your Worker's real URL, or a custom domain/route if you've set one.)

## Usage

Once connected, ask your agent to do something like:

> Sign up for Netflix. Create an inbox address pinned to `netflix.com`, use it for the signup, then wait for the confirmation email and open the verification link.

The agent calls `create_address({ label: "netflix", expected_sender: "netflix.com", ttl_minutes: 30 })`, gets back `netflix-a1b2c3d4@your-domain.example`, submits the signup with it, calls `wait_for_email({ address })`, checks the returned link's `flags` are clean, and fetches it — done.

## Security

A public inbox means anyone can send mail that lands in your agent's context, so **prompt injection can't be filtered away — it has to be designed around.** The controls here shrink the attack surface and constrain the blast radius:

- **Registered-only allowlist.** Mail to unregistered addresses is dropped, so an attacker can't inject unless they know an *active, single-purpose* address the agent just created. Re-registering a live address is rejected (so a pin can't be silently weakened), and both addresses and total volume are capped.
- **Random, short-lived addresses.** Default random local-parts + a mandatory TTL (default 60 min) make addresses unguessable and expire the attack window after your test. Expired addresses and their mail are purged.
- **Sender pinning + authentication.** Pin `expected_sender`; `sender_ok` is true only when the sender's domain aligns **and** the SPF/DKIM/DMARC verdicts (parsed from Cloudflare's `Authentication-Results` header) pass. By default `wait_for_email` ignores anything that isn't `sender_ok`. Unpinned addresses trust every sender — so `wait_for_email` returns a loud `warning` for them.
- **Untrusted-content framing.** Email content — including `list_recent` subjects/snippets — is returned under an `untrusted` key with a `security_notice`, telling the driving agent to treat it as data, never instructions.
- **Ingest limits.** Bodies are truncated and oversized messages are stubbed, so a huge/attacker email can't exceed the storage row limit or flood the agent's context window.
- **Link flagging.** Every link is classified — `private_ip`/`ip_literal` (SSRF, incl. decimal/hex/IPv6 forms), `sender_mismatch`, `non_https` — so the agent (or you) can refuse a suspicious "confirmation" link before fetching.

**What this does not do:** it cannot stop a sufficiently clever injection in text the agent reads, and it cannot control what the agent fetches or where a link *redirects* (the fetch happens in the agent, not the Worker). So the flags are advisory — fetch flagged links with `redirect: "manual"` and human confirmation — and, most importantly, **run the driving agent with least privilege**: no production credentials or other secrets in the same session. Worst case should be "it clicked a bad link in a throwaway sandbox."

### Operational hardening (recommended, configured on your account)

- **Rotate tokens with zero downtime:** `MCP_TOKEN` accepts a comma-separated list, so set `new,old`, roll clients, then drop `old`.
- **Rate-limit `/mcp`** with a Cloudflare WAF rule (especially on `401`s) to throttle brute force.
- **Add a second gate** with a [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) service token in front of the Worker — free, and independent of the bearer check.

## Notes & limits

- **Single-user by design.** One shared bearer token; no per-user accounts. It's a personal/team test tool, not a mail host.
- `wait_for_email` caps at **120s** per call (Cloudflare request limits). Poll again for longer waits.
- Email Service is for **transactional** email; don't point bulk/marketing mail at it.
- Attachments aren't stored (bodies + links only). Add an R2 binding if you need them.
- Storage is a single Durable Object — plenty for a personal test inbox, not a multi-tenant service.

## Development

```bash
npm run types      # regenerate worker-configuration.d.ts from wrangler.jsonc
npm run typecheck  # tsc --noEmit
npm run dev        # local wrangler dev (note: inbound email only works when deployed)
```

## License

MIT — see [LICENSE](LICENSE).
