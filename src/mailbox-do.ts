import { DurableObject } from "cloudflare:workers";

export interface StoredEmail {
  id: number;
  address: string;
  sender: string; // envelope MAIL FROM
  sender_domain: string; // domain used for the pin check (header From if present)
  header_from: string; // From: header address
  pinned: number; // 1 = address had an expected_sender
  sender_ok: number; // 1 = pinned AND sender aligned AND auth passed
  expected_sender: string | null;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  subject: string;
  text: string;
  html: string;
  truncated: number;
  message_id: string;
  received_at: number;
}

export interface EmailSummary {
  id: number;
  address: string;
  from: string;
  pinned: boolean;
  sender_ok: boolean;
  received_at: string;
  subject: string;
  snippet: string;
}

export interface IncomingEmail {
  address: string;
  sender: string;
  sender_domain: string;
  header_from: string;
  pinned: boolean;
  sender_ok: boolean;
  expected_sender: string | null;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  subject: string;
  text: string;
  html: string;
  truncated: boolean;
  message_id: string;
}

export interface Registration {
  address: string;
  expected_sender: string | null;
  label: string | null;
  created_at: number;
  expires_at: number | null;
}

export type RegisterResult =
  | { ok: true; registration: Registration }
  | { ok: false; error: string };

const MAX_WAIT_MS = 120_000;
const POLL_INTERVAL_MS = 1_500;
const MAX_EMAILS_PER_ADDRESS = 50;
const MAX_ADDRESSES = 500;

/**
 * Singleton (keyed "global") SQLite store. Holds two tables:
 *  - `addresses`: the allowlist of registered inbox addresses (with optional
 *    sender pinning + TTL). Mail to anything not in here is dropped on arrival.
 *  - `emails`: messages received for registered addresses.
 */
export class MailboxDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = this.ctx.storage.sql;
    sql.exec(`
      CREATE TABLE IF NOT EXISTS addresses (
        address TEXT PRIMARY KEY,
        expected_sender TEXT,
        label TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
      );
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_domain TEXT NOT NULL DEFAULT '',
        header_from TEXT NOT NULL DEFAULT '',
        pinned INTEGER NOT NULL DEFAULT 0,
        sender_ok INTEGER NOT NULL DEFAULT 0,
        expected_sender TEXT,
        spf TEXT,
        dkim TEXT,
        dmarc TEXT,
        subject TEXT NOT NULL DEFAULT '',
        text TEXT NOT NULL DEFAULT '',
        html TEXT NOT NULL DEFAULT '',
        truncated INTEGER NOT NULL DEFAULT 0,
        message_id TEXT NOT NULL DEFAULT '',
        received_at INTEGER NOT NULL
      );
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_addr_time ON emails(address, received_at);`);
  }

  /** Delete expired addresses and their mail. Called opportunistically. */
  purgeExpired(now: number): void {
    const sql = this.ctx.storage.sql;
    sql.exec(
      `DELETE FROM emails WHERE address IN
         (SELECT address FROM addresses WHERE expires_at IS NOT NULL AND expires_at <= ?)`,
      now,
    );
    sql.exec(`DELETE FROM addresses WHERE expires_at IS NOT NULL AND expires_at <= ?`, now);
  }

  // --- Address registration (the allowlist) ------------------------------

  /** Register a new address. Rejects re-registering a live address (would silently weaken its pin). */
  tryRegister(
    address: string,
    expectedSender: string | null,
    label: string | null,
    expiresAt: number | null,
  ): RegisterResult {
    const now = Date.now();
    this.purgeExpired(now);
    const addr = address.toLowerCase();
    if (this.lookupAddress(addr, now)) {
      return { ok: false, error: `Address ${addr} is already registered and active. delete_address first to change it.` };
    }
    const count = [...this.ctx.storage.sql.exec(`SELECT COUNT(*) AS c FROM addresses`)][0].c as number;
    if (count >= MAX_ADDRESSES) {
      return { ok: false, error: `Address limit reached (${MAX_ADDRESSES}). Delete unused addresses first.` };
    }
    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO addresses (address, expected_sender, label, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      addr,
      expectedSender,
      label,
      now,
      expiresAt,
    );
    return { ok: true, registration: this.lookupAddress(addr, 0)! };
  }

  /** Returns the registration if the address exists and (when `now`>0) is unexpired. */
  lookupAddress(address: string, now: number): Registration | null {
    const rows = [
      ...this.ctx.storage.sql.exec(
        `SELECT address, expected_sender, label, created_at, expires_at FROM addresses WHERE address = ?`,
        address.toLowerCase(),
      ),
    ];
    if (!rows.length) return null;
    const r = rows[0] as unknown as Registration;
    if (now > 0 && r.expires_at != null && r.expires_at <= now) return null;
    return r;
  }

  listAddresses(now: number): Array<Registration & { expired: boolean }> {
    return [
      ...this.ctx.storage.sql.exec(
        `SELECT address, expected_sender, label, created_at, expires_at FROM addresses ORDER BY created_at DESC`,
      ),
    ].map((r) => {
      const reg = r as unknown as Registration;
      return { ...reg, expired: reg.expires_at != null && reg.expires_at <= now };
    });
  }

  deleteAddress(address: string, alsoEmails: boolean): number {
    const addr = address.toLowerCase();
    if (alsoEmails) this.ctx.storage.sql.exec(`DELETE FROM emails WHERE address = ?`, addr);
    return this.ctx.storage.sql.exec(`DELETE FROM addresses WHERE address = ?`, addr).rowsWritten;
  }

  // --- Email storage & retrieval -----------------------------------------

  store(email: IncomingEmail): number {
    const sql = this.ctx.storage.sql;
    // Idempotency: a retried delivery with the same Message-ID is stored once.
    if (email.message_id) {
      const dup = [
        ...sql.exec(
          `SELECT id FROM emails WHERE address = ? AND message_id = ? LIMIT 1`,
          email.address,
          email.message_id,
        ),
      ];
      if (dup.length) return dup[0].id as number;
    }
    const id = [
      ...sql.exec(
        `INSERT INTO emails
           (address, sender, sender_domain, header_from, pinned, sender_ok, expected_sender,
            spf, dkim, dmarc, subject, text, html, truncated, message_id, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
        email.address,
        email.sender,
        email.sender_domain,
        email.header_from,
        email.pinned ? 1 : 0,
        email.sender_ok ? 1 : 0,
        email.expected_sender,
        email.spf,
        email.dkim,
        email.dmarc,
        email.subject,
        email.text,
        email.html,
        email.truncated ? 1 : 0,
        email.message_id,
        Date.now(),
      ),
    ][0].id as number;
    // Volume cap: keep only the newest N emails per address.
    sql.exec(
      `DELETE FROM emails WHERE address = ? AND id NOT IN
         (SELECT id FROM emails WHERE address = ? ORDER BY received_at DESC, id DESC LIMIT ?)`,
      email.address,
      email.address,
      MAX_EMAILS_PER_ADDRESS,
    );
    return id;
  }

  listRecent(address: string | null, limit: number): EmailSummary[] {
    const n = Math.max(1, Math.min(limit || 20, 100));
    const rows = address
      ? this.ctx.storage.sql.exec(
          `SELECT id, address, sender, pinned, sender_ok, subject, text, received_at FROM emails
           WHERE address = ? ORDER BY received_at DESC LIMIT ?`,
          address.toLowerCase(),
          n,
        )
      : this.ctx.storage.sql.exec(
          `SELECT id, address, sender, pinned, sender_ok, subject, text, received_at FROM emails
           ORDER BY received_at DESC LIMIT ?`,
          n,
        );
    return [...rows].map((r) => ({
      id: r.id as number,
      address: r.address as string,
      from: r.sender as string,
      pinned: (r.pinned as number) === 1,
      sender_ok: (r.sender_ok as number) === 1,
      subject: r.subject as string,
      received_at: new Date(r.received_at as number).toISOString(),
      snippet: ((r.text as string) || "").replace(/\s+/g, " ").trim().slice(0, 140),
    }));
  }

  get(id: number): StoredEmail | null {
    const rows = [...this.ctx.storage.sql.exec(`SELECT * FROM emails WHERE id = ?`, id)];
    return rows.length ? (rows[0] as unknown as StoredEmail) : null;
  }

  /**
   * Block until an email newer than `since` (epoch ms) arrives for `address`,
   * optionally requiring a trusted sender / subject match. Returns null on
   * timeout. The DO input gate lets the email() handler's store() run during our
   * poll sleeps, so freshly-received mail is visible on the next iteration.
   */
  async waitForEmail(
    address: string,
    since: number,
    timeoutMs: number,
    onlyTrusted: boolean,
    subjectContains: string | null,
  ): Promise<StoredEmail | null> {
    const deadline = Date.now() + Math.min(Math.max(timeoutMs, 0), MAX_WAIT_MS);
    const addr = address.toLowerCase();
    const clauses = ["address = ?", "received_at > ?"];
    const binds: (string | number)[] = [addr, since];
    if (onlyTrusted) clauses.push("sender_ok = 1");
    if (subjectContains) {
      clauses.push("subject LIKE ?");
      binds.push(`%${subjectContains}%`);
    }
    const query = `SELECT * FROM emails WHERE ${clauses.join(" AND ")} ORDER BY received_at ASC LIMIT 1`;
    for (;;) {
      const rows = [...this.ctx.storage.sql.exec(query, ...binds)];
      if (rows.length) return rows[0] as unknown as StoredEmail;
      if (Date.now() >= deadline) return null;
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
  }

  clear(address: string | null): number {
    const cursor = address
      ? this.ctx.storage.sql.exec(`DELETE FROM emails WHERE address = ?`, address.toLowerCase())
      : this.ctx.storage.sql.exec(`DELETE FROM emails`);
    return cursor.rowsWritten;
  }
}
