export interface ClassifiedLink {
  url: string;
  host: string;
  /** Safety flags — non-empty means "inspect before fetching". Advisory only. */
  flags: string[];
}

const NAMED: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
};

function cp(n: number): string {
  try {
    return String.fromCodePoint(n);
  } catch {
    return "";
  }
}

/** Decode the entity forms that actually show up in href attributes, incl. numeric ones. */
function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => cp(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d) => cp(parseInt(d, 10)))
    .replace(/&(amp|lt|gt|quot|apos);/g, (_m, n) => NAMED[n] ?? _m);
}

/** Any IP-literal host form — dotted-quad, bare decimal/hex/octal integer, or IPv6. */
function isIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h.includes(":")) return true; // IPv6 (incl. ::ffff:-mapped)
  if (/^\d+$/.test(h)) return true; // decimal integer form, e.g. 2130706433
  if (/^0x[0-9a-f]+$/.test(h)) return true; // hex
  if (/^0[0-7]+$/.test(h)) return true; // octal
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(h)) return true; // dotted quad
  return false;
}

/** True for loopback / private / link-local / CGNAT hosts — classic SSRF targets. */
function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "0.0.0.0" || h === "::" || h === "::1") return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254 metadata
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  if (h.startsWith("::ffff:127.") || h.startsWith("::ffff:10.")) return true; // IPv4-mapped loopback/private
  if (h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true; // IPv6 ULA / link-local
  return false;
}

/** host === domain or a subdomain of it. */
function domainMatch(host: string, domain: string): boolean {
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith("." + d);
}

function rawUrls(text: string, html: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (raw: string) => {
    const u = decodeEntities(raw.trim()).replace(/[).,;:]+$/, "");
    if (/^https?:\/\//i.test(u) && !seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  };
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) add(m[1]);
  for (const src of [text, html]) {
    for (const m of src.matchAll(/https?:\/\/[^\s<>"'\)\]]+/gi)) add(m[0]);
  }
  return out;
}

/**
 * Collect clickable URLs from an email and classify each for safety. Flags:
 *  - `private_ip`      host is loopback/private/link-local (SSRF risk)
 *  - `ip_literal`      host is a bare IP in any form (no legit confirmation link is)
 *  - `sender_mismatch` expected sender is set and the link host isn't on that domain
 *  - `non_https`       plaintext http link
 *  - `unparseable`     URL failed to parse
 * Advisory only — the inbox can't see where a link redirects, and the agent does
 * the actual fetching. Flags let the agent (or a human) refuse a bad link.
 */
export function collectLinks(
  text: string,
  html: string,
  expectedSender: string | null,
): ClassifiedLink[] {
  return rawUrls(text, html).map((url) => {
    const flags: string[] = [];
    let host = "";
    try {
      const u = new URL(url);
      host = u.hostname;
      if (u.protocol !== "https:") flags.push("non_https");
      if (isIpLiteral(host)) flags.push("ip_literal");
      if (isPrivateHost(host)) flags.push("private_ip");
      if (expectedSender && !domainMatch(host, expectedSender)) flags.push("sender_mismatch");
    } catch {
      flags.push("unparseable");
    }
    return { url, host, flags };
  });
}
