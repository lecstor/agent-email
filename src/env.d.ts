// Augments the wrangler-generated `Env` (worker-configuration.d.ts) with values
// that live outside wrangler.jsonc — i.e. secrets set via `wrangler secret put`.
interface Env {
  /** Bearer token gating the /mcp endpoint. Set with `wrangler secret put MCP_TOKEN`. */
  MCP_TOKEN: string;
}
