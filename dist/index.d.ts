/**
 * opencode-oci-oidc
 *
 * Authenticates with an OCI IAM Confidential Application via the OAuth 2.0
 * Client Credentials grant, then makes the resulting Bearer token available
 * to an OpenAI-compatible LLM endpoint running on OCI GPUs.
 *
 * Config is read from opencode.json (no env vars required).
 * Secrets (client_secret) are read from a file via {file:} substitution,
 * keeping them out of source-controlled config.
 *
 * Real OpenCode plugin SDK hooks used:
 *   - shell.env          → inject OCI_BEARER_TOKEN into every shell/tool env
 *   - tool.execute.before → gate bash commands that would leak the secret
 *   - event              → refresh token on session.created
 *   - tool (custom)      → oci_oidc_refresh — lets the agent trigger a refresh
 */
import type { Plugin } from "@opencode-ai/plugin";
export declare const OciOidcPlugin: Plugin;
export default OciOidcPlugin;
//# sourceMappingURL=index.d.ts.map