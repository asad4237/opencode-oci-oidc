/**
 * opencode-oci-oidc
 *
 * OpenCode plugin that authenticates with OCI IAM and injects Bearer tokens
 * into an OpenAI-compatible LLM endpoint.
 *
 * Two auth methods (configured via "auth_method" in oci-auth.config.jsonc):
 *
 *   confidential_app — OAuth 2.0 Authorization Code flow + client_secret.
 *                      Browser opens once; subsequent calls use the cached token.
 *
 *   mobile_app       — OAuth 2.0 Device Authorization Grant (RFC 8628).
 *                      No secret, no browser. A short code is printed to the
 *                      terminal; user approves it on the OCI Mobile Authenticator.
 *
 * Config file: oci-auth.config.jsonc  (next to this plugin)
 * Logs:        ~/oci-oidc-debug.log   (default, configurable)
 */
import type { Plugin } from "@opencode-ai/plugin";
export declare const OciOidcPlugin: Plugin;
export default OciOidcPlugin;
//# sourceMappingURL=index.d.ts.map