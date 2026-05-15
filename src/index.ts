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

import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
import { exec } from "child_process"
import { createServer } from "http"
import { homedir } from "os"
import { readFileSync, writeFileSync, mkdirSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from 'url';

// Simple file logger for debugging
const DEBUG_LOG_PATH = join(homedir(), "oci-oidc-debug.log");
function debugLog(message: string, data?: unknown): void {
  const ts = new Date().toISOString();
  const line = data ? `[${ts}] ${message}: ${JSON.stringify(data)}\n` : `[${ts}] ${message}\n`;
  try {
    writeFileSync(DEBUG_LOG_PATH, line, { flag: "a" });
  } catch {}
}


interface OciOidcConfig {
  /** OCI IAM Domain base URL, no trailing slash.
   *  e.g. "https://idcs-0abc123.identity.oraclecloud.com" */
  domain_url: string

  /** Confidential Application Client ID */
  client_id: string

  /**
   * Confidential Application Client Secret.
   *
   * Best practice: leave this field empty in opencode.json and use the
   * {file:} substitution to point at a secrets file instead:
   *
   *   "client_secret": "{file:~/.secrets/oci-client-secret}"
   *
   * OpenCode resolves {file:} before passing config to plugins.
   */
  client_secret?: string

  /**
   * Optional redirect URI for OIDC Authorization Code flow.
   * If omitted, defaults to "http://localhost:8000/callback".
   */
  redirect_uri?: string

  /** OAuth scopes, space-separated. Leave empty if not required. */
  scope?: string

  /** Base URL of the OpenAI-compatible OCI endpoint, no trailing slash.
   *  e.g. "https://inference.ai.us-chicago-1.oci.oraclecloud.com/v1" */
  llm_base_url: string

  /** Exact model ID accepted by the endpoint.
   *  e.g. "meta-llama/Llama-3.1-70B-Instruct" */
  model_id: string

  /** Human-readable name shown in /models. Falls back to model_id. */
  model_display_name?: string

  /** Context window tokens. Default: 32768. */
  context_tokens?: number

  /** Max output tokens per request. Default: 4096. */
  max_tokens?: number
}

// ─────────────────────────────────────────────────────────────────────────────
// Token cache — persisted to ~/.cache/opencode-oci-oidc/token.json
// so it survives across short plugin reloads within the same session
// ─────────────────────────────────────────────────────────────────────────────

interface TokenCache {
  access_token: string
  expires_at: number // unix ms
}

const CACHE_PATH = join(
  homedir(),
  ".cache",
  "opencode-oci-oidc",
  "token.json"
)

function readCache(): TokenCache | null {
  debugLog("readCache called");
  try {
    const raw = readFileSync(CACHE_PATH, "utf8");
    const cache = JSON.parse(raw) as TokenCache;
    debugLog("readCache succeeded", cache.access_token?.slice(-16));
    return cache;
  } catch {
    return null;
  }
}

function writeCache(cache: TokenCache): void {
  try {
    mkdirSync(dirname(CACHE_PATH), { recursive: true })
      writeFileSync(CACHE_PATH, JSON.stringify(cache), "utf8");
      debugLog("writeCache succeeded", cache.access_token?.slice(-16));
  } catch {
    // Non-fatal — we just won't persist across reloads
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token fetch / refresh
// ─────────────────────────────────────────────────────────────────────────────

let _memCache: TokenCache | null = null

async function fetchFreshToken(cfg: OciOidcConfig): Promise<string> {
  debugLog("fetchFreshToken called", cfg);
  // Determine redirect URI for OIDC flow (default to localhost)
  let redirectUri = cfg.redirect_uri ?? "http://localhost:8888/callback";
  debugLog("Redirect URI resolved", redirectUri);
  let redirectUrl: URL;
  try {
    redirectUrl = new URL(redirectUri);
  } catch {
    throw new Error(`[opencode-oci-oidc] Invalid redirect_uri: ${redirectUri}`);
  }
  const port = Number(redirectUrl.port) || (redirectUrl.protocol === "https:" ? 443 : 80);
  debugLog("Local server will listen on port", port);
  redirectUri = "https://10.238.113.78:8080/proxy/8888/callback" //since i am suing prot forwarding on vscode this url should be called to get the token rather than localhost. in production it will be same url
  const state = Math.random().toString(36).substring(2);
  const authUrl = `${cfg.domain_url}/oauth2/v1/authorize?${new URLSearchParams({
    client_id: cfg.client_id,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: cfg.scope ?? "",
    state,
  }).toString()}`;

  // Open the default browser to start authentication
  debugLog(`Opening browser for OCI OIDC flow: ${authUrl}`);
  try {
    const platform = process.platform;
    const openCmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    exec(`${openCmd} "${authUrl}"`);
  } catch (e) {
    debugLog(`Failed to open browser automatically: ${e}`);
    // If opening fails, user can manually navigate to the URL
  }

  // Await the authorization code via a temporary local server
  const code = await new Promise<string>((resolve, reject) => {
    let timeout: NodeJS.Timeout;
    const server = createServer((req, res) => {
      if (!req.url) {
        res.writeHead(400);
        res.end();
        return;
      }
        const reqUrl = new URL(req.url, `http://localhost:${port}`);
        debugLog("Callback request received", { url: req.url, pathname: reqUrl.pathname });
      if (reqUrl.pathname !== redirectUrl.pathname) {
        res.writeHead(404);
        res.end();
        return;
      }
      const receivedState = reqUrl.searchParams.get("state");
      const codeParam = reqUrl.searchParams.get("code");
      if (receivedState !== state) {
        res.writeHead(400);
        res.end("Invalid state. expected state: " + state + "received state: " + receivedState);
        clearTimeout(timeout);
        reject(new Error("Invalid state. expected state: " + state + "received state: " + receivedState));
        server.close();
        return;
      }
      if (!codeParam) {
        res.writeHead(400);
        res.end("Missing code");
        clearTimeout(timeout);
        reject(new Error("Missing code"));
        server.close();
        return;
      }
      // Success response to browser
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><body>Authentication successful. You may close this window.</body></html>");
      clearTimeout(timeout);
      debugLog("Authentication successful: ", { codeParam: codeParam });
      resolve(codeParam);
      server.close();
    });

    server.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    server.listen(port, () => {
      debugLog("Callback server listening", { port });
      // Server ready, waiting for callback
    });

    timeout = setTimeout(() => {
      reject(new Error("Authorization timeout"));
      server.close();
    }, 2 * 60 * 1000); // 2 minutes
  });

  // Exchange authorization code for access token
  const tokenUrl = `${cfg.domain_url}/oauth2/v1/token`;
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: cfg.client_id,
  });
  if (cfg.client_secret) {
    tokenBody.set("client_secret", cfg.client_secret);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  if (cfg.client_secret) {
    const credentials = Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString("base64");
    headers.Authorization = `Basic ${credentials}`;

    // Explicit safeguard: Ensure they are NOT in the body
    tokenBody.delete("client_id");
    tokenBody.delete("client_secret");
  }
  else {
    // Public client fallback: Pass client_id in body only if there is no secret
    tokenBody.set("client_id", cfg.client_id);
  }
  debugLog("Token endpoint tokenUrl: ", tokenUrl);
  const requestLogPayload = {
    method: "POST",
    headers: headers, // Fully serialized object
    // Convert url-encoded string back into a clean key-value object
    body: Object.fromEntries(tokenBody) 
  };

  // 2. Write to your log file via your custom function
  debugLog("Outgoing Token Request Configuration", requestLogPayload);

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers,
    body: tokenBody.toString(),
  });
  debugLog("Token endpoint response status", res.status);

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      debugLog("Token endpoint error response", {status: res.status, body: text});
      throw new Error(`[opencode-oci-oidc] OCI token request failed (${res.status}): ${text}`);
    }

  const json = (await res.json()) as {
    access_token?: string;
    expires_in?: number;
    refresh_token?: string;
  };
  debugLog("Token endpoint JSON", json.access_token?.slice(-16));
  
  if (!json.access_token) {
    throw new Error("[opencode-oci-oidc] OCI token response is missing access_token");
  }

  const ttl = (json.expires_in ?? 3600) - 60;
  const cache: TokenCache = {
    access_token: json.access_token,
    expires_at: Date.now() + ttl * 1000,
  };
  _memCache = cache;
  writeCache(cache);
      debugLog("Token fetched and cached", cache.access_token?.slice(-16));
  return cache.access_token;
}


async function getToken(cfg: OciOidcConfig): Promise<string> {
  debugLog("getToken called");
  // 1. Check in-memory cache
  if (_memCache && Date.now() < _memCache.expires_at) {
      debugLog("In‑memory cache hit", _memCache.access_token?.slice(-16));
      return _memCache.access_token
  }
  // 2. Check disk cache
  const disk = readCache()
  if (disk && Date.now() < disk.expires_at) {
    _memCache = disk
      debugLog("Disk cache hit", disk.access_token?.slice(-16));
      return disk.access_token
  }
  // 3. Fetch fresh
  return fetchFreshToken(cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// Config loader
//
// OpenCode does NOT pass plugin-specific config keys directly — plugins read
// their own config by parsing project.path + "/opencode.json" (or the global
// config). The cleanest approach is to have users put config under a top-level
// "oci_oidc" key that the plugin reads itself.
// ─────────────────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// If your compiled code runs from /dist or /src, move up one level to the root:
const pluginRoot = join(__dirname, ".."); 

function loadPluginConfig(projectPath: string): OciOidcConfig | null {
  // Try project-level opencode.json first, then global
  const candidates = [
    join(projectPath, "opencode.json"),
    join(projectPath, "opencode.jsonc"),
    join(pluginRoot, "opencode.json"),
    join(pluginRoot, "opencode.jsonc"),
    // Plugin‑specific config files
    join(projectPath, "oci-oidc.json"),
    join(projectPath, "oci-oidc.jsonc"),
    join(homedir(), ".config", "opencode", "opencode.json"),
    join(homedir(), ".config", "opencode", "opencode.jsonc"),

    // Plugin‑specific config files
    join(pluginRoot, "oci-oidc.json"),
    join(pluginRoot, "oci-oidc.jsonc"),
    join(homedir(), ".config", "opencode", "opencode.json"),
    join(homedir(), ".config", "opencode", "opencode.jsonc"),
  ]

  for (const p of candidates) {
    debugLog("Checking config candidate", p);
    try {
        const raw = readFileSync(p, "utf8");
        debugLog("Read config file", { path: p });
        debugLog("Read config file content", { raw });
      // Strip JSON comments for .jsonc
      const stripped = raw
    .replace(/^\s*\/\/.*$/gm, "") // remove line comments starting with //
    .replace(/\/\*[\s\S]*?\*\//g, "") // remove block comments
    .trim()
      const parsed = JSON.parse(stripped) as Record<string, unknown>

        // Try top-level "oci_oidc" config first
        if (parsed.oci_oidc && typeof parsed.oci_oidc === "object") {
           const cfg = parsed.oci_oidc as OciOidcConfig

           // Validate required fields
           const missing = (
             ["domain_url", "client_id", "llm_base_url", "model_id"] as const
           ).filter((k) => !cfg[k])

          if (missing.length > 0) {
            console.warn(
              `[opencode-oci-oidc] Config found in ${p} but missing required fields: ${missing.join(", ")}`
            )
            // Continue to try provider config if available
          } else {
            return cfg
          }
        }

        // Fallback: check provider["oci-oidc"].options
        const providerOpts = (parsed as any).provider?.["oci-oidc"]?.options;
        if (providerOpts && typeof providerOpts === "object") {
           const cfg = providerOpts as OciOidcConfig;
           // Validate required fields
           const missing = (
             ["domain_url", "client_id", "llm_base_url", "model_id"] as const
           ).filter((k) => !cfg[k]);
          if (missing.length > 0) {
            console.warn(
              `[opencode-oci-oidc] Provider config found in ${p} but missing required fields: ${missing.join(", ")}`
            );
            continue;
          }
          return cfg;
        }
        // Direct config file detection: if the parsed object itself contains required fields
         const directKeys = ["domain_url", "client_id", "llm_base_url", "model_id"] as const;
        const hasAllDirect = directKeys.every(k => (parsed as any)[k] !== undefined);
        if (hasAllDirect) {
          const cfg = parsed as any as OciOidcConfig;
          return cfg;
        }

    } catch (err) {
      debugLog('Read config file error: ' + String(err));
      
      // File not found or invalid JSON — try next
    }
  }

  return null
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin export
// ─────────────────────────────────────────────────────────────────────────────

export const OciOidcPlugin: Plugin = async ({ project, client }) => {
  debugLog('OCI OIDC plugin initialized');
  // Clear any existing token cache (forces a fresh OIDC flow each load – useful for debugging)
  _memCache = null;
   // Preserve disk cache across reloads (removed unlinkSync)
  const cfg = loadPluginConfig(project.worktree);
  debugLog("Config loaded: " + JSON.stringify(cfg));

  if (!cfg) {
    debugLog('No "oci_oidc" config block found in opencode.json. ' +
          "Plugin will not activate. See README for setup instructions.");
    await client.app.log({
      body: {
        service: "opencode-oci-oidc",
        level: "warn",
        message:
          'No "oci_oidc" config block found in opencode.json. ' +
          "Plugin will not activate. See README for setup instructions.",
      },
    })
    return {}
  }
  debugLog("OCI OIDC Auth plugin loaded. Domain:" + cfg.domain_url);
  await client.app.log({
    body: {
      service: "opencode-oci-oidc",
      level: "info",
      message: `OCI OIDC Auth plugin loaded. Domain: ${cfg.domain_url}`,
    },
  })

  // Eagerly fetch token at startup to validate credentials early
  try {
    const token = await getToken(cfg);
    process.env.OCI_BEARER_TOKEN = token;
    debugLog("process.env.OCI_BEARER_TOKEN set", token.slice(-16));
    await client.app.log({
      body: {
        service: "opencode-oci-oidc",
        level: "info",
        message: "OCI OIDC initial token fetch succeeded ✓",
      },
    })
  } catch (err) {
    await client.app.log({
      body: {
        service: "opencode-oci-oidc",
        level: "error",
        message: `OCI OIDC initial token fetch failed: ${String(err)}`,
      },
    })
  }

  return {
    // ── Inject the Bearer token into every shell/tool environment ─────────────
    //
    // OpenCode's built-in provider system reads apiKey from env when the
    // provider config uses {env:OCI_BEARER_TOKEN}. We refresh the token here
    // before every shell execution, keeping it current.
    //
    "shell.env": async (
      _input: unknown,
      output: { env: Record<string, string> }
    ) => {
      try {
        const token = await getToken(cfg);
        output.env.OCI_BEARER_TOKEN = token;
        debugLog("Token injected into env", token);
        // Also set as standard OPENAI_API_KEY alias so the AI SDK provider
        // can pick it up from the environment if needed
        output.env.OCI_OIDC_ACTIVE = "1";
      } catch (err) {
        await client.app.log({
          body: {
            service: "opencode-oci-oidc",
            level: "error",
            message: `Token refresh in shell.env failed: ${String(err)}`,
          },
        });
      }
    },
    // Provide the bearer token via the auth hook (used by providers that read {env:…})
    auth: {
      provider: "oci-oidc",

      /**
       * Crucial Loader Hook: Automatically intercept and pass credentials 
       * to the @ai-sdk/openai-compatible provider framework.
       */
      async loader(auth) {
        debugLog("Loader hook invoked by OpenCode LLM client");
        try {
          // Fetch the valid token (will use cache or refresh if expired)
          const token = await getToken(cfg);
          debugLog("Loader passing validated token to provider client", token.slice(-4));
          
          return {
            apiKey: token,
            baseURL: cfg.llm_base_url // Dynamically maps base URL back into the provider configuration
          };
        } catch (err) {
          debugLog("Error resolving token inside auth loader", err);
          return {};
        }
      },

      methods: [
        {
          type: "api",
          label: "OCI OIDC Token Authenticator",
          // Executed if the user manually re-triggers authentication via the CLI
          async authorize() {
            const token = await getToken(cfg);
            debugLog("Manual authorize method called: providing token", token.slice(-4));
            return {
              type: "success",
              key: "apiKey",
              metadata: { apiKey: token },
            };
          },
        },
      ],
    },

    // ── Refresh token when a new session is created ───────────────────────────
event: async ({ event }: { event: { type: string } }) => {
  debugLog("event hook invoked", event.type);
  if (event.type === "session.error") {
    // Log the full error payload to your debug file
    debugLog("DETAILED SESSION ERROR", {
      event: event
    });

    try {
      await client.app.log({
        body: {
          service: "opencode-oci-oidc",
          level: "error",
          message: `OCI Provider Error: ${event ?? "Check oci-oidc-debug.log for raw trace."}`
        },
      });
    } catch {}
    
  }

  if (event.type === "session.created") {
    try {
      const token = await getToken(cfg); // uses cache if valid
      debugLog("session.created: using cached token", !!token);
      await client.app.log({
        body: {
          service: "opencode-oci-oidc",
          level: "info",
          message: "OCI OIDC token ready for new session",
        },
      });
    } catch (err) {
      debugLog("session.created: token retrieval failed, fetching fresh token", err);
      await fetchFreshToken(cfg);
      await client.app.log({
        body: {
          service: "opencode-oci-oidc",
          level: "info",
          message: "OCI OIDC token refreshed for new session (fallback)",
        },
      });
    }
  }
},

    // ── Guard: prevent the agent from reading the config file directly ────────
    // (it contains the client_secret, even if sourced via {file:})
    "tool.execute.before": async (
      input: { tool: string; args?: { filePath?: string; command?: string } },
      output: { args: { filePath?: string } }
    ) => {
      if (
        input.tool === "read" &&
        output.args.filePath &&
        (output.args.filePath.includes("oci-client-secret") ||
          output.args.filePath.includes(".secrets"))
      ) {
        throw new Error(
          "[opencode-oci-oidc] Reading OCI credential files is not allowed."
        )
      }
    },
    // Log the full chat parameters (including the resolved apiKey) before the request is sent
    "chat.params": async (input, output) => {
      debugLog("chat.params", output);
    },

    // ── Custom tool: lets the agent request a token refresh explicitly ────────
    tool: {
      oci_oidc_refresh: tool({
        description:
          "Force-refresh the OCI OIDC Bearer token used to authenticate with " +
          "the OCI GPU LLM endpoint. Call this if you get a 401 Unauthorized " +
          "response from the model.",
        args: {},
        async execute(_args, _ctx) {
       try {
          debugLog("oci_oidc_refresh tool called");
            await fetchFreshToken(cfg)
            return "OCI OIDC token refreshed successfully."
          } catch (err) {
            return `OCI OIDC token refresh failed: ${String(err)}`
          }
        },
      }),

      oci_oidc_status: tool({
        description:
          "Show the current OCI OIDC token status — whether it is valid, " +
          "when it expires, and which LLM endpoint is configured.",
        args: {},
        async execute(_args, _ctx) {
          const cache = _memCache ?? readCache()
          const status = cache
            ? cache.expires_at > Date.now()
              ? `valid (expires in ${Math.round((cache.expires_at - Date.now()) / 1000)}s)`
              : "expired"
            : "not yet fetched"
          return [
            `OCI OIDC Auth Status`,
            `  Domain   : ${cfg.domain_url}`,
            `  Client ID: ${cfg.client_id.slice(0, 8)}…`,
            `  Token    : ${status}`,
            `  LLM URL  : ${cfg.llm_base_url}`,
            `  Model    : ${cfg.model_id}`,
          ].join("\n")
        },
      }),
    },
  }
}

export default OciOidcPlugin
