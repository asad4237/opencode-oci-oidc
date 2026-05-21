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

import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
import { exec } from "child_process"
import { createServer, IncomingMessage, ServerResponse } from "http"
import { homedir, tmpdir } from "os"
import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"

// ─────────────────────────────────────────────────────────────────────────────
// § 1 — Types
// ─────────────────────────────────────────────────────────────────────────────

type LogLevel   = "NONE" | "ERROR" | "WARN" | "INFO" | "DEBUG" | "VERBOSE"
type AuthMethod = "confidential_app" | "mobile_app"

/** All config lives in a single oci-auth.config.jsonc. */
interface OciAuthConfig {
  // ── OCI IAM credentials ──────────────────────────────────────────────
  domain_url:            string
  client_id:             string
  client_secret?:        string
  redirect_uri?:         string
  browser_redirect_uri?: string
  scope?:                string
  llm_base_url:          string
  // ── Plugin behaviour ─────────────────────────────────────────────────
  auth_method:                   AuthMethod
  log_level:                     LogLevel
  log_file:                      string | null
  browser_timeout_seconds:       number
  device_poll_interval_seconds:  number
  device_timeout_seconds:        number
  auth_on_startup:               boolean
  max_retry_attempts:            number
  retry_delay_ms:                number
}

const BEHAVIOUR_DEFAULTS: Pick<
  OciAuthConfig,
  | "auth_method" | "log_level" | "log_file"
  | "browser_timeout_seconds" | "device_poll_interval_seconds"
  | "device_timeout_seconds" | "auth_on_startup"
  | "max_retry_attempts" | "retry_delay_ms"
> = {
  auth_method:                  "confidential_app",
  log_level:                    "INFO",
  log_file:                     null,
  browser_timeout_seconds:      120,
  device_poll_interval_seconds: 5,
  device_timeout_seconds:       300,
  auth_on_startup:              false,
  max_retry_attempts:           3,
  retry_delay_ms:               1000,
}

const REQUIRED_AUTH_FIELDS = ["domain_url", "client_id", "llm_base_url"] as const

// ─────────────────────────────────────────────────────────────────────────────
// § 1b — Process-level safety net
// Catches any error that escapes our try/catch blocks (e.g. in async callbacks
// not directly awaited, retry loops, background tasks).
// ─────────────────────────────────────────────────────────────────────────────

process.on("unhandledRejection", (reason, promise) => {
  try {
    const msg = reason instanceof Error ? reason.message : String(reason)
    writeLog("ERROR", "[oci-auth] Unhandled promise rejection (bug — please report)", { reason: msg, promise: String(promise) })
  } catch { /* never crash inside the safety net */ }
})

process.on("uncaughtException", (err) => {
  try {
    writeLog("ERROR", "[oci-auth] Uncaught exception (bug — please report)", { err: err.message, stack: err.stack })
  } catch { /* never crash inside the safety net */ }
})

// ─────────────────────────────────────────────────────────────────────────────
// § 2 — Logger
// ─────────────────────────────────────────────────────────────────────────────

const LOG_RANK: Record<LogLevel, number> = {
  NONE: 0, ERROR: 1, WARN: 2, INFO: 3, DEBUG: 4, VERBOSE: 5,
}

let _logLevel: LogLevel = "INFO"
// Default until initLogger() is called. Uses CACHE_DIR so it is always writable.
// On Linux/macOS this resolves to ~/.cache/opencode-oci-oidc/plugin.log;
// on Windows to %LOCALAPPDATA%\opencode-oci-oidc\plugin.log.
// The legacy ~/oci-oidc-debug.log path is preserved if the user explicitly
// sets "log_file": "~/oci-oidc-debug.log" in their config.
let _logFile: string = join(homedir(), "oci-oidc-debug.log")   // overridden in initLogger

function getDefaultLogFile(): string {
  // Linux / macOS: ~/oci-oidc-debug.log  (matches what users already know)
  // Windows:       %LOCALAPPDATA%\opencode-oci-oidc\plugin.log (home root is less accessible)
  return process.platform === "win32"
    ? join(CACHE_DIR, "plugin.log")
    : join(homedir(), "oci-oidc-debug.log")
}

function initLogger(cfg: OciAuthConfig): void {
  _logLevel = cfg.log_level
  _logFile  = cfg.log_file
    ? cfg.log_file.replace(/^~/, homedir())
    : getDefaultLogFile()
}

function writeLog(level: LogLevel, msg: string, data?: unknown): void {
  if (LOG_RANK[level] > LOG_RANK[_logLevel]) return
  const ts   = new Date().toISOString()
  const body = data !== undefined ? `${msg}: ${safeStr(data)}` : msg
  const line = `[${ts}] [${level}] [oci-auth] ${body}\n`
  try {
    mkdirSync(dirname(_logFile), { recursive: true })
    writeFileSync(_logFile, line, { flag: "a" })
  } catch { /* never crash on log I/O */ }
}

const log = {
  error:   (m: string, d?: unknown) => writeLog("ERROR",   m, d),
  warn:    (m: string, d?: unknown) => writeLog("WARN",    m, d),
  info:    (m: string, d?: unknown) => writeLog("INFO",    m, d),
  debug:   (m: string, d?: unknown) => writeLog("DEBUG",   m, d),
  verbose: (m: string, d?: unknown) => writeLog("VERBOSE", m, d),
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3 — Config loader
// ─────────────────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url)
const __dirname  = dirname(__filename)
const pluginRoot = join(__dirname, "..")

function loadConfig(projectPath: string): OciAuthConfig | null {
  // Search order: project dir first (most specific), then global user config,
  // then plugin root last (development-only fallback — not present in npm installs).
  //
  // When installed via `npm install opencode-oci-oidc`, the plugin root lives
  // inside node_modules and should NOT contain user credentials.  Users should
  // place their oci-auth.config.jsonc in their project directory or in
  // ~/.config/opencode/ for a machine-wide default.
  const candidates = [
    // ── 1. Project directory (per-project config) ─────────────────────────
    join(projectPath, "oci-auth.config.json"),
    join(projectPath, "oci-auth.config.jsonc"),
    // ── 2. Global user config ─────────────────────────────────────────────
    join(homedir(), ".config", "opencode", "oci-auth.config.json"),
    join(homedir(), ".config", "opencode", "oci-auth.config.jsonc"),
    // ── 3. Legacy: separate auth-credentials files ────────────────────────
    // ── 4. opencode.json with oci_oidc / provider key ─────────────────────
    join(projectPath, "opencode.json"),
    join(projectPath, "opencode.jsonc"),
    join(homedir(), ".config", "opencode", "opencode.json"),
    join(homedir(), ".config", "opencode", "opencode.jsonc"),
    // ── 5. Plugin root (dev fallback — not present in production npm installs)
    join(pluginRoot,  "oci-auth.config.json"),
    join(pluginRoot,  "oci-auth.config.jsonc")
  ]

  for (const p of candidates) {
    writeLog("VERBOSE", "Checking config candidate", p)
    try {
      const raw    = readFileSync(p, "utf8")
      const parsed = JSON.parse(stripJsonComments(raw)) as Record<string, unknown>

      // Strategy 1: flat root-level config (merged format or legacy oci-oidc.jsonc)
      if (REQUIRED_AUTH_FIELDS.every(k => parsed[k])) {
        writeLog("DEBUG", "Config loaded (flat format)", p)
        return { ...BEHAVIOUR_DEFAULTS, ...(parsed as Partial<OciAuthConfig>) } as OciAuthConfig
      }

      // Strategy 2: "oci_oidc" top-level key
      const inner = parsed.oci_oidc
      if (inner && typeof inner === "object" &&
          REQUIRED_AUTH_FIELDS.every(k => (inner as Record<string, unknown>)[k])) {
        writeLog("DEBUG", "Config loaded (oci_oidc key)", p)
        return { ...BEHAVIOUR_DEFAULTS, ...(inner as Partial<OciAuthConfig>) } as OciAuthConfig
      }

      // Strategy 3: provider["oci-oidc"].options
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const provOpts = (parsed as any)?.provider?.["oci-oidc"]?.options
      if (provOpts && typeof provOpts === "object" &&
          REQUIRED_AUTH_FIELDS.every(k => (provOpts as Record<string, unknown>)[k])) {
        writeLog("DEBUG", "Config loaded (provider.oci-oidc.options)", p)
        return { ...BEHAVIOUR_DEFAULTS, ...(provOpts as Partial<OciAuthConfig>) } as OciAuthConfig
      }

    } catch (err) {
      writeLog("VERBOSE", "Config candidate unreadable", { path: p, err: safeStr(err) })
    }
  }

  return null
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4 — Token cache
// ─────────────────────────────────────────────────────────────────────────────

interface TokenCache {
  access_token:  string
  expires_at:    number
  refresh_token?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-aware writable directory
//
// Corporate environments often restrict writes to home-dir sub-paths.
// We try the most natural location for each OS, then fall back to tmpdir().
// ─────────────────────────────────────────────────────────────────────────────

function getPlatformCacheDir(): string {
  const candidates =
    process.platform === "win32"
      ? [
          // Windows: LOCALAPPDATA (e.g. C:\Users\me\AppData\Local\opencode-oci-oidc)
          process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "opencode-oci-oidc"),
          process.env.APPDATA      && join(process.env.APPDATA,      "opencode-oci-oidc"),
          join(homedir(), "AppData", "Local", "opencode-oci-oidc"),
        ]
      : [
          // Linux / macOS: XDG_CACHE_HOME → ~/.cache → ~/.opencode-oci-oidc
          process.env.XDG_CACHE_HOME && join(process.env.XDG_CACHE_HOME, "opencode-oci-oidc"),
          join(homedir(), ".cache", "opencode-oci-oidc"),
          join(homedir(), ".opencode-oci-oidc"),
        ]

  for (const dir of candidates) {
    if (!dir) continue
    try {
      mkdirSync(dir, { recursive: true })
      const probe = join(dir, ".write-probe")
      writeFileSync(probe, "ok", "utf8")
      unlinkSync(probe)
      return dir                       // first writable candidate wins
    } catch {
      continue
    }
  }

  // Last resort — OS temp dir is always writable
  const fallback = join(tmpdir(), "opencode-oci-oidc")
  mkdirSync(fallback, { recursive: true })
  return fallback
}

// Resolved once at module load so all reads/writes use the same path.
const CACHE_DIR  = getPlatformCacheDir()
const CACHE_PATH = join(CACHE_DIR, "token.json")

let _memCache: TokenCache | null = null

// Timestamp (ms) of the most-recent session.created event.
// Used to distinguish OpenCode's automatic startup probe requests (which fire
// within ~100 ms of session.created) from real user-initiated LLM requests.
// Set to 0 initially — the first loader call before any session is treated as
// part of the startup period so we never open a browser on plugin load.
let _sessionCreatedAt = 0

function isCacheValid(c: TokenCache | null): c is TokenCache {
  return !!c && Date.now() < c.expires_at
}

function readDiskCache(): TokenCache | null {
  try {
    const cache = JSON.parse(readFileSync(CACHE_PATH, "utf8")) as TokenCache
    log.verbose("Disk cache read", { tail: cache.access_token?.slice(-8) })
    return cache
  } catch {
    return null
  }
}

function writeDiskCache(cache: TokenCache): void {
  try {
    mkdirSync(dirname(CACHE_PATH), { recursive: true })
    writeFileSync(CACHE_PATH, JSON.stringify(cache), "utf8")
    log.debug("Token written to disk cache")
  } catch (err) {
    log.warn("Could not write disk cache (non-fatal)", safeStr(err))
  }
}

function storeToken(accessToken: string, expiresInSeconds: number, refreshToken?: string, marginSec = 60): string {
  const ttl   = Math.max(expiresInSeconds - marginSec, 60)
  const cache: TokenCache = { access_token: accessToken, expires_at: Date.now() + ttl * 1000 }
  if (refreshToken) cache.refresh_token = refreshToken
  _memCache = cache
  writeDiskCache(cache)
  log.info("Token cached", { expires_in_s: ttl, tail: accessToken.slice(-8), has_refresh: !!refreshToken })
  return accessToken
}

/** Returns cached token if valid; throws if no valid cache (never triggers browser). */
function getCachedToken(): string | null {
  if (isCacheValid(_memCache)) { log.debug("Memory cache hit"); return _memCache.access_token }
  const disk = readDiskCache()
  if (isCacheValid(disk)) { _memCache = disk; log.debug("Disk cache hit"); return disk.access_token }
  return null
}

/**
 * Try to silently refresh the access token using a stored refresh_token.
 * Returns the new access token on success, null if no refresh_token is stored
 * or if the refresh_token itself is expired/rejected.
 */
async function tryRefreshToken(cfg: OciAuthConfig): Promise<string | null> {
  const cache = _memCache ?? readDiskCache()
  if (!cache?.refresh_token) {
    log.debug("tryRefreshToken: no refresh_token in cache")
    return null
  }
  log.info("tryRefreshToken: attempting silent token refresh")
  const url     = `${cfg.domain_url}/oauth2/v1/token`
  const body    = new URLSearchParams({
    grant_type:    "refresh_token",
    refresh_token: cache.refresh_token,
  })
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }
  if (cfg.client_secret) {
    headers.Authorization = `Basic ${Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString("base64")}`
  } else {
    body.set("client_id", cfg.client_id)
  }
  try {
    const token = await postForToken(url, headers, body)
    log.info("tryRefreshToken: silent refresh succeeded")
    return token
  } catch (err) {
    log.warn("tryRefreshToken: refresh_token rejected — will fall back to full auth flow", safeStr(err))
    // Wipe the stale refresh token so we don't loop on it
    _memCache = null
    try { const { unlinkSync: rm } = await import("fs"); rm(CACHE_PATH) } catch { /* ok */ }
    return null
  }
}

/** Full token resolution — checks cache, tries refresh_token, then full auth flow. */
async function getToken(cfg: OciAuthConfig): Promise<string> {
  log.debug("getToken called")
  const cached = getCachedToken()
  if (cached) return cached

  // Try silent refresh before triggering browser/device flow
  const refreshed = await tryRefreshToken(cfg)
  if (refreshed) return refreshed

  log.info("No valid cached token and no refresh_token — triggering full auth flow", { method: cfg.auth_method })
  return fetchFreshToken(cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5 — Token fetch
// ─────────────────────────────────────────────────────────────────────────────

async function fetchFreshToken(cfg: OciAuthConfig): Promise<string> {
  let lastErr: unknown
  for (let attempt = 1; attempt <= cfg.max_retry_attempts; attempt++) {
    try {
      return cfg.auth_method === "mobile_app"
        ? await fetchTokenDeviceFlow(cfg)
        : await fetchTokenBrowserFlow(cfg)
    } catch (err) {
      log.error(`total_max_retry_attempts ${cfg.max_retry_attempts} token fetch attempt failed`, safeStr(err))
      lastErr = err
      if (attempt < cfg.max_retry_attempts) {
        const delay = cfg.retry_delay_ms * 2 ** (attempt - 1)
        log.warn(`Token fetch attempt ${attempt}/${cfg.max_retry_attempts} failed — retrying in ${delay}ms`, safeStr(err))
        await sleep(delay)
      } else {
        log.error(`All ${cfg.max_retry_attempts} token fetch attempts failed`, safeStr(err))
      }
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))
}

// ── 5a  Authorization Code flow (confidential_app) ───────────────────────────

async function fetchTokenBrowserFlow(cfg: OciAuthConfig): Promise<string> {
  const internalUri = cfg.redirect_uri ?? "http://localhost:8888/callback"
  let internalUrl: URL
  try {
    internalUrl = new URL(internalUri)
  } catch {
    throw new Error(`[oci-auth] Invalid redirect_uri: "${internalUri}"`)
  }
  const listenPort      = Number(internalUrl.port) || 8888
  const publicRedirectUri = cfg.browser_redirect_uri ?? internalUri

  const state  = randomState()
  const authUrl = buildAuthUrl(cfg, publicRedirectUri, state)

  log.info("Opening browser for OCI auth", { listenPort, publicRedirectUri })
  log.debug("Auth URL", authUrl)
  openBrowser(authUrl)

  const code = await waitForAuthCode(internalUrl, listenPort, state, authUrl, cfg.browser_timeout_seconds)
  log.info("Authorization code received — exchanging for token")
  return exchangeCodeForToken(cfg, code, publicRedirectUri)
}

/**
 * Start callback server but return a promise + cleanup handle instead of awaiting inline.
 * Used by authorize() so the server can run while OpenCode handles the browser.
 */
function startCallbackServer(
  callbackUrl: URL,
  port: number,
  expectedState: string,
  authUrl: string,
  timeoutSec: number,
): { codePromise: Promise<string>; cleanup: () => void } {
  let resolveCode!: (code: string) => void
  let rejectCode!:  (err: Error)   => void
  const codePromise = new Promise<string>((res, rej) => { resolveCode = res; rejectCode = rej })

  let timer: NodeJS.Timeout
  const done = (fn: () => void) => { clearTimeout(timer); server.close(); fn() }

  const server = createServer((_req: IncomingMessage, res: ServerResponse) => {
    const req = _req
    if (!req.url) { res.writeHead(400); res.end(); return }

    const reqUrl = new URL(req.url, `http://localhost:${port}`)
    log.verbose("Callback received", { path: reqUrl.pathname })
    if (reqUrl.pathname !== callbackUrl.pathname) { res.writeHead(404); res.end(); return }

    const error = reqUrl.searchParams.get("error")
    if (error) {
      const desc = reqUrl.searchParams.get("error_description") ?? error
      htmlReply(res, 400, `Authentication error: ${escHtml(desc)}`)
      done(() => rejectCode(new Error(`[oci-auth] OCI error: ${desc}`)))
      return
    }
    if (reqUrl.searchParams.get("state") !== expectedState) {
      htmlReply(res, 400, "State mismatch — possible CSRF. Please retry.")
      done(() => rejectCode(new Error("[oci-auth] OAuth state mismatch")))
      return
    }
    const code = reqUrl.searchParams.get("code")
    if (!code) {
      htmlReply(res, 400, "Missing authorization code. Please retry.")
      done(() => rejectCode(new Error("[oci-auth] Callback missing code")))
      return
    }
    htmlReply(res, 200, "Authentication successful - you may close this window.")
    log.info("Browser auth callback received")
    done(() => resolveCode(code))
  })

  server.on("error", (err: Error) => done(() => rejectCode(new Error(`[oci-auth] Callback server: ${err.message}`))))
  server.listen(port, () => log.debug("Callback server listening", { port }))

  timer = setTimeout(() => {
    server.close()
    rejectCode(new Error(
      `[oci-auth] Browser auth timed out after ${timeoutSec}s.\n` +
      `  Navigate manually to: ${authUrl}\n` +
      `  Then use the oci_oidc_refresh tool to retry.`
    ))
  }, timeoutSec * 1000)

  return { codePromise, cleanup: () => { clearTimeout(timer); server.close() } }
}

/** Await version used by fetchTokenBrowserFlow (direct call path). */
function waitForAuthCode(
  callbackUrl: URL,
  port: number,
  expectedState: string,
  authUrl: string,
  timeoutSec: number,
): Promise<string> {
  const { codePromise } = startCallbackServer(callbackUrl, port, expectedState, authUrl, timeoutSec)
  return codePromise
}

async function exchangeCodeForToken(cfg: OciAuthConfig, code: string, redirectUri: string): Promise<string> {
  const url     = `${cfg.domain_url}/oauth2/v1/token`
  const body    = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri })
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }

  if (cfg.client_secret) {
    headers.Authorization = `Basic ${Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString("base64")}`
  } else {
    body.set("client_id", cfg.client_id)
  }
  log.debug("Exchanging code for token", { url, hasSecret: !!cfg.client_secret })
  return postForToken(url, headers, body)
}

function buildAuthUrl(cfg: OciAuthConfig, redirectUri: string, state: string): string {
  return `${cfg.domain_url}/oauth2/v1/authorize?${new URLSearchParams({
    client_id: cfg.client_id, response_type: "code",
    redirect_uri: redirectUri, scope: cfg.scope ?? "", state,
  })}`
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open"
  exec(`${cmd} "${url}"`, err => { if (err) log.warn("Could not open browser", safeStr(err)) })
}

// ── 5b  Device Authorization Grant (mobile_app) ──────────────────────────────

async function fetchTokenDeviceFlow(cfg: OciAuthConfig): Promise<string> {
  const stdHdr = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }
  log.info("Starting Device Authorization Grant flow")

  const dr = await fetchWithTimeout(`${cfg.domain_url}/oauth2/v1/device/auth`, {
    method: "POST", headers: stdHdr,
    body: new URLSearchParams({ client_id: cfg.client_id, scope: cfg.scope ?? "" }).toString(),
  })
  if (!dr.ok) {
    const text = await dr.text().catch(() => dr.statusText)
    throw new Error(`[oci-auth] Device auth request failed (${dr.status}): ${text}`)
  }
  const dj = (await dr.json()) as {
    device_code: string; user_code: string; verification_uri: string
    expires_in: number; interval?: number
  }

  const pollMs  = Math.max((dj.interval ?? cfg.device_poll_interval_seconds) * 1000, 5000)
  const pad     = (s: string, n: number) => s.padEnd(n)
  const banner  = [
    "",
    "╔══════════════════════════════════════════════════════════════╗",
    "║         OCI Authentication  —  Mobile App Required          ║",
    "╠══════════════════════════════════════════════════════════════╣",
    `║  1. Open the OCI Mobile Authenticator app                    ║`,
    `║     OR visit: ${pad(dj.verification_uri, 46)}║`,
    `║  2. Enter code: ${pad(dj.user_code, 44)}║`,
    `║  Waiting up to ${pad(String(dj.expires_in) + "s for approval…", 44)}║`,
    "╚══════════════════════════════════════════════════════════════╝",
    "",
  ].join("\n")
  process.stdout.write(banner)
  log.info("Device flow: waiting for approval", { user_code: dj.user_code, verification_uri: dj.verification_uri })

  const deadline = Date.now() + Math.min(dj.expires_in, cfg.device_timeout_seconds) * 1000
  while (Date.now() < deadline) {
    await sleep(pollMs)
    const pr  = await fetchWithTimeout(`${cfg.domain_url}/oauth2/v1/token`, {
      method: "POST", headers: stdHdr,
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: dj.device_code, client_id: cfg.client_id,
      }).toString(),
    })
    const pj = (await pr.json().catch(() => ({}))) as Record<string, unknown>
    if (pr.ok && pj.access_token) {
      process.stdout.write("\n✓ OCI authentication successful.\n\n")
      log.info("Device flow: token obtained", { has_refresh_token: !!pj.refresh_token })
      return storeToken(pj.access_token as string, (pj.expires_in as number) ?? 3600, pj.refresh_token as string | undefined)
    }
    const ec = (pj.error as string) ?? ""
    if (ec === "authorization_pending") { log.verbose("Device flow: pending"); continue }
    if (ec === "slow_down")             { log.verbose("Device flow: slow_down"); await sleep(pollMs); continue }
    if (ec === "expired_token")         { throw new Error("[oci-auth] Device code expired — please retry.") }
    if (ec === "access_denied")         { throw new Error("[oci-auth] Device authorization denied by user.") }
    throw new Error(`[oci-auth] Device flow error: ${ec || JSON.stringify(pj)}`)
  }
  throw new Error(`[oci-auth] Device flow timed out after ${cfg.device_timeout_seconds}s.`)
}

// ── 5c  Shared token-endpoint POST ───────────────────────────────────────────

async function postForToken(url: string, headers: Record<string, string>, body: URLSearchParams): Promise<string> {
  const grantType = body.get("grant_type") ?? "unknown"
  log.debug("postForToken: POST to token endpoint", { url, grant_type: grantType })
  const res  = await fetchWithTimeout(url, { method: "POST", headers, body: body.toString() })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    log.error("Token endpoint error", { status: res.status, grant_type: grantType, body: text })
    throw new Error(`[oci-auth] Token request failed (${res.status}): ${text}`)
  }
  const json = (await res.json()) as {
    access_token?: string; expires_in?: number
    refresh_token?: string; token_type?: string; scope?: string
  }
  log.debug("Token endpoint response", {
    has_access_token:  !!json.access_token,
    has_refresh_token: !!json.refresh_token,
    token_type:        json.token_type,
    expires_in:        json.expires_in,
    scope:             json.scope,
  })
  if (!json.access_token) throw new Error("[oci-auth] Token response missing access_token")
  return storeToken(json.access_token, json.expires_in ?? 3600, json.refresh_token)
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6 — Utilities
// ─────────────────────────────────────────────────────────────────────────────

function stripJsonComments(raw: string): string {
  return raw.replace(/^\s*\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "").trim()
}
function randomState(): string {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
}
function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)) }

/**
 * fetch() with an AbortController timeout.
 * Default: 30 s — enough for any OCI token endpoint call.
 * Without this, a stalled network connection hangs the plugin forever.
 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs = 30_000,
): Promise<Response> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal })
    clearTimeout(timer)
    return res
  } catch (err) {
    clearTimeout(timer)
    if ((err as Error).name === "AbortError") {
      throw new Error(`[oci-auth] Network timeout after ${timeoutMs / 1000}s calling ${url}`)
    }
    throw err
  }
}
function safeStr(v: unknown): string {
  try { return typeof v === "object" ? JSON.stringify(v) : String(v) } catch { return String(v) }
}
function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}
function htmlReply(res: ServerResponse, status: number, msg: string): void {
  res.writeHead(status, { "Content-Type": "text/html" })
  res.end(`<html><body><h2>${msg}</h2></body></html>`)
}

// ─────────────────────────────────────────────────────────────────────────────
// § 7 — Plugin export
// ─────────────────────────────────────────────────────────────────────────────

export const OciOidcPlugin: Plugin = async ({ project, client }) => {

  const cfg = loadConfig(project.worktree)
  if (!cfg) {
    writeLog("WARN", "No OCI auth config found — plugin inactive. Create oci-auth.config.jsonc next to the plugin.")
    await client.app.log({ body: { service: "oci-auth", level: "warn", message: "No OCI auth config found — plugin inactive." } })
    return {}
  }

  initLogger(cfg)
  _memCache = null
  const maskStr = (k: string) =>
        !k || k.trim() === "" ? "(none)" : k.length <= 16 ? k : `${k.slice(0, 8)}…${k.slice(-8)}`

  log.info("Plugin initialised", {
    auth_method: cfg.auth_method, log_level: cfg.log_level,
    log_file: _logFile, domain: cfg.domain_url,
    cache_path: CACHE_PATH,
    client_id: maskStr(cfg.client_id)
  })

  await client.app.log({ body: { service: "oci-auth", level: "info",
    message: `OCI auth plugin ready | method: ${cfg.auth_method} | domain: ${cfg.domain_url}` } })

  // Warm memory cache from disk. If auth_on_startup is true, also fetch fresh.
  const disk = readDiskCache()
  if (isCacheValid(disk)) {
    _memCache = disk
    log.info("Valid cached token loaded from disk — no auth needed at startup")
  } else if (cfg.auth_on_startup) {
    log.info("auth_on_startup=true — prefetching token in background")
    getToken(cfg).catch(err =>
      log.warn("Startup prefetch failed (non-fatal)", safeStr(err))
    )
  } else {
    log.info("No cached token — auth will trigger on first LLM request")
  }

  return {

    // ── Token → shell env ────────────────────────────────────────────────────
    "shell.env": async (_input: unknown, output: { env: Record<string, string> }) => {
      try {
        output.env.OCI_BEARER_TOKEN = await getToken(cfg)
        output.env.OCI_OIDC_ACTIVE  = "1"
        log.verbose("Token injected into shell env")
      } catch (err) {
        const msg = `Token refresh in shell.env failed: ${safeStr(err)}`
        log.error(msg)
        await client.app.log({ body: { service: "oci-auth", level: "error", message: msg } })
      }
    },

    // ── Auth hook ────────────────────────────────────────────────────────────
    //
    // STARTUP BROWSER FIX — two-part strategy:
    //
    // 1. loader()     — CACHE ONLY. Returns a token if one is cached; otherwise
    //                   returns {} without triggering any auth flow.
    //                   OpenCode calls loader() at startup to initialise the
    //                   provider. Returning {} here means OpenCode will call
    //                   authorize() only when an actual LLM request is made and
    //                   the loader returns no credentials.
    //                   *** We deliberately do NOT call await _auth() because
    //                   that asks OpenCode to resolve its internal auth state,
    //                   which triggers authorize() immediately if no state exists.
    //
    // 2. authorize()  — FRESH AUTH. Called by OpenCode when loader() returns {}
    //                   and a request needs credentials. Starts the local
    //                   callback server, returns the OCI auth URL (OpenCode opens
    //                   the browser), then callback() exchanges the code for a
    //                   token once the redirect arrives.
    // ─────────────────────────────────────────────────────────────────────────
    auth: {
      provider: "oci-oidc",

      async loader(_auth) {
        // NOTE: OpenCode calls loader() ONCE at startup and caches the result.
        // It does NOT re-call loader() for every LLM request.  For that reason:
        //   - We do NOT trigger auth here (would cause startup browser).
        //   - We do NOT apply the grace-period logic here (pointless — this only
        //     runs at startup, never for real user messages).
        //   - The per-request auth gate lives in the chat.params hook below.
        //
        // Also: Do NOT call await _auth() — it asks OpenCode to resolve stored
        // auth state; if none exists it calls authorize() immediately (startup browser).
        log.debug("Auth loader invoked (startup — result will be cached by OpenCode)")
        const cached = getCachedToken()

        // Always include baseURL — without it OpenCode builds "undefined/chat/completions".
        const baseFields = {
          baseUrl:     cfg.llm_base_url,
          baseURL:     cfg.llm_base_url,
          instanceUrl: cfg.domain_url,
          clientId:    cfg.client_id,
        }

        if (cached) {
          log.debug("Auth loader: returning cached token", { tail: cached.slice(-8) })
          return { apiKey: cached, ...baseFields }
        }

        log.info(
          "Auth loader: no cached token at startup — returning baseURL only. " +
          "First user message will trigger auth via chat.params hook."
        )
        return baseFields
      },

      methods: [
        {
          type:    "oauth" as const,
          label:   "OCI OIDC Authenticator",
          prompts: [],

          async authorize() {
            log.info("authorize() invoked — starting auth flow", { method: cfg.auth_method })

            if (cfg.auth_method === "mobile_app") {
              // Device flow: no browser window. Start the flow and expose it
              // via callback(). OpenCode will await callback() while the user
              // approves on their phone.
              log.info("authorize(): device flow — awaiting mobile approval")
              return {
                method:       "auto" as const,
                url:          `${cfg.domain_url}/oauth2/v1/device/auth`,
                instructions: "Check your terminal — enter the displayed code in the OCI Mobile Authenticator app",
                async callback() {
                  try {
                    const token = await fetchTokenDeviceFlow(cfg)
                    return { type: "success" as const, provider: "oci-oidc",
                             key: "apiKey", metadata: { apiKey: token } }
                  } catch (err) {
                    log.error("[oci-auth] authorize().callback() device flow failed", safeStr(err))
                    throw err instanceof Error ? err : new Error(String(err))
                  }
                },
              }
            }

            // Browser flow (confidential_app)
            const internalUri     = cfg.redirect_uri ?? "http://localhost:8888/callback"
            const internalUrl     = new URL(internalUri)
            const listenPort      = Number(internalUrl.port) || 8888
            const publicRedirectUri = cfg.browser_redirect_uri ?? internalUri
            const state           = randomState()
            const authUrl         = buildAuthUrl(cfg, publicRedirectUri, state)

            // Start the callback server NOW (before browser opens) so it is
            // ready when OCI redirects the user back.
            const { codePromise, cleanup } = startCallbackServer(
              internalUrl, listenPort, state, authUrl, cfg.browser_timeout_seconds
            )

            log.info("authorize(): returning OCI auth URL", { authUrl })

            return {
              method:       "auto" as const,
              url:          authUrl,        // OpenCode opens this in the browser
              instructions: "Complete OCI login in your browser, then return here",
              async callback() {
                log.debug("authorize.callback() invoked — awaiting auth code")
                try {
                  const code  = await codePromise
                  log.debug("authorize.callback() got auth code — exchanging for token")
                  const token = await exchangeCodeForToken(cfg, code, publicRedirectUri)
                  log.info("authorize.callback() browser flow completed successfully")
                  return { type: "success" as const, provider: "oci-oidc",
                           key: "apiKey", metadata: { apiKey: token } }
                } catch (err) {
                  log.error("[oci-auth] authorize().callback() browser flow failed", safeStr(err))
                  cleanup()
                  throw err instanceof Error ? err : new Error(String(err))
                }
              },
            }
          },
        },
      ],
    },

    // ── Events ───────────────────────────────────────────────────────────────
    event: async ({ event }: { event: { type: string } }) => {
      const knownTypes = new Set(["session.created", "session.error", "session.status"])
      if (knownTypes.has(event.type)) {
        log.debug("Event received", event.type)
      } else {
        // Log full payload of unknown events — helps discover new event types.
        //log.info("Event received (unhandled)", safeStr(event))
        log.debug("Event received", event.type)
      }

      // ── session.status ──────────────────────────────────────────────────────
      // Fires periodically with session health / state info.
      // Log it fully so we can see what OpenCode reports while we're "stuck".
      //if (event.type === "session.status") {
//        log.info("session.status", safeStr(event))
  //    }

      if (event.type === "session.error") {
        log.error("Session error", event)

        // Check if the error is a 401 / auth failure from the backend.
        // If so: wipe the cached token and fetch a fresh one automatically.
        // This handles the case where the backend rejects a token as expired
        // (e.g. OCI rotated keys, or the token was issued before a password change).
        const errData = (event as Record<string, unknown>)?.properties as Record<string, unknown> | undefined
        const errObj  = errData?.error as Record<string, unknown> | undefined
        const errInner = errObj?.data as Record<string, unknown> | undefined
        const statusCode: number | undefined =
          (errInner?.statusCode as number | undefined) ??
          (errObj?.statusCode as number | undefined)
        const errMsg = String(
          errInner?.message ?? errObj?.message ?? ""
        ).toLowerCase()

        const isAuthError =
          statusCode === 401 ||
          errMsg.includes("authentication") ||
          errMsg.includes("unauthorized") ||
          errMsg.includes("token") ||
          errMsg.includes("expired")

        if (isAuthError) {
          log.warn(
            `session.error: auth/token error detected (status=${statusCode ?? "?"}, msg="${errMsg}") — ` +
            "attempting silent refresh_token refresh (no browser will open)"
          )
          // Expire the access token in memory but keep the refresh_token on disk.
          // tryRefreshToken() reads the disk cache to find the refresh_token.
          if (_memCache) _memCache = { ..._memCache, access_token: "", expires_at: 0 }
          else { try { const { unlinkSync: rm } = await import("fs"); rm(CACHE_PATH) } catch { /* ok */ } }

          // IMPORTANT: only try SILENT refresh here — never open a browser from an
          // event handler.  If tryRefreshToken() fails (no refresh_token, or OCI
          // rejects it), we log clearly and ask the user to /connect manually.
          tryRefreshToken(cfg).then(token => {
            if (token) {
              log.info("session.error: silent token refresh succeeded", { tail: token.slice(-8) })
            } else {
              log.warn(
                "session.error: no refresh_token available — user must run /connect to re-authenticate"
              )
            }
          }).catch(err => {
            log.error(
              "session.error: silent refresh failed — user must run /connect to re-authenticate",
              String(err)
            )
          })

          await client.app.log({ body: { service: "oci-auth", level: "warn",
            message: "OCI token expired or rejected — refreshing automatically. If the next message also fails, run /connect." }
          }).catch(() => {})
        } else {
          await client.app.log({ body: { service: "oci-auth", level: "error",
            message: `OCI session error (status=${statusCode ?? "?"}) — see ${_logFile}` }
          }).catch(() => {})
        }
      }

      if (event.type === "session.created") {
        // Record the timestamp so loader() can distinguish OpenCode's automatic
        // startup probe (fires within ~100 ms of this event) from real user requests.
        _sessionCreatedAt = Date.now()
        log.debug("session.created: timestamp recorded", { _sessionCreatedAt })

        const cached = getCachedToken()
        if (cached) {
          log.info("session.created: valid cached token — no auth needed at startup")
          await client.app.log({ body: { service: "oci-auth", level: "info",
            message: "OCI token ready for new session" } }).catch(() => {})
        } else {
          log.info(
            `session.created: no cached token — auth will trigger automatically on first user message`
          )
          await client.app.log({ body: { service: "oci-auth", level: "info",
            message: `OCI auth pending (method: ${cfg.auth_method}) — send any message to authenticate` }
          }).catch(() => {})
        }
      }
    },

    // ── Security guard ───────────────────────────────────────────────────────
    "tool.execute.before": async (
      input: { tool: string; args?: { filePath?: string } },
      output: { args: { filePath?: string } }
    ) => {
      const blocklist = ["oci-client-secret", ".secrets", "oci-auth.config", "oci-oidc"]
      if (input.tool === "read" && output.args.filePath &&
          blocklist.some(b => output.args.filePath!.includes(b))) {
        log.warn("Blocked agent attempt to read credential file", output.args.filePath)
        throw new Error("[oci-auth] Reading OCI credential files is not permitted.")
      }
    },

    // ── Per-request auth gate ─────────────────────────────────────────────────
    //
    // chat.params output = { temperature, topP, topK, maxOutputTokens, options }
    // There is NO apiKey in the output — Bearer token injection belongs in
    // chat.headers (see below).  This hook only decides whether to let the
    // request proceed or block it with a user-facing error.
    //
    // Logic:
    //   1. Valid token in our cache → let through (chat.headers will inject it).
    //   2. No token → block with clear message; never send empty credentials.
    // ─────────────────────────────────────────────────────────────────────────
    "chat.params": async (_input: unknown, _output: unknown) => {
      const cached = getCachedToken()
      if (cached) {
        log.debug("chat.params: token in cache — request allowed (chat.headers will inject Bearer)")
        return
      }

      // No token — block the request entirely with a clear user-facing message.
      const errMsg =
        `[oci-auth:chat.params] OCI authentication required — no token available.\n` +
        `Run /connect in opencode to authenticate` +
        (cfg.auth_method === "mobile_app"
          ? " (you will be shown a code to enter in the OCI Mobile Authenticator app)"
          : " (a browser window will open for OCI login)") +
        `, then resend your message.`

      log.warn("BLOCKING request — " + errMsg)
      throw new Error(errMsg)
    },

    // ── Bearer token injection ────────────────────────────────────────────────
    //
    // chat.headers fires before every LLM HTTP request and is the correct place
    // to inject the Authorization header.  We always use the freshest token from
    // our cache — this automatically picks up tokens refreshed after a 401 without
    // needing to reload OpenCode's auth state.
    // ─────────────────────────────────────────────────────────────────────────
    "chat.headers": async (_input: unknown, output: { headers: Record<string, string> }) => {
      try {
        const cached = getCachedToken()
        if (cached) {
          output.headers["Authorization"] = `Bearer ${cached}`
          const tail = cached.length > 16 ? `${cached.slice(0, 8)}…${cached.slice(-8)}` : cached
          log.info("chat.headers: Authorization header injected", { tail })
        } else {
          log.warn("chat.headers: no cached token — Authorization header not set (request will likely 401)")
        }
      } catch (err) {
        log.error("[oci-auth] chat.headers hook threw unexpectedly", safeStr(err))
      }
    },

    // ── Custom tools ─────────────────────────────────────────────────────────
    tool: {

      oci_oidc_refresh: tool({
        description: "Force-refresh the OCI Bearer token. Use after a 401 Unauthorized error or to pre-warm auth.",
        args: {},
        async execute() {
          log.info("oci_oidc_refresh called by agent")
          _memCache = null
          try {
            await fetchFreshToken(cfg)
            return "OCI token refreshed successfully."
          } catch (err) {
            return `OCI token refresh failed: ${safeStr(err)}`
          }
        },
      }),

      oci_oidc_status: tool({
        description: "Show current OCI auth status: token validity, expiry, endpoint and model.",
        args: {},
        async execute() {
          const cache  = _memCache ?? readDiskCache()
          const status = !cache ? "not yet fetched"
            : isCacheValid(cache) ? `valid — expires in ${Math.round((cache.expires_at - Date.now()) / 1000)}s`
            : "expired"
          return [
            "OCI OIDC Auth Status",
            `  Auth method : ${cfg.auth_method}`,
            `  Log level   : ${cfg.log_level}`,
            `  Log file    : ${_logFile}`,
            `  Domain      : ${cfg.domain_url}`,
            `  Client ID   : ${cfg.client_id.slice(0, 8)}…`,
            `  Token       : ${status}`,
            `  LLM URL     : ${cfg.llm_base_url}`,
          ].join("\n")
        },
      }),
    },
  }
}

export default OciOidcPlugin
