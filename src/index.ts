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
import { readFileSync, writeFileSync, mkdirSync, unlinkSync, renameSync } from "fs"
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
  model?:                string
  // ── Debug proxy ───────────────────────────────────────────────────────
  debug_proxy?:          boolean  // start a local logging proxy; set opencode.json baseURL to the proxy address
  debug_proxy_port?:     number   // default 8890
  debug_proxy_target?:   string   // real backend URL the proxy forwards to (defaults to llm_base_url)
  disable_thinking?:     boolean  // inject enable_thinking:false into every request
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
  max_retry_attempts:           1,
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
    // Intentional throws from our own hooks (e.g. chat.params blocking a request)
    // propagate as unhandled rejections when OpenCode doesn't await them.
    // These are expected — do not log them as bugs.
    if (msg.includes("[oci-auth]")) return
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

// OpenCode client reference — set once the plugin initialises.
// Stored as unknown to avoid fighting the SDK's internal generic types;
// cast to any only at the log call site (fire-and-forget, errors suppressed).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _ocClient: any = null

let _logLevel: LogLevel = "INFO"
// Initialized after CACHE_DIR is resolved (see initLogFile() call below).
let _logFile: string = ""

function getDefaultLogFile(): string {
  // Linux / macOS: ~/oci-oidc-debug.log
  // Windows:       %LOCALAPPDATA%\opencode-oci-oidc\plugin.log  (always writable)
  return process.platform === "win32"
    ? join(CACHE_DIR, "plugin.log")
    : join(homedir(), "oci-oidc-debug.log")
}

/** Call once at module load after CACHE_DIR is available. */
function initLogFile(): void {
  _logFile = getDefaultLogFile()
  // Write the log path to stderr immediately so it appears in OpenCode's
  // console output even before any config is found or any log entry is written.
  process.stderr.write(`[oci-auth] Log file: ${_logFile}\n`)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function initLogger(cfg: OciAuthConfig, client: any): void {
  _ocClient = client
  _logLevel = cfg.log_level
  const resolved = cfg.log_file
    ? cfg.log_file.replace(/^~/, homedir()).replace(/\//g, process.platform === "win32" ? "\\" : "/")
    : getDefaultLogFile()
  if (resolved !== _logFile) {
    _logFile = resolved
    process.stderr.write(`[oci-auth] Log file (from config): ${_logFile}\n`)
  }
}

// Map our log levels to OpenCode's expected level strings
const OC_LEVEL: Record<LogLevel, string> = {
  NONE: "info", ERROR: "error", WARN: "warn", INFO: "info", DEBUG: "debug", VERBOSE: "debug",
}

function writeLog(level: LogLevel, msg: string, data?: unknown): void {
  if (LOG_RANK[level] > LOG_RANK[_logLevel]) return
  const ts   = new Date().toISOString()
  const body = data !== undefined ? `${msg}: ${safeStr(data)}` : msg
  const line = `[${ts}] [${level}] [oci-auth] ${body}\n`

  // 1. File log — surface write errors via stderr so the user knows the custom path failed
  try {
    mkdirSync(dirname(_logFile), { recursive: true })
    writeFileSync(_logFile, line, { flag: "a" })
  } catch (fileErr) {
    try {
      process.stderr.write(`[oci-auth] WARNING: cannot write to log file "${_logFile}": ${String(fileErr)}\n`)
      process.stderr.write(`[oci-auth] Falling back to stderr only. Check the path and permissions.\n`)
    } catch { /* truly last resort */ }
  }

  // 2. stderr — always for ERROR/WARN, so they appear in the OpenCode console
  //    even before the client is available or if client.app.log fails.
  if (level === "ERROR" || level === "WARN") {
    try { process.stderr.write(line) } catch { /* ignore */ }
  }

  // 3. OpenCode built-in logger — forwards to the OpenCode console for all levels.
  //    Fire-and-forget; never await to avoid blocking the caller.
  if (_ocClient) {
    _ocClient.app.log({ body: { service: "oci-auth", level: OC_LEVEL[level], message: `[${level}] ${body}` } })
      .catch(() => { /* ignore — never crash on log delivery */ })
  }
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

// Read version from package.json at module load so it's always in sync with npm.
let PLUGIN_VERSION = "unknown" // loaded from package.json at runtime
try {
  const pkg = JSON.parse(readFileSync(join(pluginRoot, "package.json"), "utf8")) as { version?: string }
  PLUGIN_VERSION = pkg.version ?? "unknown"
} catch { /* non-fatal */ }

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
    // ── 3. System-wide config (read-only, requires admin/root) ───────────
    ...(process.platform === "darwin"
      ? [
          "/Library/Application Support/opencode/oci-auth.config.json",
          "/Library/Application Support/opencode/oci-auth.config.jsonc",
        ]
      : process.platform === "win32"
      ? [
          ...(process.env.ProgramData
            ? [
                join(process.env.ProgramData, "opencode", "oci-auth.config.json"),
                join(process.env.ProgramData, "opencode", "oci-auth.config.jsonc"),
              ]
            : []),
        ]
      : [
          "/etc/opencode/oci-auth.config.json",
          "/etc/opencode/oci-auth.config.jsonc",
        ]),
    // ── 4. opencode.json with oci_oidc / provider key ─────────────────────
    join(projectPath, "opencode.json"),
    join(projectPath, "opencode.jsonc"),
    join(homedir(), ".config", "opencode", "opencode.json"),
    join(homedir(), ".config", "opencode", "opencode.jsonc"),
    // ── 5. Plugin root (dev fallback — not present in production npm installs)
    join(pluginRoot,  "oci-auth.config.json"),
    join(pluginRoot,  "oci-auth.config.jsonc")
  ]

  const tried: string[] = []

  for (const p of candidates) {
    tried.push(p)
    writeLog("DEBUG", "Checking config candidate", p)
    try {
      const raw = readFileSync(p, "utf8")
      let parsed: Record<string, unknown>
      const stripped = stripJsonComments(raw)
      try {
        parsed = JSON.parse(stripped) as Record<string, unknown>
      } catch (parseErr) {
        // Find the approximate line number from the error message position.
        const posMatch = String(parseErr).match(/position\s+(\d+)|line\s+(\d+)/i)
        let lineHint = ""
        if (posMatch) {
          const pos = parseInt(posMatch[1] ?? posMatch[2] ?? "0", 10)
          const lines = stripped.split("\n")
          let cur = 0
          for (let i = 0; i < lines.length; i++) {
            cur += lines[i].length + 1
            if (cur >= pos) {
              lineHint = `\n  Near line ${i + 1}: ${lines[i].trim()}`
              break
            }
          }
        }
        writeLog("WARN",
          `Config file found at "${p}" but failed to parse as JSON.\n` +
          `  Error: ${String(parseErr)}${lineHint}\n` +
          `  Common causes:\n` +
          `    1. Windows path with single backslashes in "log_file" or other string values.\n` +
          `       Use forward slashes:  "C:/Users/you/oci-auth.log"\n` +
          `    2. Trailing comma after the last field (not valid in JSON).\n` +
          `    3. Unmatched quote or brace.`
        )
        // Log the stripped content at DEBUG so the user can see what we tried to parse.
        writeLog("DEBUG", `Stripped content of "${p}" that failed to parse`, stripped)
        continue
      }

      // Strategy 1: flat root-level config (merged format or legacy oci-oidc.jsonc)
      if (REQUIRED_AUTH_FIELDS.every(k => parsed[k])) {
        writeLog("DEBUG", "Config loaded (flat format)", p)
        _configPath = p
        return { ...BEHAVIOUR_DEFAULTS, ...(parsed as Partial<OciAuthConfig>) } as OciAuthConfig
      }

      // Strategy 2: "oci_oidc" top-level key
      const inner = parsed.oci_oidc
      if (inner && typeof inner === "object" &&
          REQUIRED_AUTH_FIELDS.every(k => (inner as Record<string, unknown>)[k])) {
        writeLog("DEBUG", "Config loaded (oci_oidc key)", p)
        _configPath = p
        return { ...BEHAVIOUR_DEFAULTS, ...(inner as Partial<OciAuthConfig>) } as OciAuthConfig
      }

      // Strategy 3: provider["oci-oidc"].options
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const provOpts = (parsed as any)?.provider?.["oci-oidc"]?.options
      if (provOpts && typeof provOpts === "object" &&
          REQUIRED_AUTH_FIELDS.every(k => (provOpts as Record<string, unknown>)[k])) {
        writeLog("DEBUG", "Config loaded (provider.oci-oidc.options)", p)
        _configPath = p
        return { ...BEHAVIOUR_DEFAULTS, ...(provOpts as Partial<OciAuthConfig>) } as OciAuthConfig
      }

      writeLog("DEBUG", "Config file found but missing required fields — skipping", {
        path: p, required: REQUIRED_AUTH_FIELDS.join(", ")
      })
    } catch (err) {
      writeLog("DEBUG", "Config candidate not found (file missing)", { path: p })
    }
  }

  // Always log the full search path at ERROR so the user can diagnose placement issues
  // without needing to change log_level (config isn't loaded yet at this point).
  writeLog("ERROR",
    "No valid OCI auth config found.\n" +
    "  Expected file names: oci-auth.config.jsonc  OR  oci-auth.config.json\n" +
    "  Searched paths (in priority order):\n" +
    tried.map(p => `    - ${p}`).join("\n") + "\n" +
    "  To fix: create oci-auth.config.jsonc in your project directory\n" +
    "          or at ~/.config/opencode/oci-auth.config.jsonc for a machine-wide default."
  )
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

// Initialise log file path now that CACHE_DIR is resolved.
initLogFile()

let _memCache: TokenCache | null = null

// Auth-flow mutex: if a browser/device flow is already in progress, all
// concurrent chat.params calls wait for it rather than opening more windows.
let _authInProgress: Promise<string> | null = null

// Refresh mutex: concurrent callers (chat.params, shell.env, session.error) share
// one refresh_token grant. OCI rotates refresh tokens, so a second parallel grant
// with the same (now consumed) refresh_token would be rejected and sign the user out.
let _refreshInProgress: Promise<string | null> | null = null

// The OAuth callback server currently owned by this process (if any).
// A new browser flow cancels it and takes over the port, so a stale server
// (e.g. from an abandoned authorize()) can never block a fresh login.
let _activeCallback: { port: number; cancel: (reason: string) => void } | null = null

// Prevent the startup banner from printing more than once per process even
// though OpenCode calls the plugin factory multiple times on startup.
let _startupDone = false

// LLM health check runs once after the first valid token is available.
// _pendingHealthCheck lets chat.params await it rather than racing ahead.
let _healthCheckDone = false
let _pendingHealthCheck: Promise<void> | null = null

// Path of the config file that was successfully loaded (set by loadConfig).
let _configPath = "(unknown)"

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
    // Atomic write (tmp + rename): another OpenCode process reading mid-write
    // would otherwise see truncated JSON, treat it as "no token" and start a login.
    const tmp = `${CACHE_PATH}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(cache), { encoding: "utf8", mode: 0o600 })
    renameSync(tmp, CACHE_PATH)
    log.debug("Token written to disk cache")
  } catch (err) {
    log.warn("Could not write disk cache (non-fatal)", safeStr(err))
  }
}

function storeToken(accessToken: string, expiresInSeconds: number, refreshToken?: string, marginSec = 60): string {
  const ttl   = Math.max(expiresInSeconds - marginSec, 60)
  const cache: TokenCache = { access_token: accessToken, expires_at: Date.now() + ttl * 1000 }
  // Keep the previous refresh_token if the server did not issue a new one,
  // otherwise the next expiry would force a full browser login.
  const prevRefresh = (_memCache ?? readDiskCache())?.refresh_token
  if (refreshToken ?? prevRefresh) cache.refresh_token = refreshToken ?? prevRefresh
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
function tryRefreshToken(cfg: OciAuthConfig): Promise<string | null> {
  if (!_refreshInProgress) {
    _refreshInProgress = doRefreshToken(cfg).finally(() => { _refreshInProgress = null })
  }
  return _refreshInProgress
}

async function doRefreshToken(cfg: OciAuthConfig, retried = false): Promise<string | null> {
  // Always read disk: another OpenCode process may have rotated the refresh_token.
  const cache = readDiskCache() ?? _memCache
  if (cache && Date.now() < cache.expires_at) { _memCache = cache; return cache.access_token }
  if (!cache?.refresh_token) {
    log.debug("tryRefreshToken: no refresh_token in cache")
    return null
  }
  const usedRefresh = cache.refresh_token
  log.info("tryRefreshToken: attempting silent token refresh")
  const url     = `${cfg.domain_url}/oauth2/v1/token`
  const body    = new URLSearchParams({
    grant_type:    "refresh_token",
    refresh_token: usedRefresh,
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
    // Another process may have refreshed (and rotated the refresh_token) while we
    // were in flight — if so, use its result instead of signing the user out.
    const latest = readDiskCache()
    if (latest?.refresh_token && latest.refresh_token !== usedRefresh) {
      log.info("tryRefreshToken: refresh_token was rotated by another process — using its token")
      if (isCacheValid(latest)) { _memCache = latest; return latest.access_token }
      if (!retried) return doRefreshToken(cfg, true)
    }

    // Only discard the refresh_token when OCI actually rejected it (400/401).
    // Network errors, timeouts and 5xx are transient — keep it for the next try.
    const status = err instanceof TokenEndpointError ? err.status : undefined
    if (status === 400 || status === 401) {
      log.warn("tryRefreshToken: refresh_token rejected — will fall back to full auth flow", safeStr(err))
      _memCache = null
      try { unlinkSync(CACHE_PATH) } catch { /* ok */ }
      return null
    }
    log.warn("tryRefreshToken: transient refresh failure — keeping refresh_token", safeStr(err))
    throw err instanceof Error ? err : new Error(String(err))
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

  // Mutex: if a full auth flow (browser/device) is already running, wait for it
  // instead of opening a second browser window / CMD window.
  if (_authInProgress) {
    log.info("Auth flow already in progress — waiting for it to complete")
    return _authInProgress
  }

  log.info("No valid cached token — triggering full auth flow", { method: cfg.auth_method })
  const inFlight: Promise<string> = fetchFreshToken(cfg).finally(() => {
    if (_authInProgress === inFlight) _authInProgress = null
  })
  _authInProgress = inFlight
  return inFlight
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
      // Don't reopen the browser after the user ignored/cancelled a login or
      // another process holds the callback port — only retry transient errors.
      const msg = err instanceof Error ? err.message : String(err)
      if (err instanceof PortBusyError || /Browser auth timed out|Login cancelled|OCI error:/.test(msg)) break
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

  // Bind the callback port BEFORE opening the browser. Any earlier flow in this
  // process is cancelled and its port taken over, so a stale server can never
  // leave us waiting on a login whose browser window never opened.
  let flow: { codePromise: Promise<string>; cleanup: () => void }
  try {
    flow = await startCallbackServer(internalUrl, listenPort, state, authUrl, cfg.browser_timeout_seconds)
  } catch (err) {
    if (!(err instanceof PortBusyError)) throw err
    // Another process (usually a second OpenCode window) is mid-login on this port.
    // It shares the disk token cache, so wait for it to finish instead of failing.
    log.warn(err.message)
    const deadline = Date.now() + cfg.browser_timeout_seconds * 1000
    while (Date.now() < deadline) {
      await sleep(2000)
      const cached = getCachedToken()
      if (cached) {
        log.info("fetchTokenBrowserFlow: token received from another process's login")
        return cached
      }
    }
    throw err
  }

  log.info("Opening browser for OCI auth", { listenPort, publicRedirectUri })
  log.warn(
    `If no browser window opened, open this URL to sign in:\n  ${authUrl}\n` +
    `  If the redirect can't reach this machine, run /connect and paste the redirect URL there.`
  )
  openBrowser(authUrl)

  const code = await flow.codePromise
  log.info("Authorization code received — exchanging for token")
  return exchangeCodeForToken(cfg, code, publicRedirectUri)
}

class PortBusyError extends Error {}

/**
 * Bind the OAuth callback server and return a promise for the auth code plus a
 * cleanup handle. Resolves once the port is listening; rejects with PortBusyError
 * if another process holds the port.
 */
async function startCallbackServer(
  callbackUrl: URL,
  port: number,
  expectedState: string,
  authUrl: string,
  timeoutSec: number,
  successMsg = "Authentication successful - you may close this window.",
): Promise<{ codePromise: Promise<string>; cleanup: () => void }> {
  if (_activeCallback?.port === port) {
    log.info("Cancelling previous OAuth callback server — starting a fresh login", { port })
    _activeCallback.cancel("superseded by a newer login attempt")
  }

  let resolveCode!: (code: string) => void
  let rejectCode!:  (err: Error)   => void
  const codePromise = new Promise<string>((res, rej) => { resolveCode = res; rejectCode = rej })
  // Callers may never await codePromise (e.g. a cancelled authorize() flow).
  codePromise.catch(() => { /* handled by awaiting callers */ })

  let timer: NodeJS.Timeout | undefined
  let settled = false
  let handle: NonNullable<typeof _activeCallback> | null = null
  const done = (fn: () => void) => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    if (_activeCallback === handle) _activeCallback = null   // port is free again
    server.close()
    server.closeAllConnections?.()
    fn()
  }

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
      // Likely a redirect from an older, superseded login tab — keep waiting
      // for the current one rather than failing the whole flow.
      htmlReply(res, 400, "This login link has expired. Please use the most recently opened login window.")
      log.warn("Callback with stale/unknown state ignored")
      return
    }
    const code = reqUrl.searchParams.get("code")
    if (!code) {
      htmlReply(res, 400, "Missing authorization code. Please retry.")
      done(() => rejectCode(new Error("[oci-auth] Callback missing code")))
      return
    }
    htmlReply(res, 200, successMsg)
    log.info("Browser auth callback received")
    done(() => resolveCode(code))
  })

  // The previous server's listening socket may take a moment to release.
  for (let attempt = 1; ; attempt++) {
    try {
      await new Promise<void>((res, rej) => {
        server.once("error", rej)
        server.listen(port, () => { server.off("error", rej); res() })
      })
      break
    } catch (err) {
      const errno = (err as NodeJS.ErrnoException).code
      if (errno === "EADDRINUSE" && attempt < 5) { await sleep(300); continue }
      if (errno === "EADDRINUSE") {
        throw new PortBusyError(
          `[oci-auth] OAuth callback port ${port} is in use by another process ` +
          `(another OpenCode window mid-login?). Finish or close that login, then retry.`
        )
      }
      throw new Error(`[oci-auth] Callback server: ${(err as Error).message}`)
    }
  }
  log.debug("Callback server listening", { port })

  server.on("error", (err: Error) => done(() => rejectCode(new Error(`[oci-auth] Callback server: ${err.message}`))))
  handle = { port, cancel: (reason: string) => done(() => rejectCode(new Error(`[oci-auth] Login cancelled: ${reason}`))) }
  _activeCallback = handle

  timer = setTimeout(() => done(() => rejectCode(new Error(
    `[oci-auth] Browser auth timed out after ${timeoutSec}s.\n` +
    `  Navigate manually to: ${authUrl}\n` +
    `  Then use the oci_oidc_refresh tool to retry.\n` +
    `  On a remote/headless machine, run /connect and paste the redirect URL there.`
  ))), timeoutSec * 1000)

  return { codePromise, cleanup: () => handle!.cancel("cleanup") }
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

/**
 * Interpret what the user pasted in the manual flow. Accepts:
 *   - the full redirect URL from the browser address bar (state is verified)
 *   - just the authorization code
 *   - an OCI access token (JWT) obtained elsewhere
 */
function parsePastedAuthInput(raw: string, expectedState: string): { code: string } | { accessToken: string } {
  const input = raw.trim().replace(/^["']|["']$/g, "")
  if (!input) throw new Error("[oci-auth] Nothing was pasted")

  if (/^https?:\/\//i.test(input) || input.includes("code=")) {
    const query  = /^https?:\/\//i.test(input) ? new URL(input).search : input.slice(input.indexOf("?") + 1)
    const params = new URLSearchParams(query)
    const error  = params.get("error")
    if (error) throw new Error(`[oci-auth] OCI error: ${params.get("error_description") ?? error}`)
    const code = params.get("code")
    if (!code) throw new Error("[oci-auth] Pasted URL has no code= parameter")
    const state = params.get("state")
    if (state && state !== expectedState) {
      throw new Error("[oci-auth] Pasted URL is from a different login attempt (state mismatch) — use the latest URL")
    }
    return { code }
  }
  if (/^eyJ[\w-]*\.[\w-]+\.[\w-]*$/.test(input)) return { accessToken: input }
  return { code: input }
}

/** Cache a pasted access token, using its JWT exp claim when present. No refresh_token. */
function storePastedAccessToken(token: string): string {
  let expiresIn = 3600
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as { exp?: number }
    if (payload.exp) expiresIn = payload.exp - Math.floor(Date.now() / 1000)
  } catch { /* not decodable — assume 1h */ }
  if (expiresIn <= 0) throw new Error("[oci-auth] Pasted access token is already expired")
  log.warn("Using pasted access token — it cannot be refreshed; you'll need to log in again when it expires")
  // Don't carry over an old refresh_token: it belongs to a different session.
  _memCache = null
  try { unlinkSync(CACHE_PATH) } catch { /* ok */ }
  return storeToken(token, expiresIn, undefined, 0)
}

function buildAuthUrl(cfg: OciAuthConfig, redirectUri: string, state: string): string {
  return `${cfg.domain_url}/oauth2/v1/authorize?${new URLSearchParams({
    client_id: cfg.client_id, response_type: "code",
    redirect_uri: redirectUri, scope: cfg.scope ?? "", state,
  })}`
}

function openBrowser(url: string): void {
  if (process.platform === "darwin") {
    exec(`open "${url}"`, err => { if (err) log.warn("Could not open browser", safeStr(err)) })
  } else if (process.platform === "win32") {
    // Use PowerShell Start-Process — opens the URL in the default browser
    // with no CMD window appearing. Escape single quotes in the URL.
    const escaped = url.replace(/'/g, "''")
    exec(
      `powershell -NoProfile -WindowStyle Hidden -Command "Start-Process '${escaped}'"`,
      err => { if (err) log.warn("Could not open browser via PowerShell", safeStr(err)) }
    )
  } else {
    exec(`xdg-open "${url}"`, err => { if (err) log.warn("Could not open browser", safeStr(err)) })
  }
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

class TokenEndpointError extends Error {
  constructor(readonly status: number, body: string) {
    super(`[oci-auth] Token request failed (${status}): ${body}`)
  }
}

async function postForToken(url: string, headers: Record<string, string>, body: URLSearchParams): Promise<string> {
  const grantType = body.get("grant_type") ?? "unknown"
  log.debug("postForToken: POST to token endpoint", { url, grant_type: grantType })
  const res  = await fetchWithTimeout(url, { method: "POST", headers, body: body.toString() })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    log.error("Token endpoint error", { status: res.status, grant_type: grantType, body: text })
    throw new TokenEndpointError(res.status, text)
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
  // Handles both full-line and inline // comments, and /* */ block comments.
  // Preserves // and /* inside string literals by matching quoted strings first.
  // Pattern: match a string literal (keep it) OR a comment (drop it).
  return raw
    .replace(
      /("(?:[^"\\]|\\.)*")|\/\/[^\r\n]*|\/\*[\s\S]*?\*\//g,
      (_, str) => str ?? ""   // keep string literals, drop comments
    )
    .trim()
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
  // Error properties are non-enumerable, so JSON.stringify(err) would give "{}".
  if (v instanceof Error) return v.message
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
// § 6b — Debug logging proxy
// When debug_proxy:true, starts a local HTTP reverse proxy on localhost:8890
// (port configurable via debug_proxy_port). OpenCode is redirected to this
// proxy via auth.loader returning baseURL=http://localhost:PORT. The proxy
// logs every request body and response body at INFO level, then forwards to
// the real LLM endpoint with the Bearer token injected.
//
// Additionally, if disable_thinking:true, the proxy injects
// "enable_thinking":false into every POST request body before forwarding,
// which disables chain-of-thought mode on vLLM/SGLang servers without
// requiring a server config change.
// ─────────────────────────────────────────────────────────────────────────────

let _proxyPort: number | null = null  // set once proxy is started

function startDebugProxy(cfg: OciAuthConfig, getTokenFn: () => string | null): number {
  const port       = cfg.debug_proxy_port ?? 8890
  // debug_proxy_target is the REAL backend. Defaults to llm_base_url.
  // Set this explicitly when you need llm_base_url and the proxy address to differ.
  const realTarget = (cfg.debug_proxy_target ?? cfg.llm_base_url).replace(/\/$/, "")

  // Self-loop guard: if the real target resolves to this proxy's own address,
  // every forwarded request would loop back and append the path repeatedly
  // (e.g. /api → /api/api → /api/api/api…). Fail loudly instead.
  const selfOrigins = [
    `http://127.0.0.1:${port}`,
    `http://localhost:${port}`,
    `http://0.0.0.0:${port}`,
  ]
  if (selfOrigins.some(o => realTarget.startsWith(o))) {
    const msg =
      `[oci-auth] debug_proxy self-loop detected!\n` +
      `  The proxy would forward to itself (target="${realTarget}", proxy port=${port}).\n` +
      `  Fix: set "llm_base_url" to the REAL backend (e.g. "https://10.x.x.x/api").\n` +
      `  If you want OpenCode to connect through the proxy, change "baseURL" in opencode.json\n` +
      `  to "http://127.0.0.1:${port}" — NOT llm_base_url in oci-auth.config.jsonc.\n` +
      `  Alternatively, set "debug_proxy_target" to the real backend URL in oci-auth.config.jsonc.`
    writeLog("ERROR", msg)
    throw new Error(msg)
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    writeLog("INFO", `Proxy: request received — ${req.method} ${req.url}`)
    handleProxyRequest(cfg, realTarget, getTokenFn, req, res).catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      writeLog("WARN", `Proxy: handler error — ${msg}`)
      if (!res.headersSent) res.writeHead(502)
      res.end(`Proxy error: ${msg}`)
    })
  })

  server.on("connection", (sock) => {
    writeLog("DEBUG", `Proxy: TCP connection from ${sock.remoteAddress ?? "?"}:${sock.remotePort ?? "?"}`)
  })

  server.on("error", (err) => {
    writeLog("ERROR", `Proxy: server error — ${err.message}`)
  })

  server.listen(port, "127.0.0.1", () => {
    writeLog("INFO", `Proxy: listening on http://127.0.0.1:${port} → ${realTarget}`)
  })

  return port
}

async function handleProxyRequest(
  cfg: OciAuthConfig,
  baseTarget: string,
  getTokenFn: () => string | null,
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
    // Collect request body
    const chunks: Buffer[] = []
    await new Promise<void>(resolve => {
      req.on("data", (c: Buffer) => chunks.push(c))
      req.on("end", () => resolve())
    })

    let bodyBuf = Buffer.concat(chunks)
    let bodyStr = bodyBuf.toString("utf8")

    log.info("Proxy →", {
      method: req.method,
      path:   req.url,
      body:   bodyStr.length > 4000 ? bodyStr.slice(0, 4000) + "…" : bodyStr,
    })

    // Optionally inject enable_thinking:false
    if (cfg.disable_thinking && req.method === "POST" && bodyStr.trim().startsWith("{")) {
      try {
        const parsed = JSON.parse(bodyStr) as Record<string, unknown>
        if (!("enable_thinking" in parsed)) {
          parsed["enable_thinking"] = false
          bodyStr = JSON.stringify(parsed)
          bodyBuf = Buffer.from(bodyStr, "utf8")
          log.debug("Proxy: injected enable_thinking:false")
        }
      } catch { /* non-JSON body — leave as-is */ }
    }

    const token = getTokenFn()
    const targetUrl = baseTarget + (req.url ?? "")

    try {
      const hasBody = bodyBuf.length > 0 && req.method !== "GET" && req.method !== "HEAD"
      const upstream = await fetch(targetUrl, {
        method:  req.method ?? "GET",
        headers: {
          "content-type":  req.headers["content-type"] ?? "application/json",
          "accept":        req.headers["accept"] ?? "*/*",
          "authorization": token ? `Bearer ${token}` : (req.headers["authorization"] ?? ""),
          ...(hasBody ? { "content-length": String(bodyBuf.length) } : {}),
        },
        body:    hasBody ? bodyBuf : undefined,
        duplex:  hasBody ? "half" : undefined,
      })

      // Forward response headers, skip content-encoding to avoid double-decode
      const fwdHeaders: Record<string, string> = {}
      upstream.headers.forEach((v, k) => {
        if (k !== "content-encoding") fwdHeaders[k] = v
      })
      res.writeHead(upstream.status, fwdHeaders)

      // Stream response back to OpenCode and capture for logging
      const respChunks: Buffer[] = []
      if (upstream.body) {
        const reader = upstream.body.getReader()
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          const chunk = Buffer.from(value)
          respChunks.push(chunk)
          res.write(chunk)
        }
      }
      res.end()

      const respStr = Buffer.concat(respChunks).toString("utf8")
      log.info("Proxy ←", {
        status: upstream.status,
        body:   respStr.length > 4000 ? respStr.slice(0, 4000) + "…" : respStr,
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      log.warn("Proxy: upstream error", msg)
      if (!res.headersSent) res.writeHead(502)
      res.end(`Proxy upstream error: ${msg}`)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6c — LLM endpoint health check
// Always GETs /models to verify reachability and auth, then POSTs a 1-token
// completion with the configured model (or the first discovered model).
// If no model is configured, prints ready-to-run curl commands so the user
// can copy a model ID into their config.
// ─────────────────────────────────────────────────────────────────────────────
type PluginClient = Parameters<Plugin>[0]["client"]

async function runHealthCheck(cfg: OciAuthConfig, token: string, client: PluginClient): Promise<void> {
  const modelsUrl = `${cfg.llm_base_url}/models`
  let firstModelId: string | null = null

  // Step 1 — GET /models
  try {
    log.debug("Health check: GET /models", { url: modelsUrl })
    const res = await fetch(modelsUrl, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10_000),
    })
    if (res.ok) {
      const data: unknown = await res.json().catch(() => null)
      const models = (data && typeof data === "object" && "data" in data && Array.isArray((data as { data: unknown }).data))
        ? (data as { data: { id: string }[] }).data : null
      firstModelId = models?.[0]?.id ?? null
      const ids = models ? models.map(m => m.id).join(", ") : "(could not parse)"
      log.info("Health check: /models OK", { status: res.status, available_models: ids })
      await client.app.log({ body: { service: "oci-auth", level: "info",
        message: `LLM endpoint OK — available models: ${ids}` } }).catch(() => {})
    } else {
      const body = await res.text().catch(() => "")
      log.warn("Health check: /models error", { status: res.status, body: body.slice(0, 400) })
      await client.app.log({ body: { service: "oci-auth", level: "error",
        message: `LLM /models HTTP ${res.status} — ${body.slice(0, 300) || "no body"}` } }).catch(() => {})
      return
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    log.warn("Health check: LLM endpoint unreachable", { error: msg, url: modelsUrl })
    await client.app.log({ body: { service: "oci-auth", level: "error",
      message: `LLM endpoint unreachable: ${msg}` } }).catch(() => {})
    return
  }

  // Step 2 — POST /chat/completions to verify a specific model
  const modelToProbe = cfg.model ?? firstModelId
  if (!modelToProbe) {
    log.warn("Health check: no models returned by /models — cannot probe chat/completions")
    return
  }

  // Step 2 — streaming probe: matches how OpenCode actually calls the model.
  // Reads SSE chunks and checks whether any chunk delivers non-empty delta.content.
  // A 200 response with only empty deltas (thinking/reasoning mode) is reported
  // as a WARNING so the problem surfaces before the user sends their first message.
  const completionsUrl = `${cfg.llm_base_url}/chat/completions`
  try {
    log.debug("Health check: POST /chat/completions (stream:true)", { url: completionsUrl, model: modelToProbe })
    const res = await fetch(completionsUrl, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model:      modelToProbe,
        messages:   [{ role: "user", content: "Say one word." }],
        max_tokens: 10,
        stream:     true,
      }),
      signal: AbortSignal.timeout(20_000),
    })

    if (!res.ok) {
      const body = await res.text().catch(() => "")
      log.warn("Health check: model probe failed", { status: res.status, model: modelToProbe, body: body.slice(0, 400) })
      await client.app.log({ body: { service: "oci-auth", level: "error",
        message: `Model "${modelToProbe}" rejected HTTP ${res.status} — ${body.slice(0, 200) || "no body"}` } }).catch(() => {})
      return
    }

    // Read SSE stream and check for non-empty delta.content in any chunk
    let gotContent = false
    const rawChunks: string[] = []
    if (res.body) {
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        const text = decoder.decode(value, { stream: true })
        rawChunks.push(text)
        // Parse SSE lines: "data: {...}"
        for (const line of text.split("\n")) {
          const trimmed = line.trim()
          if (!trimmed.startsWith("data:")) continue
          const jsonStr = trimmed.slice(5).trim()
          if (jsonStr === "[DONE]") continue
          try {
            const chunk = JSON.parse(jsonStr) as {
              choices?: Array<{ delta?: { content?: string; reasoning_content?: string } }>
            }
            const content = chunk.choices?.[0]?.delta?.content
            if (content && content.length > 0) { gotContent = true; break }
          } catch { /* skip unparseable chunk */ }
        }
        if (gotContent) { reader.cancel().catch(() => {}); break }
      }
    }

    const rawSample = rawChunks.join("").slice(0, 600)
    if (gotContent) {
      log.info("Health check: streaming model probe OK — content received", { model: modelToProbe })
      await client.app.log({ body: { service: "oci-auth", level: "info",
        message: `Model "${modelToProbe}" OK — streaming content received` } }).catch(() => {})
    } else {
      log.warn(
        "Health check: model returned HTTP 200 but delta.content was empty in all chunks.\n" +
        "  The model is outputting to a non-standard field (e.g. delta.reasoning_content)\n" +
        "  instead of delta.content. This is expected for reasoning/thinking models.\n" +
        "  OpenCode reads delta.content — if the model never populates it, responses will appear blank.\n" +
        "  If this is unintentional, check whether reasoning/thinking mode is enabled on the LLM server.\n" +
        `  Raw stream sample: ${rawSample}`
      )
      await client.app.log({ body: { service: "oci-auth", level: "warn",
        message: `Model "${modelToProbe}" WARNING: streaming response has empty delta.content — model may be a reasoning/thinking model. Responses will appear blank if delta.content is never populated.` } }).catch(() => {})
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    log.warn("Health check: model probe error", { error: msg, model: modelToProbe })
  }

  // Step 3 — if model was not configured, print curl commands and suggest adding it
  if (!cfg.model && modelToProbe) {
    const body = JSON.stringify({
      model: modelToProbe,
      messages: [{ role: "user", content: "ping" }],
      max_tokens: 5,
    })
    const winBody = body.replace(/"/g, '\\"')
    log.info(
      `Health check: 'model' not set in config — using first discovered model "${modelToProbe}" for probe.\n` +
      `  To enable per-model health checks and avoid this message, add to your config:\n` +
      `    File : ${_configPath}\n` +
      `    Add  : "model": "${modelToProbe}"\n\n` +
      `  To test the model directly from the command line:\n` +
      `  Linux/macOS:\n` +
      `    curl -sk -H "Authorization: Bearer ${token}" \\\n` +
      `         -H "Content-Type: application/json" \\\n` +
      `         -d '${body}' \\\n` +
      `         ${completionsUrl}\n\n` +
      `  Windows:\n` +
      `    curl.exe -sk -H "Authorization: Bearer ${token}" ^\n` +
      `             -H "Content-Type: application/json" ^\n` +
      `             -d "${winBody}" ^\n` +
      `             ${completionsUrl}`
    )
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 7 — Plugin export
// ─────────────────────────────────────────────────────────────────────────────

export const OciOidcPlugin: Plugin = async ({ project, client }) => {

  // project.worktree can be empty on Windows — fall back to process.cwd()
  const projectPath = project.worktree || process.cwd()

  // OpenCode calls the plugin factory multiple times on startup — only print
  // the banner and run one-time init on the first call.
  if (!_startupDone) {
    _startupDone = true
    const startupMsg =
      `Starting v${PLUGIN_VERSION}\n` +
      `  plugin dir  : ${pluginRoot}\n` +
      `  log file    : ${_logFile}\n` +
      `  project dir : ${projectPath}\n` +
      `  platform    : ${process.platform}\n` +
      `  node        : ${process.version}\n` +
      `  home        : ${homedir()}\n` +
      `  NODE_TLS_REJECT_UNAUTHORIZED : ${process.env.NODE_TLS_REJECT_UNAUTHORIZED ?? "(not set)"}`
    writeLog("INFO", startupMsg)
    // _ocClient is not set yet (initLogger runs after config loads), so writeLog
    // above only reaches the disk file. Forward explicitly to the OpenCode console
    // at WARN so it is visible at OpenCode's default log level, not only with DEBUG.
    await client.app.log({ body: { service: "oci-auth", level: "warn", message: startupMsg } }).catch(() => {})
  }

  const cfg = loadConfig(projectPath)
  if (!cfg) {
    writeLog("ERROR", "Plugin inactive — no valid OCI auth config found (see above for searched paths).")
    await client.app.log({ body: { service: "oci-auth", level: "error", message: "No OCI auth config found — plugin inactive. Check the log for the full list of searched paths." } })
    return {}
  }

  initLogger(cfg, client)
  _memCache = null
  const maskStr = (k: string) =>
        !k || k.trim() === "" ? "(none)" : k.length <= 16 ? k : `${k.slice(0, 8)}…${k.slice(-8)}`

  // Start debug proxy on first init only (it binds a port — can't rebind)
  if (cfg.debug_proxy && _proxyPort === null) {
    _proxyPort = startDebugProxy(cfg, getCachedToken)
  }

  log.info(`Plugin initialised v${PLUGIN_VERSION}`, {
    version: PLUGIN_VERSION,
    auth_method: cfg.auth_method, log_level: cfg.log_level,
    log_file: _logFile, domain: cfg.domain_url,
    llm_base_url: cfg.llm_base_url,
    ...(cfg.debug_proxy ? { debug_proxy: `http://127.0.0.1:${_proxyPort}` } : {}),
    cache_path: CACHE_PATH,
    client_id: maskStr(cfg.client_id)
  })

  // WARN so the loaded version and settings show at OpenCode's default log level.
  await client.app.log({ body: { service: "oci-auth", level: "warn",
    message: `OCI auth plugin ready v${PLUGIN_VERSION} | method: ${cfg.auth_method} | llm_base_url: ${cfg.llm_base_url} | ` +
             `domain: ${cfg.domain_url} | client_id: ${maskStr(cfg.client_id)} | log_level: ${cfg.log_level} | ` +
             `log_file: ${_logFile} | config: ${_configPath} | token cache: ${CACHE_PATH}` } })

  // Warm memory cache from disk. If auth_on_startup is true, also fetch fresh.
  const disk = readDiskCache()
  if (isCacheValid(disk)) {
    _memCache = disk
    log.info("Valid cached token loaded from disk — no auth needed at startup")
    // Token is available immediately — kick off health check now so results
    // are ready before the user sends their first message.
    if (!_healthCheckDone) {
      _healthCheckDone = true
      _pendingHealthCheck = runHealthCheck(cfg, disk.access_token, client)
        .finally(() => { _pendingHealthCheck = null })
    }
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
        // Cached token or silent refresh only — opening a terminal or running a
        // shell command must never pop up a browser login.
        const token = getCachedToken() ?? await tryRefreshToken(cfg)
        if (!token) {
          log.debug("shell.env: no token available — skipping (login triggers on the next LLM request)")
          return
        }
        output.env.OCI_BEARER_TOKEN = token
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

        // The endpoint URL (baseURL) comes from opencode.json provider options — the user
        // controls it there and can point it at the proxy or the real backend as needed.
        // We deliberately do NOT return baseURL here: returning it would silently override
        // whatever is in opencode.json, making that setting unreliable.
        // We only return the credential (apiKey) and identity fields.
        const baseFields = {
          instanceUrl: cfg.domain_url,
          clientId:    cfg.client_id,
        }

        if (cached) {
          log.info("Auth loader: returning cached token", { tail: cached.slice(-8) })
          return { apiKey: cached, ...baseFields }
        }

        log.info("Auth loader: no cached token — returning identity fields only")
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

            // Browser flow (confidential_app) — like Claude Code's login: we open the
            // browser AND accept a pasted redirect URL, so login still works when the
            // browser can't open or the localhost redirect can't reach this machine.
            // OpenCode's "code" dialog requires input, so after an automatic redirect
            // the user just types "ok".
            const internalUri     = cfg.redirect_uri ?? "http://localhost:8888/callback"
            const internalUrl     = new URL(internalUri)
            const listenPort      = Number(internalUrl.port) || 8888
            const publicRedirectUri = cfg.browser_redirect_uri ?? internalUri
            const state           = randomState()
            const authUrl         = buildAuthUrl(cfg, publicRedirectUri, state)

            // The local callback server is best-effort: if the port is unavailable
            // the user can still finish by pasting the redirect URL.
            let local: { codePromise: Promise<string>; cleanup: () => void } | null = null
            try {
              local = await startCallbackServer(
                internalUrl, listenPort, state, authUrl, cfg.browser_timeout_seconds,
                "Authentication successful - return to OpenCode, type ok and press Enter.",
              )
            } catch (err) {
              log.warn("authorize(): local callback server unavailable — paste flow only", safeStr(err))
            }

            // localToken: resolves when the redirect hits our server and the code is
            // exchanged. Stored in _authInProgress so chat.params waits on this flow
            // instead of opening a second browser window.
            let localGotCode = false
            let localToken: Promise<string> | null = null
            if (local) {
              localToken = local.codePromise.then(code => {
                localGotCode = true
                log.debug("authorize(): auth code received — exchanging for token")
                return exchangeCodeForToken(cfg, code, publicRedirectUri)
              })
              const inFlight: Promise<string> = localToken.finally(() => {
                if (_authInProgress === inFlight) _authInProgress = null
              })
              inFlight.catch(() => { /* surfaced via callback() / getToken() */ })
              _authInProgress = inFlight
            }

            log.info("authorize(): opening browser, paste fallback enabled", { authUrl })
            openBrowser(authUrl)

            return {
              method:       "code" as const,
              url:          authUrl,
              instructions:
                "A browser window should open for OCI sign-in. When it shows \"Authentication successful\", " +
                "type ok and press Enter. If no browser opened, open the link below. If the page after " +
                "sign-in fails to load, copy the full URL from its address bar and paste it here.",
              async callback(input: string) {
                try {
                  const trimmed = input.trim()
                  const isPaste = /^https?:\/\//i.test(trimmed) || trimmed.includes("code=") || trimmed.length >= 16
                  let token: string | null = null

                  if (localToken && (localGotCode || !isPaste)) {
                    // The redirect reached us (or the user typed "ok") — use the local
                    // result; a pasted copy of the same code would fail as already used.
                    token = await Promise.race([localToken.catch(() => null), sleep(10_000).then(() => null)])
                    token ??= getCachedToken()
                    if (!token && !isPaste) throw new Error("Sign-in not completed yet — finish in the browser, or paste the redirect URL")
                  }

                  if (!token) {
                    local?.cleanup()
                    const pasted = parsePastedAuthInput(trimmed, state)
                    token = "accessToken" in pasted
                      ? storePastedAccessToken(pasted.accessToken)
                      : await exchangeCodeForToken(cfg, pasted.code, publicRedirectUri)
                  }

                  log.info("authorize.callback() browser flow completed successfully")
                  return { type: "success" as const, provider: "oci-oidc",
                           key: "apiKey", metadata: { apiKey: token } }
                } catch (err) {
                  // "failed" lets OpenCode show "Invalid code" and the user can retry
                  // (e.g. paste the URL) in the same dialog.
                  log.error("[oci-auth] authorize().callback() browser flow failed", safeStr(err))
                  return { type: "failed" as const }
                }
              },
            }
          },
        },
        {
          // Paste-only fallback: no local callback server, no browser launch.
          // Kept separate so login remains possible if the combined flow above
          // misbehaves (port conflicts, browser launch issues, OpenCode UI changes).
          type:    "oauth" as const,
          label:   "OCI OIDC — copy URL & paste code (remote / no browser)",
          prompts: [],

          async authorize() {
            const internalUri       = cfg.redirect_uri ?? "http://localhost:8888/callback"
            const publicRedirectUri = cfg.browser_redirect_uri ?? internalUri
            const state             = randomState()
            const authUrl           = buildAuthUrl(cfg, publicRedirectUri, state)
            log.info("authorize(): manual paste flow — returning OCI auth URL", { authUrl })

            return {
              method:       "code" as const,
              url:          authUrl,
              instructions:
                "Open the link below in any browser and sign in. You'll be redirected to " +
                `${publicRedirectUri}?code=… (the page may fail to load — that's fine). ` +
                "Copy the full URL from the address bar (or just the code) and paste it here.",
              async callback(input: string) {
                try {
                  const pasted = parsePastedAuthInput(input, state)
                  const token = "accessToken" in pasted
                    ? storePastedAccessToken(pasted.accessToken)
                    : await exchangeCodeForToken(cfg, pasted.code, publicRedirectUri)
                  log.info("authorize().callback() manual paste flow completed successfully")
                  return { type: "success" as const, provider: "oci-oidc",
                           key: "apiKey", metadata: { apiKey: token } }
                } catch (err) {
                  log.error("[oci-auth] manual paste flow failed", safeStr(err))
                  return { type: "failed" as const }
                }
              },
            }
          },
        },
      ],
    },

    // ── Events ───────────────────────────────────────────────────────────────
    event: async ({ event }: { event: { type: string } }) => {
      // At VERBOSE level, dump full payload for message events so we can see
      // exactly what content OpenCode is receiving from the LLM endpoint.
      const verboseTypes = new Set(["message.part.updated", "message.updated", "message.part.added", "session.status"])
      if (verboseTypes.has(event.type)) {
        log.verbose(`Event: ${event.type}`, safeStr(event))
      } else {
        log.debug("Event received", event.type)
      }

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

        // Keep this narrow: a bare "token" match also hits context-length errors
        // ("maximum context length is N tokens"), and our own "[oci-auth]" errors
        // must not loop back into another refresh.
        const isAuthError =
          !errMsg.includes("[oci-auth") && (
            statusCode === 401 ||
            errMsg.includes("unauthorized") ||
            /invalid[_ ]token|token (has )?expired|expired token|authentication (error|failed)/.test(errMsg)
          )

        if (isAuthError) {
          log.warn(
            `session.error: auth/token error detected (status=${statusCode ?? "?"}, msg="${errMsg}") — ` +
            "attempting silent refresh_token refresh (no browser will open)"
          )
          // Expire the access token in memory but keep the refresh_token on disk.
          // tryRefreshToken() reads the disk cache to find the refresh_token.
          // Expire it on disk too, otherwise the refresh would just reload the
          // rejected token from the disk cache.
          const current = _memCache ?? readDiskCache()
          if (current) {
            _memCache = { ...current, access_token: "", expires_at: 0 }
            writeDiskCache(_memCache)
          }

          // IMPORTANT: only try SILENT refresh here — never open a browser from an
          // event handler.  If tryRefreshToken() fails (no refresh_token, or OCI
          // rejects it), we log clearly and ask the user to /connect manually.
          tryRefreshToken(cfg).then(token => {
            if (token) {
              log.info("session.error: silent token refresh succeeded", { tail: token.slice(-8) })
            } else {
              log.warn(
                "session.error: no refresh_token available — user must re-authenticate (send any message to trigger auth)"
              )
            }
          }).catch(err => {
            log.error(
              "session.error: silent refresh failed — user must re-authenticate (send any message to trigger auth)",
              String(err)
            )
          })

          await client.app.log({ body: { service: "oci-auth", level: "warn",
            message: "OCI token expired or rejected — refreshing automatically. If the next message also fails, send it again to re-authenticate." }
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

        // An in-flight login is deliberately kept across sessions: every browser
        // and device flow now settles on its own timeout, and clearing it here
        // made the next request open a second browser window.

        const cached = getCachedToken()
        const disk    = _memCache ?? readDiskCache()
        if (cached) {
          const expiresInMin = Math.round(((_memCache ?? disk)!.expires_at - Date.now()) / 60000)
          log.info(`session.created: valid cached token — expires in ~${expiresInMin} min`, {
            has_refresh: !!(disk?.refresh_token),
          })
          await client.app.log({ body: { service: "oci-auth", level: "info",
            message: `OCI token ready — expires in ~${expiresInMin} min` } }).catch(() => {})
        } else if (disk?.refresh_token) {
          log.info("session.created: access token expired but refresh_token available — will refresh silently on first message")
          await client.app.log({ body: { service: "oci-auth", level: "info",
            message: "OCI access token expired — will refresh silently on first message" } }).catch(() => {})
        } else {
          log.info("session.created: no cached token — auth will trigger on first message")
          await client.app.log({ body: { service: "oci-auth", level: "info",
            message: `OCI auth pending (method: ${cfg.auth_method}) — browser will open on first message` }
          }).catch(() => {})
        }

        // Health check runs at plugin init if a token was already cached.
        // If there was no token at init (auth just completed), start it now.
        if (!_healthCheckDone) {
          const token = getCachedToken()
          if (token) {
            _healthCheckDone = true
            _pendingHealthCheck = runHealthCheck(cfg, token, client)
              .finally(() => { _pendingHealthCheck = null })
          }
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
    // Triggers auth inline when no token is cached. The mutex in getToken()
    // ensures only one browser/device flow runs at a time regardless of how
    // many concurrent requests arrive.
    // ─────────────────────────────────────────────────────────────────────────
    "chat.params": async (_input: unknown, _output: unknown) => {
      // If a health check is in flight (started at init), wait for it so its
      // results appear before the first request rather than racing ahead of it.
      if (_pendingHealthCheck) {
        log.debug("chat.params: awaiting health check")
        await Promise.race([_pendingHealthCheck, new Promise<void>(r => setTimeout(r, 8_000))])
      }

      // Note: _output here contains only model params (temperature, topP, maxOutputTokens, options).
      // Messages are NOT available in this hook — stripping is done in the proxy instead.

      const cached = getCachedToken()
      if (cached) {
        log.debug("chat.params: token in cache — request allowed (chat.headers will inject Bearer)")
        return
      }

      log.info("chat.params: no token — triggering auth flow", { method: cfg.auth_method })
      try {
        await getToken(cfg)
        log.info("chat.params: auth completed — request will proceed")
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err)
        log.error("chat.params: auth failed — blocking request", errMsg)
        throw new Error(`[oci-auth] Authentication failed: ${errMsg}`)
      }
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
