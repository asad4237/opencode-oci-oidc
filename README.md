# opencode-oci-oidc

An [OpenCode](https://opencode.ai) plugin that authenticates with **Oracle Cloud Infrastructure (OCI) IAM** and injects a Bearer token into every request sent to an OpenAI-compatible LLM endpoint running on OCI.

Two auth methods are supported:

| Method | Status | Description |
|--------|--------|-------------|
| `confidential_app` | Tested | Browser-based OAuth 2.0 Authorization Code flow with a client secret |
| `mobile_app` | Not tested | OCI Device Authorization Grant (RFC 8628) — no browser, no secret; approve on the OCI Mobile Authenticator app |

Tokens are cached in memory and on disk and refreshed automatically using the refresh token when they expire. If the refresh token is also expired, the plugin prompts for re-authentication.

---

## Installation

```bash
npm install opencode-oci-oidc
```

Then add the plugin to your `opencode.json`:

```jsonc
{
  "plugin": ["opencode-oci-oidc"]
}
```

---

## Configuration

Copy `oci-auth.config.example.jsonc` (included in the package) to one of these locations and fill in your values:

| Location | Scope |
|----------|-------|
| `<your-project>/oci-auth.config.jsonc` | Per-project (takes priority) |
| `~/.config/opencode/oci-auth.config.jsonc` | Machine-wide default |

```jsonc
{
  // ── OCI IAM credentials ─────────────────────────────────────────────
  "domain_url":  "https://idcs-<your-idcs-id>.identity.oraclecloud.com",
  "client_id":   "<your-client-id>",

  // Confidential app: provide client_secret as a plain string or file reference
  // Mobile app: omit client_secret entirely
  "client_secret": "<your-client-secret>",
  // Or reference a file to keep the secret out of this file:
  // "client_secret": "{file:~/.secrets/oci-client-secret}",

  "redirect_uri": "http://localhost:8888/callback",
  "scope": "openid profile",

  // Base URL of the OpenAI-compatible LLM endpoint (no trailing slash)
  "llm_base_url": "https://<your-oci-gpu-endpoint>/v1",

  // ── Plugin behaviour ─────────────────────────────────────────────────
  "auth_method": "confidential_app",   // or "mobile_app"
  "log_level":   "INFO"                // NONE | ERROR | WARN | INFO | DEBUG | VERBOSE
}
```

> **Client secret options**
> You can provide the secret as a plain string directly in the config, or use `"{file:~/.secrets/oci-client-secret}"` to read it from a separate file (useful if this config file is inside a version-controlled project). The plugin blocks the AI agent from reading files under `~/.secrets/`.

---

## Provider and model setup

Model IDs, context sizes, and the provider endpoint are managed in `opencode.json` alongside your other providers — not in the plugin config:

```jsonc
// opencode.json
{
  "plugin": ["opencode-oci-oidc"],

  "provider": {
    "oci-oidc": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OCI GPU",
      "options": {
        "baseURL": "https://<your-oci-gpu-endpoint>/v1"
      },
      "models": {
        "llama-3-1-70b": {
          "id": "meta-llama/Llama-3.1-70B-Instruct",
          "name": "Llama 3.1 70B (OCI)",
          "limit": { "context": 131072, "output": 8192 }
        }
      }
    }
  },

  "model": "oci-oidc/llama-3-1-70b"
}
```

The plugin automatically injects the `Authorization: Bearer <token>` header into every request sent to the `oci-oidc` provider.

---

## Auth flows

### Confidential App (browser)

1. Run `/connect` in OpenCode. A browser window opens to the OCI login page, and OpenCode shows the login link with an input box
2. Sign in. Then either:
   - **The browser shows "Authentication successful"**: type `ok` in OpenCode and press Enter
   - **No browser opened, or the page after sign-in fails to load** (SSH session, bastion host, container): open the link yourself, sign in, copy the **full URL** of the `localhost:8888/callback?code=…` page from the address bar, and paste it into OpenCode
3. The plugin exchanges the code for a token, caches it with the refresh token, and subsequent requests are automatic

A pasted URL must come from the current login attempt (its `state` is checked). You can also paste just the `code` value. Or you can paste an OCI access token (JWT) you obtained elsewhere; it's used until its `exp`, but it can't be refreshed.

### Mobile App (device flow)

1. Run `/connect` in OpenCode — a short code is printed to the terminal
2. Open the OCI Mobile Authenticator app and enter the code
3. The plugin polls for approval and caches the token when granted

---

## Tools available to the AI agent

| Tool | Description |
|------|-------------|
| `oci_oidc_refresh` | Force-refresh the Bearer token (useful after a 401) |
| `oci_oidc_status` | Show current token validity, expiry, endpoint, and auth method |

---

## OCI application setup

### Confidential App

1. OCI Console → **Identity & Security → Domains → \<your domain\>**
2. **Integrated Applications → Add Application → Confidential Application**
3. Under **Configure this application as a client**:
   - Grant types: ✅ **Authorization Code**, ✅ **Refresh Token**
   - Redirect URL: `http://localhost:8888/callback`
   - Scopes: `openid profile` (and any resource scopes your LLM endpoint requires)
4. Click **Finish → Activate**
5. Copy **Client ID** and **Client Secret**

### Mobile App (Device Authorization Grant) [not tested, may nto work]

Same steps as above but:
- Grant types: ✅ **Device Code**, ✅ **Refresh Token**
- No client secret needed

---

## Logs

The plugin writes a log file from the moment it loads — even before your config is read. This makes it the primary tool for diagnosing any issue.

**Default log file location:**

| Platform | Path |
|----------|------|
| Linux / macOS | `~/oci-oidc-debug.log` |
| Windows | `%LOCALAPPDATA%\opencode-oci-oidc\plugin.log` |

**To follow logs in real time:**
```bash
tail -f ~/oci-oidc-debug.log
```

**To enable detailed logging**, add these two lines to your `oci-auth.config.jsonc`:
```jsonc
"log_level": "DEBUG",
"log_file": "~/oci-oidc-debug.log"
```

On Windows, use forward slashes or double backslashes for the path — single backslashes are invalid in JSON and will prevent the config from loading:
```jsonc
"log_file": "C:/Users/you/oci-auth.log"      // recommended
"log_file": "C:\\Users\\you\\oci-auth.log"   // also valid
```

Available log levels (most to least verbose): `VERBOSE` → `DEBUG` → `INFO` → `WARN` → `ERROR` → `NONE`

> The log file is written to the **default path** even if your config fails to load. Check the default location first — the `[WARN]` entry will show exactly what went wrong and which paths were searched.

---

## Troubleshooting

### `"undefined/chat/completions" cannot be parsed as a URL`

The plugin could not find or read your `oci-auth.config.jsonc`. Steps to diagnose:

1. Open `~/oci-oidc-debug.log` — look for a `[WARN]` entry listing the paths that were searched
2. Make sure your config file is named exactly `oci-auth.config.jsonc` (not `.json`, not `oci-oidc.jsonc`)
3. Place it in one of these locations:
   - **Per-project:** same directory as `opencode.json` / `opencode.jsonc`
   - **Machine-wide:** `~/.config/opencode/oci-auth.config.jsonc`
4. Verify the file contains at least `domain_url`, `client_id`, and `llm_base_url` with real values (not `<placeholders>`)
5. Validate the JSON is valid — JSONC comments (`// ...`) are supported but trailing commas are not

### Other issues

| Symptom | Fix |
|---------|-----|
| Browser doesn't open on `/connect` | Check `redirect_uri` matches what is registered in your OCI Confidential App, or open the link shown in `/connect` yourself and paste the redirect URL back |
| Token rejected (401) after previously working | Run `oci_oidc_refresh` tool or `/connect` again |
| Plugin keeps retrying auth silently | Check the log for `session.error` entries — likely a new/changed client secret |
| Hanging after sending a message | Check log for `Network timeout` — indicates OCI IAM or the LLM endpoint is unreachable |
| No refresh token (`has_refresh_token: false` in log) | Add `offline_access` to `scope` and ensure **Refresh Token** grant is enabled in the OCI app |
| `mobile_app` flow not working | This flow has not been tested — only `confidential_app` is verified to work |

---

## License

MIT — [Asad Jahangir](https://github.com/asad4237)
