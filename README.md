# opencode-oci-oidc

An [OpenCode](https://opencode.ai) plugin that authenticates with **Oracle Cloud Infrastructure (OCI) IAM** and injects a Bearer token into every request sent to an OpenAI-compatible LLM endpoint running on OCI.

Two auth methods are supported:

| Method | Description |
|--------|-------------|
| `confidential_app` | Browser-based OAuth 2.0 Authorization Code flow with a client secret |
| `mobile_app` | OCI Device Authorization Grant (RFC 8628) — no browser, no secret; approve on the OCI Mobile Authenticator app |

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

1. Run `/connect` in OpenCode — a browser window opens to the OCI login page
2. Complete login; the browser redirects back to `localhost:8888/callback`
3. The plugin exchanges the code for a token, caches it, and subsequent requests are automatic

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

Default log file: `~/oci-oidc-debug.log`

Change location and verbosity in `oci-auth.config.jsonc`:
```jsonc
"log_level": "DEBUG",
"log_file": "~/my-custom-path/oci-auth.log"
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `No OCI auth config found` | Place `oci-auth.config.jsonc` next to `opencode.json` or in `~/.config/opencode/` |
| Browser doesn't open | Check `redirect_uri` is registered in your OCI application |
| Token rejected (401) after working | Run `oci_oidc_refresh` tool or `/connect` again |
| Hanging after sending a message | Check `~/oci-oidc-debug.log` — look for network timeout errors |
| No refresh token (`has_refresh_token: false` in logs) | Add `offline_access` to `scope` in the plugin config |

---

## License

MIT — [Asad Jahangir](https://github.com/asad4237)
