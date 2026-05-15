# opencode-oci-oidc

**OCI OIDC Auth** — an [OpenCode](https://opencode.ai) plugin that authenticates
with an **Oracle Cloud Infrastructure Confidential Application** using the OAuth 2.0
Client Credentials grant, then injects the resulting Bearer token into requests
made to an **OpenAI-compatible LLM endpoint** served on OCI GPUs.

```
 opencode.json            plugin (shell.env hook)         OCI IAM Domain
 ─────────────            ────────────────────────         ──────────────
 oci_oidc.client_id  ──▶  fetchToken()  ─────────────▶  POST /oauth2/v1/token
 oci_oidc.client_secret   ◀── access_token ────────────  (Client Credentials)
 
 OCI_BEARER_TOKEN injected into env
         │
         ▼
 provider "oci-oidc"                                      OCI GPU Endpoint
 apiKey: {env:OCI_BEARER_TOKEN}  ──────────────────────▶  OpenAI-compat API
```

---

## Folder structure

```
opencode-oci-oidc/
├── src/
│   └── index.ts            ← Plugin source (TypeScript)
├── dist/                   ← Compiled output (after npm run build)
│   ├── index.js
│   └── index.d.ts
├── package.json
├── tsconfig.json
├── opencode.json           ← Drop this into your project root (edit values)
└── README.md
```

Your project layout after setup:

```
my-project/
├── opencode.json           ← Contains oci_oidc config + provider block
├── .opencode/
│   └── plugins/
│       └── oci-oidc.ts     ← Symlink or copy of src/index.ts (local dev)
└── ... your code ...
```

Global secrets file (outside any project):

```
~/.secrets/
└── oci-client-secret       ← Plain text, no newline. NEVER commit this.
```

---

## Prerequisites

| | What you need |
|---|---|
| Node.js | v20 or later |
| npm | v10 or later (comes with Node 20) |
| OpenCode | Latest (installed in WSL — see below) |
| OCI IAM | A Confidential Application with Client Credentials grant |
| OCI LLM | An OpenAI-compatible inference endpoint URL + model ID |

---

## Windows setup (WSL — recommended by OpenCode)

OpenCode's own documentation recommends running it inside WSL on Windows.
All paths below are **WSL paths** unless stated otherwise.

### 1 — Install WSL (if you haven't)

Open **PowerShell as Administrator** and run:

```powershell
wsl --install
```

Restart when prompted. The default distro is Ubuntu 22.04 LTS.

### 2 — Install Node.js inside WSL

Open your WSL terminal, then:

```bash
# Install nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# Reload shell
source ~/.bashrc

# Install Node 20 LTS
nvm install 20
nvm use 20
nvm alias default 20

# Verify
node -v   # should print v20.x.x
npm -v    # should print 10.x.x
```

### 3 — Install OpenCode inside WSL

```bash
curl -fsSL https://opencode.ai/install | bash
```

### 4 — Clone / copy this plugin into WSL

```bash
# Option A: clone the repo (if published)
git clone https://github.com/YOUR_ORG/opencode-oci-oidc.git
cd opencode-oci-oidc

# Option B: copy from Windows filesystem
# Your Windows C: drive is at /mnt/c/ in WSL
cp -r /mnt/c/Users/YourName/Downloads/opencode-oci-oidc ~/opencode-oci-oidc
cd ~/opencode-oci-oidc
```

### 5 — Install dependencies and build

```bash
npm install
npm run build
# → creates dist/index.js
```

### 6 — Store the OCI Client Secret

```bash
mkdir -p ~/.secrets
chmod 700 ~/.secrets

# Paste ONLY the secret value — no newline, no quotes
printf 'YOUR_OCI_CLIENT_SECRET_HERE' > ~/.secrets/oci-client-secret
chmod 600 ~/.secrets/oci-client-secret
```

> **Windows note:** `%USERPROFILE%\.secrets\oci-client-secret` on the Windows
> filesystem is accessible from WSL at
> `/mnt/c/Users/YourName/.secrets/oci-client-secret`. Either location works
> with `{file:}` substitution — use the WSL path in `opencode.json`.

---

## Configuration

### Edit `opencode.json` in your project

Copy `opencode.json` from this repo into your project root, then fill in your values:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-oci-oidc"],

  "oci_oidc": {
    "domain_url": "https://idcs-0abc123def456.identity.oraclecloud.com",
    "client_id": "your-confidential-app-client-id",
    "client_secret": "{file:~/.secrets/oci-client-secret}",
    "scope": "urn:opc:resource:consumer::all",
    "llm_base_url": "https://inference.ai.us-chicago-1.oci.oraclecloud.com/v1",
    "model_id": "meta-llama/Llama-3.1-70B-Instruct",
    "model_display_name": "Llama 3.1 70B (OCI GPU)",
    "context_tokens": 131072,
    "max_tokens": 8192
  },

  "provider": {
    "oci-oidc": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OCI OIDC Auth",
      "options": {
        "baseURL": "https://inference.ai.us-chicago-1.oci.oraclecloud.com/v1",
        "apiKey": "{env:OCI_BEARER_TOKEN}"
      },
      "models": {
        "llama-3-1-70b": {
          "id": "meta-llama/Llama-3.1-70B-Instruct",
          "name": "Llama 3.1 70B (OCI GPU)",
          "limit": { "context": 131072, "output": 8192 }
        }
      }
    }
  },

  "model": "oci-oidc/llama-3-1-70b"
}
```

### Config field reference

| Field | Required | Description |
|-------|----------|-------------|
| `domain_url` | ✅ | OCI IAM Domain base URL (no trailing slash) |
| `client_id` | ✅ | Confidential Application Client ID |
| `client_secret` | ✅ | Client Secret — use `{file:~/.secrets/oci-client-secret}` |
| `scope` | ✗ | OAuth scopes, space-separated |
| `llm_base_url` | ✅ | OpenAI-compatible endpoint base URL (include `/v1`) |
| `model_id` | ✅ | Exact model string your endpoint accepts |
| `model_display_name` | ✗ | Label in `/models` list. Defaults to `model_id` |
| `context_tokens` | ✗ | Context window size. Default: `32768` |
| `max_tokens` | ✗ | Max output tokens. Default: `4096` |

---

## Loading the plugin

### Option A — Local plugin file (best for development)

```bash
# From your project root
mkdir -p .opencode/plugins

# Copy the compiled file
cp ~/opencode-oci-oidc/dist/index.js .opencode/plugins/oci-oidc.js

# OR copy the TypeScript source — OpenCode compiles TS natively via Bun
cp ~/opencode-oci-oidc/src/index.ts .opencode/plugins/oci-oidc.ts
```

No changes needed to `opencode.json` for local plugins — OpenCode auto-loads
everything in `.opencode/plugins/`.

Remove the `"plugin"` line from your config if you use a local file to avoid
loading it twice.

### Option B — npm package (once published)

```jsonc
// opencode.json
{
  "plugin": ["opencode-oci-oidc"]
}
```

OpenCode installs it automatically via Bun on startup.

---

## How it works

### Auth flow

1. On startup and on each `session.created` event, the plugin calls:
   ```
   POST {domain_url}/oauth2/v1/token
   Authorization: Basic base64(client_id:client_secret)
   Body: grant_type=client_credentials&scope=...
   ```
2. The `access_token` is cached in memory **and** on disk at
   `~/.cache/opencode-oci-oidc/token.json`, with a 60-second safety margin.

### Token injection

OpenCode fires the `shell.env` hook before every tool execution (bash, read,
write, etc.). The plugin uses this hook to set:

```
OCI_BEARER_TOKEN=<current_access_token>
```

The `provider` block in `opencode.json` reads it via `{env:OCI_BEARER_TOKEN}`,
so every request to the OCI endpoint carries a fresh Bearer token.

### Custom tools exposed to the agent

| Tool name | What it does |
|-----------|--------------|
| `oci_oidc_refresh` | Force-fetches a new token (call after a 401) |
| `oci_oidc_status` | Shows token validity, expiry, endpoint, model |

---

## OCI Confidential Application setup

If you haven't set it up yet:

1. OCI Console → **Identity & Security → Domains → \<your domain\>**
2. **Integrated Applications → Add Application → Confidential Application**
3. Application name: `opencode-llm-client` (or any name)
4. Under **Configure this application as a client**:
   - Grant types: ✅ **Client Credentials**
   - Scopes: add the scope your LLM endpoint requires
   - Do **not** add any Identity Domain admin roles
5. Click **Finish**, then **Activate**
6. Copy **Client ID** and **Client Secret** → write secret to `~/.secrets/oci-client-secret`

---

## Development workflow (Windows + WSL)

```bash
# 1. Open WSL terminal
# 2. Navigate to the plugin folder
cd ~/opencode-oci-oidc

# 3. Build after making changes
npm run build

# 4. Copy updated file to your project
cp dist/index.js /mnt/c/Users/YourName/my-project/.opencode/plugins/oci-oidc.js

# 5. Restart OpenCode in your project
cd /mnt/c/Users/YourName/my-project
opencode
```

For live rebuild while editing:

```bash
npm run dev      # tsc --watch — rebuilds on save
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Plugin not loading | File not in `.opencode/plugins/` | Check path; restart OpenCode |
| `OCI token request failed (401)` | Wrong client ID or secret | Re-check credentials in OCI Console |
| `OCI token request failed (400)` | Invalid scope | Check `scope` field or leave it empty |
| `oci_oidc` config not found | Missing block in opencode.json | Add the `oci_oidc` block; check JSON syntax |
| `{file:~/.secrets/oci-client-secret}` not resolving | File missing or wrong path | Run `ls -la ~/.secrets/` inside WSL |
| 401 from LLM endpoint | Stale token | Ask agent to call `oci_oidc_refresh` |
| Model not in `/models` | Provider block mismatch | Confirm `baseURL` and model key in `provider` block |

---

## Security notes

- `client_secret` lives in `~/.secrets/oci-client-secret` — never in the config file
- The `tool.execute.before` hook prevents the agent from reading files under `~/.secrets/`
- OCI tokens are short-lived (1 hour default) — no long-lived credential exposure
- The Confidential Application should have **no IAM admin roles** — only the scopes needed for LLM access

---

## License

MIT
