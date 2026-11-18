#!/usr/bin/env bash
# publish.sh — build, verify, and publish opencode-oci-oidc to npm
# Usage:
#   ./publish.sh            — publish as-is (version in package.json)
#   ./publish.sh patch      — bump patch version (1.1.0 → 1.1.1) then publish
#   ./publish.sh minor      — bump minor version (1.1.0 → 1.2.0) then publish
#   ./publish.sh major      — bump major version (1.1.0 → 2.0.0) then publish
#   ./publish.sh --dry-run  — full run but no actual publish
#   ./publish.sh --tag=next — publish under a dist-tag other than "latest"
#                             (required for prerelease versions like 1.2.0-beta.0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DRY_RUN=false
BUMP=""
OTP=""
TAG=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    patch|minor|major) BUMP="$arg" ;;
    --otp=*) OTP="${arg#--otp=}" ;;
    --tag=*) TAG="${arg#--tag=}" ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  opencode-oci-oidc — npm publish script"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── 1. Verify npm login ──────────────────────────────────────────────────────
echo "[ 1/6 ] Checking npm authentication..."
NPM_USER=$(npm whoami 2>/dev/null || true)
if [[ -z "$NPM_USER" ]]; then
  echo ""
  echo "  ERROR: Not logged in to npm."
  echo "  Run:  npm login"
  echo "  Then re-run this script."
  exit 1
fi
echo "        Logged in as: $NPM_USER"

# ── 2. Safety checks — no credentials in published files ────────────────────
echo "[ 2/6 ] Checking for credential leaks in publish candidates..."

# Detect real OCI credential values (not placeholders).
# OCI client secrets always start with "idcscs-" followed by lowercase hex UUID segments.
# Placeholder examples use "x" characters, so [0-9a-f]{8} won't match them.
SENSITIVE_PATTERNS=("idcscs-[0-9a-f]{8}")
FILES_TO_SCAN=("oci-auth.config.example.jsonc" "README.md")

for f in "${FILES_TO_SCAN[@]}"; do
  if [[ ! -f "$f" ]]; then continue; fi
  for pat in "${SENSITIVE_PATTERNS[@]}"; do
    if grep -qE "$pat" "$f" 2>/dev/null; then
      echo "  ERROR: Potential credential found in $f (pattern: $pat)"
      echo "  Check the file before publishing."
      exit 1
    fi
  done
done

# Make sure real config (with actual secrets) is NOT in the files list
if grep -q '"oci-auth.config.jsonc"' package.json 2>/dev/null; then
  echo "  ERROR: oci-auth.config.jsonc (real credentials) is listed in package.json 'files'."
  echo "  Only oci-auth.config.example.jsonc should be published."
  exit 1
fi
echo "        No credential leaks detected."

# ── 3. Bump version if requested ─────────────────────────────────────────────
if [[ -n "$BUMP" ]]; then
  echo "[ 3/6 ] Bumping $BUMP version..."
  npm version "$BUMP" --no-git-tag-version
  NEW_VERSION=$(node -p "require('./package.json').version")
  echo "        Version is now: $NEW_VERSION"
else
  CURRENT_VERSION=$(node -p "require('./package.json').version")
  echo "[ 3/6 ] Using current version: $CURRENT_VERSION (pass patch/minor/major to bump)"
fi

# ── 4. Clean build ───────────────────────────────────────────────────────────
echo "[ 4/6 ] Building..."
rm -rf dist
npm run build
echo "        Build complete."

# ── 5. Show what will be published ───────────────────────────────────────────
echo "[ 5/6 ] Package contents (dry pack):"
npm pack --dry-run 2>&1 | grep -E "^npm notice|Tarball" | sed 's/^/        /'

# ── 6. Publish ───────────────────────────────────────────────────────────────
VERSION=$(node -p "require('./package.json').version")
echo "[ 6/6 ] Publishing opencode-oci-oidc@$VERSION to npm..."
echo ""

TAG_FLAG=""
[[ -n "$TAG" ]] && TAG_FLAG="--tag=$TAG"
if [[ "$VERSION" == *-* && -z "$TAG" ]]; then
  echo "  ERROR: $VERSION is a prerelease — pass --tag=<name> (e.g. --tag=next) so it doesn't become 'latest'."
  exit 1
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "        DRY RUN — skipping actual publish."
  echo "        Would have run: npm publish --access public $TAG_FLAG"
else
  OTP_FLAG=""
  [[ -n "$OTP" ]] && OTP_FLAG="--otp=$OTP"
  npm publish --access public $TAG_FLAG $OTP_FLAG
  echo ""
  echo "  Published: https://www.npmjs.com/package/opencode-oci-oidc"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Done."
echo "═══════════════════════════════════════════════════════"
echo ""
