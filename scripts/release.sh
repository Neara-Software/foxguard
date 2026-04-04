#!/usr/bin/env bash
set -euo pipefail

# Release script for foxguard
# Usage: ./scripts/release.sh 0.4.0

VERSION="${1:?Usage: ./scripts/release.sh <version>}"

echo "=== Releasing foxguard v${VERSION} ==="

# 1. Bump all versions
echo "Bumping versions..."
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

for pkg in packages/npm/package.json vscode-extension/package.json; do
  node -e "
    const pkg = require('./${pkg}');
    pkg.version = '${VERSION}';
    require('fs').writeFileSync('${pkg}', JSON.stringify(pkg, null, 2) + '\n');
  "
done

# 2. Build and test
echo "Building..."
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# 3. Commit, tag, push
echo "Committing..."
git add Cargo.toml packages/npm/package.json vscode-extension/package.json
git commit -m "v${VERSION}"
git push
git tag "v${VERSION}"
git push origin "v${VERSION}"

# 4. Publish npm
echo "Publishing to npm..."
cd packages/npm && npm publish --access public && cd ../..

# 5. Publish VS Code extension
echo "Publishing VS Code extension..."
cd vscode-extension
npx @vscode/vsce publish -p "${VSCE_PAT:-}"
cd ..

echo ""
echo "=== v${VERSION} released ==="
echo "  GitHub Release: building (check Actions)"
echo "  npm: foxguard@${VERSION}"
echo "  VS Code: peaktwilight.foxguard@${VERSION}"
echo "  Homebrew: update homebrew-tap Formula manually"
