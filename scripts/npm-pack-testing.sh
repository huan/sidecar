#!/usr/bin/env bash
set -e

# Huan(202107) Credit: https://stackoverflow.com/a/48287203/1123955
function diff_lines () {
  diff \
    -y \
    --strip-trailing-cr \
    --suppress-common-lines \
    $1 \
    $2 \
    | wc -l
}

npm run dist
npm pack

TMPDIR="/tmp/npm-pack-testing.$$"
mkdir "$TMPDIR"
# trap "rm -fr '$TMPDIR'" EXIT

mv ./*-*.*.*.tgz "$TMPDIR"
cp tests/fixtures/* "$TMPDIR"

cd $TMPDIR
npm init -y
# ES Modules
npx pkg-jq -i '.type="module"'
npm install ./*-*.*.*.tgz \
  es-main \
  pkg-jq \
  @chatie/tsconfig

npx tsc \
  --target es2020 \
  --module es2020 \
  --skipLibCheck \
  --strict \
  --experimentalDecorators \
  --emitDecoratorMetadata \
  --moduleResolution node \
  smoke-testing.ts

echo
echo "ES Module: pack testing..."
node smoke-testing.js

#
# Dump testing (ESM only)
#
npx sidecar-dump metadata smoke-testing.ts > smoke-testing.metadata.json
if [[ $(diff_lines smoke-testing.metadata.json sidecar-dump.metadata.smoke-testing.json.fixture) -gt 10 ]]; then
  >&2 echo "FAILED: sidecar-dump metadata smoke-testing.ts"
  exit 1
fi
echo "PASSED: sidecar-dump metadata smoke-testing.ts"

npx sidecar-dump source smoke-testing.ts > smoke-testing.source.js
if [[ $(diff_lines smoke-testing.source.js sidecar-dump.source.smoke-testing.js.fixture) -gt 10 ]]; then
  >&2 echo "FAILED: sidecar-dump source smoke-testing.ts"
  exit 1
fi
echo "PASSED: sidecar-dump source smoke-testing.ts (ESM only)"
