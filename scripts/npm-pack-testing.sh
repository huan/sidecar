#!/usr/bin/env bash
set -e

# Huan(202107) Credit: https://stackoverflow.com/a/48287203/1123955
function diff_lines () {
  diff \
    -y \
    --suppress-common-lines \
    $1 \
    $2 \
    | wc -l
}

npm run dist
npm pack

TMPDIR="/tmp/npm-pack-testing.$$"
mkdir "$TMPDIR"
mv ./*-*.*.*.tgz "$TMPDIR"
cp tests/fixtures/* "$TMPDIR"

cd $TMPDIR
npm init -y
npm install ./*-*.*.*.tgz \
  pkg-jq \
  @chatie/tsconfig

#
# CommonJS
#
./node_modules/.bin/tsc \
  --target es6 \
  --module CommonJS \
  --skipLibCheck \
  --strict \
  --experimentalDecorators \
  --emitDecoratorMetadata \
  smoke-testing.ts

echo
echo "CommonJS: pack testing..."
node smoke-testing.js
echo "No dump testing with CJS. (Only support ESM for now)"

#
# ES Modules
#

# https://stackoverflow.com/a/59203952/1123955
# echo "`jq '.type="module"' package.json`" > package.json
npx pkg-jq -i '.type="module"'

./node_modules/.bin/tsc \
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
