#!/usr/bin/env bash
set -e

# Huan(202107) Credit: https://stackoverflow.com/a/48287203/1123955
function diffLines () {
  diff \
    -y \
    --suppress-common-lines \
    $1 \
    $2 \
    | wc -l
}

function sidecarDumpTest () {
  npx sidecar-dump metadata smoke-testing.ts > smoke-testing.metadata.json
  if [[ $(diffLines smoke-testing.metadata.json sidecar-dump.metadata.smoke-testing.json.fixture) -gt 10 ]]; then
    >&2 echo "FAILED: sidecar-dump metadata smoke-testing.ts"
    exit 1
  fi
  echo "PASSED: sidecar-dump metadata smoke-testing.ts"

  npx sidecar-dump source smoke-testing.ts > smoke-testing.source.js
  if [[ $(diffLines smoke-testing.source.js sidecar-dump.source.smoke-testing.js.fixture) -gt 10 ]]; then
    >&2 echo "FAILED: sidecar-dump source smoke-testing.ts"
    exit 1
  fi
  echo "PASSED: sidecar-dump source smoke-testing.ts"
}

npm run dist
npm pack

TMPDIR="/tmp/npm-pack-testing.$$"
mkdir "$TMPDIR"
mv *-*.*.*.tgz "$TMPDIR"
cp tests/fixtures/* "$TMPDIR"

cd $TMPDIR
npm init -y
npm install *-*.*.*.tgz \
  @chatie/tsconfig \
  typescript@next

#
# CommonJS
#
./node_modules/.bin/tsc \
  --esModuleInterop \
  --lib esnext \
  --noEmitOnError \
  --noImplicitAny \
  --skipLibCheck \
  --target es5 \
  --module CommonJS \
  --moduleResolution node \
  smoke-testing.ts

echo
echo "CommonJS: pack testing..."
node smoke-testing.js
sidecarDumpTest

#
# ES Modules
#

# https://stackoverflow.com/a/59203952/1123955
echo "`jq '.type="module"' package.json`" > package.json

./node_modules/.bin/tsc \
  --esModuleInterop \
  --lib esnext \
  --noEmitOnError \
  --noImplicitAny \
  --skipLibCheck \
  --target es2020 \
  --module es2020 \
  --moduleResolution node \
  smoke-testing.ts

echo
echo "ES Module: pack testing..."
node smoke-testing.js
sidecarDumpTest
