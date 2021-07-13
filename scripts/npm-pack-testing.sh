#!/usr/bin/env bash
set -e

npm run dist
npm run pack

TMPDIR="/tmp/npm-pack-testing.$$"
mkdir "$TMPDIR"
mv *-*.*.*.tgz "$TMPDIR"
cp tests/fixtures/* "$TMPDIR"

cd $TMPDIR
npm init -y
npm install *-*.*.*.tgz \
  @chatie/tsconfig \
  typescript@next

./node_modules/.bin/tsc \
  --target es5 \
  --lib esnext \
  --noEmitOnError \
  --noImplicitAny \
  --experimentalDecorators \
  --emitDecoratorMetadata \
  --esModuleInterop \
  smoke-testing.ts

node smoke-testing.js

# Huan(202107) Credit: https://stackoverflow.com/a/48287203/1123955
function diffLines () {
  diff \
    -y \
    --suppress-common-lines \
    $1 \
    $2 \
    | wc -l
}

npx sidecar-dump metadata smoke-testing.ts > smoke-testing.test.metadata.json
if [[ $(diffLines smoke-testing.test.metadata.json smoke-testing.sidecar-dump.metadata.json) -gt 10 ]]; then
  exit 1
fi
echo "PASSED: sidecar-dump metadata smoke-testing.ts"

npx sidecar-dump source smoke-testing.ts > smoke-testing.test.source.js
if [[ $(diffLines smoke-testing.test.source.js smoke-testing.sidecar-dump.source.js) -gt 10 ]]; then
  exit 1
fi
echo "PASSED: sidecar-dump source smoke-testing.ts"
