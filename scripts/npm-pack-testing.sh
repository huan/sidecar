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

npx sidecar-dump metadata smoke-testing.ts > smoke-testing.metadata.json
diff \
  smoke-testing.sidecar-dump.metadata.json \
  smoke-testing.metadata.json \
  || exit 1
echo "PASSED: sidecar-dump metadata smoke-testing.ts"

npx sidecar-dump source smoke-testing.ts > smoke-testing.source.js
diff \
  smoke-testing.sidecar-dump.source.js \
  smoke-testing.source.js \
  || exit 1
echo "PASSED: sidecar-dump source smoke-testing.ts"
