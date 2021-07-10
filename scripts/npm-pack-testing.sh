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

npx sidecar-dump metadata smoke-testing.ts > smoke-testing.metadata.test.json
diff \
  smoke-testing.metadata.json \
  smoke-testing.metadata.test.json \
  || exit 1
echo "PASSED: sidecar-dump metadata smoke-testing.ts"

npx sidecar-dump source smoke-testing.ts > smoke-testing.source.test.json
diff \
  smoke-testing.source.json \
  smoke-testing.source.test.json \
  || exit 1
echo "PASSED: sidecar-dump source smoke-testing.ts"
