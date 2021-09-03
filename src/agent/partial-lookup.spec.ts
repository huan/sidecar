#!/usr/bin/env -S node --no-warnings --loader ts-node/esm
import { test }  from 'tstest'

import fs from 'fs'

import {
  partialLookup,
}                         from './partial-lookup.js'

test('partialLookup()', async t => {
  const EXPECTED_STR = fs.readFileSync(
    require.resolve('./templates/libs/log.js')
  ).toString()
  const source = await partialLookup('libs/log.js')
  t.equal(source, EXPECTED_STR, 'should get right partial file content')
})
