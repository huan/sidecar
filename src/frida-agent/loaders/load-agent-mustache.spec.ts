#!/usr/bin/env ts-node
import { test }  from 'tstest'

import fs from 'fs'

import {
  loadAgentMustache,
}                         from './load-agent-mustache'

test('loadAgentMustache()', async t => {
  const EXPECTED_STR = fs.readFileSync(
    require.resolve('./agent.mustache')
  ).toString()
  const source = await loadAgentMustache()
  t.equal(source, EXPECTED_STR, 'should get right agent source content')
})
