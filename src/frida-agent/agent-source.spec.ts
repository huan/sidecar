#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  agentSource,
}                         from './agent-source'

import { getSidecarViewFixture } from '../../tests/fixtures/sidecar-view.fixture'

test('agentSurce()', async t => {
  const view = getSidecarViewFixture()

  const initAgentSource = 'console.log(42)'

  const source = await agentSource({
    initAgentSource,
    view,
  })

  // console.log(source)
  t.true(source, 'ok')
})
