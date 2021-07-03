#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { ChatboxSidecar }         from '../../examples/chatbox-sidecar'
import { getSidecarViewFixture }  from '../../tests/fixtures/sidecar-view.fixture'
// import { Call, RetType, Sidecar } from '../decorators/mod'
import { sidecarMetadata } from '../decorators/sidecar/sidecar-metadata'
// import { Ret } from '../ret'
// import { SidecarBody } from '../sidecar-body/sidecar-body'

import {
  buildAgentSource,
}                         from './build-agent-source'
import { sidecarView } from './sidecar-view'
import { wrapView } from '../wrappers/mod'

test('buildAgentSource() from fixture', async t => {
  const view = getSidecarViewFixture()

  const initAgentSource = 'console.log(42)'

  const source = await buildAgentSource({
    initAgentSource,
    view,
  })

  // console.log(source)
  t.true(source, 'ok')
})

test('buildAgentSource() from example demo', async t => {

  const meta = sidecarMetadata(ChatboxSidecar)
  // console.log(JSON.stringify(meta, null, 2))

  const rawView = sidecarView(meta)
  // console.log(JSON.stringify(view, null, 2))

  const view = wrapView(rawView)

  const initAgentSource = 'console.log(42)'

  const source = await buildAgentSource({
    initAgentSource,
    view,
  })

  console.log(source)
  t.true(source, 'ok')
})
