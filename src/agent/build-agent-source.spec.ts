#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { ChatboxSidecar }   from '../../examples/chatbox-sidecar'
import { getMetadataView }  from '../decorators/sidecar/metadata-view'

// import { Call, RetType, Sidecar } from '../decorators/mod'
// import { sidecarMetadata } from '../decorators/sidecar/sidecar-metadata'
// import { Ret } from '../ret'
// import { SidecarBody } from '../sidecar-body/sidecar-body'

import {
  buildAgentSource,
}                         from './build-agent-source'
import { wrapView } from '../wrappers/mod'
import { getSidecarViewFixture } from '../../tests/fixtures/sidecar-view.fixture'

test('buildAgentSource() from fixture', async t => {
  const view = getSidecarViewFixture()

  const initAgentSource = 'console.log(42)'

  const source = await buildAgentSource({
    initAgentSource,
    view,
  })

  // console.log(source)
  t.true(source, 'ok (tbw)')
})

test('buildAgentSource() from example demo', async t => {

  const rawView = getMetadataView(ChatboxSidecar)!
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
