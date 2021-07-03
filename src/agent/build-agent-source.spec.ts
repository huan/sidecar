#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { ChatboxSidecar }   from '../../examples/chatbox-sidecar'
import { getMetadataSidecar }  from '../decorators/sidecar/metadata-sidecar'

// import { Call, RetType, Sidecar } from '../decorators/mod'
// import { sidecarMetadata } from '../decorators/sidecar/sidecar-metadata'
// import { Ret } from '../ret'
// import { SidecarBody } from '../sidecar-body/sidecar-body'

import {
  buildAgentSource,
}                         from './build-agent-source'
import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

test('buildAgentSource() from fixture', async t => {
  const metadata = getSidecarMetadataFixture()

  const source = await buildAgentSource(metadata)

  // console.log(source)
  t.true(source, 'ok (tbw)')
})

test('buildAgentSource() from example demo', async t => {

  const metadata = getMetadataSidecar(ChatboxSidecar)!
  // console.log(JSON.stringify(view, null, 2))

  const source = await buildAgentSource(metadata)

  // console.log(source)
  t.true(source, 'ok')
})
