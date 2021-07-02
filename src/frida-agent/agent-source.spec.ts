#!/usr/bin/env ts-node
import { test }  from 'tstest'

// import { ChatboxSidecar }         from '../../examples/chatbox-sidecar'
import { getSidecarViewFixture }  from '../../tests/fixtures/sidecar-view.fixture'
import { Call, RetType, Sidecar } from '../decorators/mod'
import { sidecarMetadata } from '../decorators/sidecar/sidecar-metadata'
import { Ret } from '../ret'
import { SidecarBody } from '../sidecar-body/sidecar-body'

import {
  agentSource,
}                         from './agent-source'
import { sidecarView } from './sidecar-view'

test('agentSource() from fixture', async t => {
  const view = getSidecarViewFixture()

  const initAgentSource = 'console.log(42)'

  const source = await agentSource({
    initAgentSource,
    view,
  })

  // console.log(source)
  t.true(source, 'ok')
})

test('agentSource() from example demo', async t => {

  @Sidecar('test')
  class Test extends SidecarBody {

    @Call(0x1234)
    @RetType('int')
    test (): Promise<number> { return Ret() }

  }

  const meta = sidecarMetadata(Test)
  // console.log(JSON.stringify(meta, null, 2))

  const view = sidecarView(meta)
  // console.log(JSON.stringify(view, null, 2))

  const initAgentSource = 'console.log(42)'

  const source = await agentSource({
    initAgentSource,
    view,
  })

  // console.log(source)
  t.true(source, 'ok')
})
