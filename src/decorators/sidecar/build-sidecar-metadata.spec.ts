#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { Ret } from '../../ret'
import { Call } from '../call/call'
import { Hook } from '../hook/hook'
import { ParamType } from '../param-type/param-type'
import { RetType } from '../ret-type/ret-type'

import {
  buildSidecarMetadata,
}                         from './build-sidecar-metadata'

import { Sidecar } from './sidecar'
import { SidecarBody } from '../../sidecar-body/mod'
import {
  agentTarget,
  exportTarget,
}                   from '../../function-target'

const getFixture = () => {
  @Sidecar('chatbox')
  class Test extends SidecarBody {

    @Call(0x42)
    @RetType('pointer', 'Utf8String')
    testMethod (
      @ParamType('pointer', 'Utf8String') content: string,
      @ParamType('int') n: number,
    ): Promise<string> { return Ret(content, n) }

    @Hook(agentTarget('agentVar'))
    hookMethod (
      @ParamType('int') n: number,
    ) { return Ret(n) }

    @Call(exportTarget('exportNameTest', 'moduleNameTest'))
    @RetType('pointer', 'Int')
    anotherCall (
      @ParamType('pointer', 'Int') i: number,
    ): Promise<number> { return Ret(i) }

  }

  return Test
}

test('@Sidecar() buildSidecarMetadata()', async t => {

  const Test = getFixture()

  const meta = buildSidecarMetadata(Test, {
    targetProcess: 'chatbox',
  })
  const EXPECTED_DATA = {
    initAgentSource: undefined,
    interceptorList: [
      {
        agent: {
          name: 'hookMethod',
          paramTypeList: [
            [
              'int',
            ],
          ],
          retType: undefined,
          target: { type: 'agent', varName: 'agentVar' },
        },
      },
    ],
    nativeFunctionList: [
      {
        address: {
          name: 'testMethod',
          paramTypeList: [
            [
              'pointer',
              'Utf8String',
            ],
            [
              'int',
            ],
          ],
          retType: [
            'pointer',
            'Utf8String',
          ],
          target: { address: '0x42', moduleName: null, type: 'address' },
        },
      },
      {
        export: {
          name: 'anotherCall',
          paramTypeList: [
            [
              'pointer',
              'Int',
            ],
          ],
          retType: [
            'pointer',
            'Int',
          ],
          target: { exportName: 'exportNameTest', moduleName: 'moduleNameTest', type: 'export' },
        },
      },
    ],
    targetProcess: 'chatbox',
  }

  t.deepEqual(meta, EXPECTED_DATA, 'should get metadata correct')
})
