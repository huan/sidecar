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

const getFixture = () => {
  @Sidecar('chatbox')
  class Test extends SidecarBody {

    @Call(0x42)
    @RetType('pointer', 'Utf8String')
    testMethod (
      @ParamType('pointer', 'Utf8String') content: string,
      @ParamType('int') n: number,
    ): Promise<string> { return Ret(content, n) }

    @Hook(0x17)
    hookMethod (
      @ParamType('int') n: number,
    ) { return Ret(n) }

    // Huan(202106) TODO: support { label }
    // @Call({ label: 'label1' }) anotherCall () { return Ret() }

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
        name: 'hookMethod',
        paramTypeList: [
          [
            'int',
          ],
        ],
        retType: undefined,
        target: 23,
      },
    ],
    nativeFunctionList: [
      {
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
        target: 66,
      },
    ],
    targetProcess: 'chatbox',
  }

  t.deepEqual(meta, EXPECTED_DATA, 'should get metadata correct')
})
