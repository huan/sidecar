#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { Ret } from '../../ret'
import { Call } from '../call/call'
import { Hook } from '../hook/hook'
import { ParamType } from '../param-type/param-type'
import { RetType } from '../ret-type/ret-type'

import {
  sidecarMetadata,
  SidecarMetadata,
}                   from './sidecar-metadata'

import { Sidecar } from './sidecar'
import { SidecarBody } from '../../sidecar-body/mod'

test('sidecarMetadata() empty class', async t => {

  @Sidecar('chatbox') class Test extends SidecarBody {}

  const EXPECTED_DATA: SidecarMetadata = { call: {}, hook: {}, paramType: {}, retType: {} }

  const metadata = sidecarMetadata(Test)

  t.deepEqual(metadata, EXPECTED_DATA, 'should get empty data for empty class')
})

test('sidecarMetadata smoke testing', async t => {

  @Sidecar('test')
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

    @Call({ label: 'label1' }) anotherCall () { return Ret() }

  }

  const EXPECTED_DATA: SidecarMetadata = {
    call: {
      anotherCall: {
        label: 'label1',
      },
      testMethod: 66,
    },
    hook: {
      hookMethod: 23,
    },
    paramType: {
      hookMethod: [
        [
          'int',
        ],
      ],
      testMethod: [
        [
          'pointer',
          'Utf8String',
        ],
        [
          'int',
        ],
      ],
    },
    retType: {
      testMethod: [
        'pointer',
        'Utf8String',
      ],
    },
  }

  const metadata = sidecarMetadata(Test)
  t.deepEqual(metadata, EXPECTED_DATA, 'should get the correct sidecar metadata for decorated class')
})
