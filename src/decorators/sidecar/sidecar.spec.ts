#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { Ret } from '../../ret'
import { SidecarBody } from '../../sidecar-body/sidecar-body'
import { Call } from '../call/call'
import { Hook } from '../hook/hook'
import { ParamType } from '../param-type/param-type'
import { RetType } from '../ret-type/ret-type'
import { getMetadataSidecar } from './metadata-sidecar'

import { Sidecar } from './sidecar'

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

test('@Sidecar() smoke testing', async t => {

  @Sidecar('chatbox') class Test extends SidecarBody {}

  const test = new Test()

  t.equal(Test.name, 'Test', 'should have the original class name after @Sidecar decorated')
  t.true(test, 'should instanciate decorated class successfully')
})

test('@Sidecar() viewMetadata()', async t => {

  const Test = getFixture()

  const metadata = getMetadataSidecar(Test)
  const EXPECTED_DATA = {
    initAgentScript: undefined,
    interceptorList: [
      {
        address: {
          name: 'hookMethod',
          paramTypeList: [
            [
              'int',
            ],
          ],
          retType: undefined,
          target: { address: '0x17', moduleName: null, type: 'address' },
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
    ],
    targetProcess: 'chatbox',
  }

  t.deepEqual(metadata, EXPECTED_DATA, 'should get view from metadata correct')
})
