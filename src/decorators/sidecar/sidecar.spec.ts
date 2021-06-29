#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { Ret } from '../../ret'
import { Call } from '../call/call'
import { Hook } from '../hook/hook'
import { ParamType } from '../param-type/param-type'
import { RetType } from '../ret-type/ret-type'

import { Sidecar } from './sidecar'

test('@Sidecar() smoke testing', async t => {

  @Sidecar() class Test {}

  const test = new Test()

  t.equal(Test.name, 'Test', 'should have the original class name after @Sidecar decorated')
  t.true(test, 'should instanciate decorated class successfully')
})

test('@Sidecar() generateCallAgent()', async t => {

  @Sidecar()
  class Test {

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

  const test = new Test()

  t.true(test, 'should instanciate class successfully')
})
