#!/usr/bin/env ts-node
import { test }         from 'tstest'
import { EventEmitter } from 'stream'
import {
  Ret,
  RET_SYMBOL,
}                         from '../../ret'
import { CALL_RET_ERROR } from './constants'

import {
  updateRpcDescriptor,
}                           from './update-rpc-descriptor'

test('update & get call target metadata', async t => {

  const AFTER_VALUE = 42

  class Test {

    script = {
      exports: {
        testMethod: () => AFTER_VALUE,
      },
    }

    testMethod () { return Ret() }

  }

  const test = new Test()

  const descriptor = Reflect.getOwnPropertyDescriptor(Test.prototype, 'testMethod')
  const beforeValue = await descriptor?.value()
  t.equal(beforeValue, RET_SYMBOL, 'should get RET_SYMBOL before update rpc method')

  const rpcDescriptor = updateRpcDescriptor(
    Test,
    'testMethod',
    descriptor!,
  )

  const rpcValue = await rpcDescriptor.value.bind(test)()
  t.equal(rpcValue, AFTER_VALUE, 'should get AFTER_VALUE from rpcValue')

  Object.defineProperty(Test.prototype, 'testMethod', rpcDescriptor)
  const ret = await test.testMethod()
  t.equal(ret, AFTER_VALUE, 'should get a updated method return value')

  await new Promise(setImmediate)
  t.false((Test as any)[CALL_RET_ERROR], 'should not trigger error if the method returns "Ret()"')
})

test('method to be proxyed must retur "Ret()"', async t => {

  const RET_VALUE = 42

  class Test extends EventEmitter {

    method () {
      return Promise.resolve(RET_VALUE)
    }

  }

  const descriptor = Reflect.getOwnPropertyDescriptor(Test.prototype, 'method')
  const beforeValue = await descriptor?.value()
  t.equal(beforeValue, RET_VALUE, 'should get ret value from the descriptor')

  updateRpcDescriptor(
    Test,
    'method',
    descriptor!,
  )
  await new Promise(setImmediate)

  t.true((Test as any)[CALL_RET_ERROR], 'should trigger error if the method does not return "Ret()" (We can safely ignore the Error message above this test)')
})
