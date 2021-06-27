#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { Ret, RET_SYMBOL } from '../../ret'

import {
  updateRpcDescriptor,
}                           from './update-rpc-descriptor'

test('update & get call target metadata', async t => {

  const AFTER_VALUE = 42

  class Test {

    script = {
      exports: {
        method: () => AFTER_VALUE,
      },
    }

    method () {
      return Ret()
    }

  }

  const test = new Test()

  const descriptor = Reflect.getOwnPropertyDescriptor(Test.prototype, 'method')
  const beforeValue = await descriptor?.value()
  t.equal(beforeValue, RET_SYMBOL, 'should get RET_SYMBOL before update rpc method')

  const rpcDescriptor = updateRpcDescriptor(
    Test,
    'method',
    descriptor!,
  )

  const rpcValue = await rpcDescriptor.value.bind(test)()
  t.equal(rpcValue, AFTER_VALUE, 'should get AFTER_VALUE from rpcValue')

  Object.defineProperty(Test.prototype, 'method', rpcDescriptor)
  const ret = await test.method()
  t.equal(ret, AFTER_VALUE, 'should get a updated method return value')
})

/**
 * Huan(202106) FIXME:
 *  We can not catch this error because the function is sync
 */
test.skip('method to be proxyed must retur "Ret()"', async t => {

  const RET_VALUE = 42

  class Test {

    method () {
      return Promise.resolve(RET_VALUE)
    }

  }

  const descriptor = Reflect.getOwnPropertyDescriptor(Test.prototype, 'method')
  const beforeValue = await descriptor?.value()
  t.equal(beforeValue, RET_VALUE, 'should get ret value from the descriptor')

  const update = () => updateRpcDescriptor(
    Test,
    'method',
    descriptor!,
  )

  update()
  t.throws(update, 'should throw if the method does not return "Ret()"')
})
