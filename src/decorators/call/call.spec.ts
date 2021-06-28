#!/usr/bin/env ts-node
import { test }   from 'tstest'
import {
  FridaTarget,
  LabelTarget,
}                 from '../../frida'
import { Ret }    from '../../ret'

import {
  Call,
}                             from './call'
import { getMetadataCall }    from './metadata-call'
import { CALL_SYMBOL }        from './constants'

test('Call with metadata', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Call(TARGET) method () {}

  }

  const instance = new Test()
  const data = Reflect.getMetadata(
    CALL_SYMBOL,
    instance,
    'method',
  )

  /* eslint-disable no-sparse-arrays */
  t.deepEqual(data, TARGET, 'should get the Call target data')
})

test('getCallTarget()', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Call(TARGET) testMethod () {}

  }

  const instance = new Test()

  const data = getMetadataCall(
    instance,
    'testMethod',
  )

  t.deepEqual(data, TARGET, 'should get Call target data')
})

test.only('getCallTarget() with label', async t => {
  const TARGET: LabelTarget = { label: 'label1' }

  class Test {

    @Call(TARGET) testMethod () { return Ret() }

  }

  const instance = new Test()

  const data = getMetadataCall(
    instance,
    'testMethod',
  )

  t.deepEqual(data, TARGET, 'should get Call target data by')
})
