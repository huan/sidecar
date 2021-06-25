#!/usr/bin/env ts-node
import { test }  from 'tstest'
import {
  FridaTarget,
  LabelTarget,
}               from '../frida'

import {
  Call,
  getCallTarget,
  CALL_TARGET_SYMBOL,
}                         from './call'

test('Call with metadata', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Call(TARGET) method () {}

  }

  const instance = new Test()
  const data = Reflect.getMetadata(
    CALL_TARGET_SYMBOL,
    instance,
    'method',
  )

  /* eslint-disable no-sparse-arrays */
  t.deepEqual(data, TARGET, 'should get the Call target data')
})

test('getCallTarget()', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Call(TARGET) method () {}

  }

  const instance = new Test()

  const data = getCallTarget(
    instance,
    'method',
  )

  t.deepEqual(data, TARGET, 'should get Call target data')
})

test('getCallTarget() with label', async t => {
  const TARGET: LabelTarget = { label: 'label1' }

  class Test {

    @Call(TARGET) method () {}

  }

  const instance = new Test()

  const data = getCallTarget(
    instance,
    'method',
  )

  t.deepEqual(data, TARGET, 'should get Call target data by')
})
