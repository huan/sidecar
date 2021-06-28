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
  const METHOD_NAME = 'testMethod'

  class Test {

    @Call(TARGET) [METHOD_NAME] () { return Ret() }

  }

  const instance = new Test()
  const data = Reflect.getMetadata(
    CALL_SYMBOL,
    instance,
    METHOD_NAME,
  )

  /* eslint-disable no-sparse-arrays */
  t.deepEqual(data, TARGET, 'should get the Call target data')
})

test('getCallTarget()', async t => {
  const TARGET: FridaTarget = 0x42
  const METHOD_NAME = 'testMethod'

  class Test {

    @Call(TARGET) [METHOD_NAME] () { return Ret() }

  }

  const instance = new Test()

  const data = getMetadataCall(
    instance,
    METHOD_NAME,
  )

  t.deepEqual(data, TARGET, 'should get Call target data')
})

test('getCallTarget() with label', async t => {
  const TARGET: LabelTarget = { label: 'label1' }
  const METHOD_NAME = 'testMethod'

  class Test {

    @Call(TARGET) [METHOD_NAME] () { return Ret() }

  }

  const instance = new Test()

  const data = getMetadataCall(
    instance,
    METHOD_NAME,
  )

  t.deepEqual(data, TARGET, 'should get Call target data by')
})
