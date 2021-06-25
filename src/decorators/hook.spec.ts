#!/usr/bin/env ts-node
/* eslint-disable padded-blocks */

import { test }  from 'tstest'
import { FridaTarget } from '../frida'

import {
  Hook,
  getHookTarget,
  HOOK_TARGET_SYMBOL,
}                         from './hook'

test('Hook with metadata', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Hook(TARGET) method () {}

  }

  const instance = new Test()
  const data = Reflect.getMetadata(
    HOOK_TARGET_SYMBOL,
    instance,
    'method',
  )

  /* eslint-disable no-sparse-arrays */
  t.deepEqual(data, TARGET, 'should get the hook target data')
})

test('getHookTarget()', async t => {
  const TARGET: FridaTarget = 0x42

  class Test {

    @Hook(TARGET) method () {}

  }

  const instance = new Test()

  const data = getHookTarget(
    instance,
    'method',
  )

  t.deepEqual(data, TARGET, 'should get hook target data')
})
