#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  getCallTarget,
  updateCallTarget,
}                         from './metadata-call-target'

test('update & get call target metadata', async t => {
  const PROPERTY_KEY = 'key'
  const TARGET = {
    [PROPERTY_KEY]: () => {},
  }
  const CALL_TARGET = 0x42

  updateCallTarget(
    TARGET,
    PROPERTY_KEY,
    CALL_TARGET,
  )

  const data = getCallTarget(
    TARGET,
    PROPERTY_KEY,
  )

  t.deepEqual(data, CALL_TARGET, 'should get the call target data the same as we set(update')
})
