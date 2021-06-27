#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  getMetadataCall,
  updateMetadataCall,
}                           from './metadata-call'

test('update & get call target metadata', async t => {
  const PROPERTY_KEY = 'key'
  const TARGET = {
    [PROPERTY_KEY]: () => {},
  }
  const CALL_TARGET = 0x42

  updateMetadataCall(
    TARGET,
    PROPERTY_KEY,
    CALL_TARGET,
  )

  const data = getMetadataCall(
    TARGET,
    PROPERTY_KEY,
  )

  t.deepEqual(data, CALL_TARGET, 'should get the call target data the same as we set(update')
})
