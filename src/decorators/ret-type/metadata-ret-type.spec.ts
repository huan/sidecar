#!/usr/bin/env ts-node
import { test }  from 'tstest'
import {
  NativeType,
  PointerType,
}                 from '../../frida'

import {
  getRetType,
  updateRetType,
}                 from './metadata-ret-type'

test('update & get ret type metadata', async t => {
  const PROPERTY_KEY = 'key'
  const TARGET = {
    [PROPERTY_KEY]: () => {},
  }
  const VALUE = ['pointer', 'Utf8String'] as [NativeType, ...PointerType[]]

  updateRetType(
    TARGET,
    PROPERTY_KEY,
    VALUE,
  )

  const data = getRetType(
    TARGET,
    PROPERTY_KEY,
  )

  t.deepEqual(data, VALUE, 'should get the ret type data the same as we set(update')
})
