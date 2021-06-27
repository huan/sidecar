#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { NativeType, PointerType } from '../../frida'

import {
  getMetadataParamType,
  updateMetadataParamType,
}                           from './metadata-param-type'

test('update & get parame type metadata', async t => {
  const PROPERTY_KEY = 'key'
  const TARGET = {
    [PROPERTY_KEY]: () => {},
  }
  const VALUE = ['pointer', 'Utf8String'] as [NativeType, ...PointerType[]]

  updateMetadataParamType(
    TARGET,
    PROPERTY_KEY,
    0,
    VALUE,
  )

  const data = getMetadataParamType(
    TARGET,
    PROPERTY_KEY,
    0,
  )

  t.deepEqual(data, VALUE, 'should get the parameter type data the same as we set(update')
})
