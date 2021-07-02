#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { TypeChain } from '../../frida'

import {
  getMetadataParamType,
  updateMetadataParamType,
}                           from './metadata-param-type'

test('update & get parame type metadata', async t => {
  const PROPERTY_KEY = 'key'
  const TARGET = {
    [PROPERTY_KEY]: () => {},
  }
  const VALUE = [['pointer', 'Utf8String']] as TypeChain[]

  updateMetadataParamType(
    TARGET,
    PROPERTY_KEY,
    0,
    VALUE[0],
  )

  const data = getMetadataParamType(
    TARGET,
    PROPERTY_KEY,
  )

  t.deepEqual(data, VALUE, 'should get the parameter type data the same as we set(update)')
})
