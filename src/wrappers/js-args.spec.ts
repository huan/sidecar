#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

import { jsArgs } from './js-args'

test('jsArgs()', async t => {
  const SIDECAR_METADATA = getSidecarMetadataFixture()

  const nativeFunctionList      = SIDECAR_METADATA.nativeFunctionList
  const interceptorFunctionList = SIDECAR_METADATA.interceptorList

  const EXPECTED_ARGS_LIST = [
    '[ args[0].readInt(), args[1].readPointer().readUtf8String() ]',
    '[ args[0].readUtf8String(), args[1] ]',
    '[ args[0], args[1].readUtf8String() ]',
  ]

  const result = [
    ...nativeFunctionList,
    ...interceptorFunctionList,
  ].map(x => jsArgs.call(x))

  t.deepEqual(result, EXPECTED_ARGS_LIST, 'should wrap the args correct')
})
