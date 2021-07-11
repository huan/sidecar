#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

import { rawArgs } from './raw-args'

test('rawArgs()', async t => {
  const SIDECAR_METADATA = getSidecarMetadataFixture()

  const nativeFunctionList      = SIDECAR_METADATA.nativeFunctionList
  const interceptorFunctionList = SIDECAR_METADATA.interceptorList

  const EXPECTED_ARGS_LIST = [
    '[ args[0], args[1] ]',
    '[ args[0], args[1] ]',
    '[ args[0], args[1] ]',
  ]

  const result = [
    ...nativeFunctionList,
    ...interceptorFunctionList,
  ].map(x => Object.values(x))
    .flat()
    .map(x => rawArgs.call(x))

  t.deepEqual(result, EXPECTED_ARGS_LIST, 'should get the raw args correct')
})
