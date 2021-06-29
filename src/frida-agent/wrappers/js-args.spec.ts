#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import { jsArgs } from './js-args'

test('jsArgs()', async t => {
  const SIDECAR_VIEW = getSidecarViewFixture()

  const nativeFunctionList      = SIDECAR_VIEW.nativeFunctionList
  const interceptorFunctionList = SIDECAR_VIEW.interceptorList

  const EXPECTED_ARGS_LIST = [
    '[ args[0].readPointer().readInt(), args[1].readPointer().readPointer().readUtf8String() ]',
    '[ args[0].readPointer().readUtf8String(), args[1] ]',
    '[ args[0] ]',
  ]

  const result = [
    ...nativeFunctionList,
    ...interceptorFunctionList,
  ].map(x => jsArgs.call(x))

  t.deepEqual(result, EXPECTED_ARGS_LIST, 'should wrap the args correct')
})
