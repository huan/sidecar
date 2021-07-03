#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../tests/fixtures/sidecar-view.fixture'

import {
  nativeArgs,
}                       from './native-args'

test('nativeArgs()', async t => {

  const fixture = getSidecarViewFixture()

  // console.log(fixture.nativeFunctionList.length)
  const result = fixture.nativeFunctionList.map(x => nativeArgs.call(x))

  const EXPECTED_RESULT = [
    '[ anotherCall_NativeArg_0, anotherCall_NativeArg_1 ]',
    '[ testMethod_NativeArg_0, testMethod_NativeArg_1 ]',
  ]
  t.deepEqual(result, EXPECTED_RESULT, 'should list the native arg names correctly.')
})
