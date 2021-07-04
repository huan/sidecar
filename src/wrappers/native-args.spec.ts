#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

import {
  nativeArgs,
}                       from './native-args'

test('nativeArgs()', async t => {

  const fixture = getSidecarMetadataFixture()

  // console.log(fixture.nativeFunctionList.length)
  const result = fixture.nativeFunctionList
    .map(x => Object.values(x))
    .flat()
    .map(x => nativeArgs.call(x))

  const EXPECTED_RESULT = [
    '[ anotherCall_NativeArg_0, anotherCall_NativeArg_1 ]',
    '[ testMethod_NativeArg_0, testMethod_NativeArg_1 ]',
  ]
  t.deepEqual(result, EXPECTED_RESULT, 'should list the native arg names correctly.')
})
