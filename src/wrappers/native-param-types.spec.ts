#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'

import {
  nativeParamTypes,
}                       from './native-param-types'

test('nativeParamTypes()', async t => {

  const fixture = getSidecarMetadataFixture()

  // console.log(JSON.stringify(fixture.nativeFunctionList, null, 2))
  const result = fixture.nativeFunctionList
    .map(x => Object.values(x))
    .flat()
    .map(x => nativeParamTypes.call(x))

  // console.log(result)
  const EXPECTED_RESULT = [
    "'pointer', 'pointer'",
    "'pointer', 'int'",
    "'pointer'",
    '',
  ]
  t.deepEqual(result, EXPECTED_RESULT, 'should list the native param types correctly.')
})
