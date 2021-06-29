#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import {
  nativeParamTypes,
}                       from './native-param-types'

test('nativeParamTypes()', async t => {

  const fixture = getSidecarViewFixture()

  // console.log(JSON.stringify(fixture.nativeFunctionList, null, 2))
  const result = fixture.nativeFunctionList.map(x => nativeParamTypes.call(x))
  // console.log(result)
  const EXPECTED_RESULT = [
    "'pointer', 'pointer'",
    "'pointer', 'int'",
  ]
  t.deepEqual(result, EXPECTED_RESULT, 'should list the native param types correctly.')
})
