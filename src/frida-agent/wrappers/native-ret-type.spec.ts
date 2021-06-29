#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import {
  nativeRetType,
}                       from './native-ret-type'

test('nativeRetType()', async t => {

  const fixture = getSidecarViewFixture()

  // console.log(JSON.stringify(fixture.nativeFunctionList, null, 2))
  const result = fixture.nativeFunctionList.map(x => nativeRetType.call(x))
  // console.log(result)
  const EXPECTED_RESULT = [
    "'pointer'",
    "'pointer'",
  ]
  t.deepEqual(result, EXPECTED_RESULT, 'should list the native ret type correctly.')
})
