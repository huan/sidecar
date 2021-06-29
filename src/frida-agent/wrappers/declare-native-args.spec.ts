#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import {
  declareNativeArgs,
}                       from './declare-native-args'

test('declareNativeArgs()', async t => {

  const fixture = getSidecarViewFixture()

  console.log(fixture.nativeFunctionList.length)
  const result = fixture.nativeFunctionList.map(x => declareNativeArgs.call(x))
  // const result = declareNativeArgs.call(SIDECAR_VIEW.nativeFunctionList[0])
  // console.log('###', fixture.nativeFunctionList[0])
  // console.log(result[0])

  /**
   * Huan(202106) FIXME: find a way to check the generated script
   */
  t.true(result, 'should declare the native args correctly. (TBD)')
})
