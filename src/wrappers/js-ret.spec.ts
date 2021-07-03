#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarViewFixture } from '../../tests/fixtures/sidecar-view.fixture'
import { jsRet } from './js-ret'

test('jsRet()', async t => {
  const SIDECAR_VIEW = getSidecarViewFixture()

  const nativeFunctionList = SIDECAR_VIEW.nativeFunctionList

  const EXPECTED_RET_LIST = [
    'ret.readPointer().readInt()',
    'ret.readPointer().readUtf8String()',
  ]

  const result = nativeFunctionList
    .map(x => jsRet.call(x))

  // console.log(result)
  t.deepEqual(result, EXPECTED_RET_LIST, 'should wrap the ret correct')
})
