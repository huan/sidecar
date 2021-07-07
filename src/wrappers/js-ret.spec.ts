#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../tests/fixtures/sidecar-metadata.fixture'
import { jsRet } from './js-ret'

test('jsRet()', async t => {
  const SIDECAR_VIEW = getSidecarMetadataFixture()

  const nativeFunctionList = SIDECAR_VIEW.nativeFunctionList.map(x => Object.values(x)).flat()

  const EXPECTED_RET_LIST = [
    'ret.readPointer().readInt()',
    'ret.readPointer().readUtf8String()',
  ]

  const result = nativeFunctionList
    .map(x => jsRet.call(x))

  // console.log(result)
  t.deepEqual(result, EXPECTED_RET_LIST, 'should wrap the ret correct')
})
