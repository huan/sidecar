#!/usr/bin/env ts-node
import { test }  from 'tstest'

import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../partial-lookup'

import { getSidecarMetadataFixture } from '../../../tests/fixtures/sidecar-metadata.fixture'

import { wrapView } from '../../wrappers/mod'

test('native-functions.mustache', async t => {

  const SIDECAR_METADATA = getSidecarMetadataFixture()

  const view = wrapView(SIDECAR_METADATA)

  // console.log(view.nativeFunctionList)
  const template = await partialLookup('native-functions.mustache')

  // console.log(template)
  const result = Mustache.render(template, view)

  /**
   * Huan(202106): how could we test this script has been correctly generated?
   */
  t.true(result, 'should render to the right script (TBW)')
})
