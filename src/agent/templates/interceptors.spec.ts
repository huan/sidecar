#!/usr/bin/env ts-node
import { test }  from 'tstest'

import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../partial-lookup'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import { wrapView } from '../../wrappers/mod'

test('interceptors.mustache', async t => {

  const SIDECAR_VIEW = getSidecarViewFixture()

  const view = wrapView(SIDECAR_VIEW)

  // console.log(JSON.stringify(view.interceptorList, null, 2))
  const template = await partialLookup('interceptors.mustache')

  // console.log(template)
  const result = Mustache.render(template, view)
  // console.log(result)

  /**
   * Huan(202106): how could we test this script has been correctly generated?
   */
  t.true(result, 'should render to the right script (TBW)')
})
