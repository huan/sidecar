#!/usr/bin/env ts-node
import { test }  from 'tstest'

import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../partial-lookup'

import { getSidecarViewFixture } from '../../../tests/fixtures/sidecar-view.fixture'

import { wrapView } from '../../wrappers/mod'

test('native-functions.mustache', async t => {

  const SIDECAR_VIEW = getSidecarViewFixture()

  const view = wrapView(SIDECAR_VIEW)

  // console.log(view.nativeFunctionList)
  const template = await partialLookup('agent.mustache')

  // console.log(template)
  const result = Mustache.render(
    template,
    {
      ...view,
      initAgentSource: 'console.log("hello")',
    },
    partialLookup,
  )
  // console.log(result)

  /**
   * Huan(202106): how could we test this script has been correctly generated?
   */
  t.true(result, 'should render to the right script (TBW)')
})
