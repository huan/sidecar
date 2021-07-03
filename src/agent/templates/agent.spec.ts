#!/usr/bin/env ts-node
import { test }  from 'tstest'

import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../partial-lookup'

import { ChatboxSidecar } from '../../../examples/chatbox-sidecar'

import { wrapView } from '../../wrappers/mod'
import { getMetadataSidecar } from '../../decorators/sidecar/metadata-sidecar'

test('agent.mustache', async t => {

  const view = getMetadataSidecar(ChatboxSidecar)

  // console.log(JSON.stringify(view, null, 2))
  const wrappedView = wrapView(view!)

  // console.log(JSON.stringify(wrappedView, null, 2))
  // console.log(Object.keys(wrappedView))
  const template = await partialLookup('agent.mustache')

  // console.log(template)
  const result = Mustache.render(
    template,
    {
      ...wrappedView,
      initAgentSource: 'console.log("hello")',
    },
    partialLookup,
  )
  // console.log('result:', result)

  /**
   * Huan(202106): how could we test this script has been correctly generated?
   */
  t.true(result, 'should render to the right script (TBW)')
})
