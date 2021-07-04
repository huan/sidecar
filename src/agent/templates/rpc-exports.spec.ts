#!/usr/bin/env ts-node
import { test }  from 'tstest'

import vm from 'vm'
import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../partial-lookup'

import { getSidecarMetadataFixture } from '../../../tests/fixtures/sidecar-metadata.fixture'
import { wrapView } from '../../wrappers/mod'

test('render rpc-exports()', async t => {

  const SIDECAR_METADATA = getSidecarMetadataFixture()
  const view = wrapView(SIDECAR_METADATA)

  const template = await partialLookup('rpc-exports.mustache')

  // console.log(template)
  const code = Mustache.render(template, view)
  // console.log(code)

  /**
   * https://nodejs.org/api/vm.html
   */
  const context = {
    anotherCall_NativeFunction_wrapper: () => {},
    rpc: {
      exports: {},
    },
    testMethod_NativeFunction_wrapper: () => {},
  }

  vm.createContext(context) // Contextify the object.
  vm.runInContext(code, context)
  t.true('testMethod' in context.rpc.exports, 'should export testMethod')
  t.true('anotherCall' in context.rpc.exports, 'should export anotherCall')

  /**
   * Do not export Hook/Interceptor methods
   */
  t.false('hookMethod' in context.rpc.exports, 'should not export hookMethod')
})
