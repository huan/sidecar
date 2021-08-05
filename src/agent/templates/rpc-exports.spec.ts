#!/usr/bin/env ts-node
/* eslint-disable camelcase */
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
    __sidecar__agentMethod_Function_wrapper   : () => {},
    __sidecar__anotherCall_Function_wrapper   : () => {},
    __sidecar__pointerMethod_Function_wrapper : () => {},
    __sidecar__testMethod_Function_wrapper    : () => {},
    __sidecar__voidMethod_Function_wrapper    : () => {},
    rpc: {
      exports: {},
    },
  }

  vm.createContext(context) // Contextify the object.
  vm.runInContext(code, context)
  t.true('testMethod'     in context.rpc.exports, 'should export testMethod')
  t.true('pointerMethod'  in context.rpc.exports, 'should export pointerMethod')
  t.true('anotherCall'    in context.rpc.exports, 'should export anotherCall')
  t.true('agentMethod'    in context.rpc.exports, 'should export agentCall')

  /**
   * Do not export Hook/Interceptor methods
   */
  t.false('hookMethod' in context.rpc.exports, 'should not export hookMethod')
})
