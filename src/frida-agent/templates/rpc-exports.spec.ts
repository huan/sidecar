#!/usr/bin/env ts-node
import { test }  from 'tstest'

import vm from 'vm'
import Mustache from  'mustache'

import {
  partialLookup,
}                         from '../loaders/partial-lookup'

import { FIXTURE } from '../views/sidecar-view.spec'

test('render rpc-exports()', async t => {

  const template = await partialLookup('rpc-exports.mustache')

  // console.log(template)
  const code = Mustache.render(template, FIXTURE.view)
  // console.log(code)

  /**
   * https://nodejs.org/api/vm.html
   */
  const context = {
    anotherCallNativeFunction_wrapper: () => {},
    rpc: {
      exports: {},
    },
    testMethodNativeFunction_wrapper: () => {},
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
