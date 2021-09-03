#!/usr/bin/env -S node --no-warnings --loader ts-node/esm
import { test }  from 'tstest'

import {
  isInstance,
}                 from './misc.js'

test('isInstance()', async t => {
  class Test {}
  const test = new Test()

  t.false(isInstance(Test), 'should identify static Class is not an instance')
  t.true(isInstance(test), 'should identify class instance to be an instance')
})
