#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { Sidecar } from './sidecar'

test('@Sidecar()', async t => {

  @Sidecar() class Test {}

  const test = new Test()

  t.equal(Test.name, 'Test', 'should have the original class name after @Sidecar decorated')
  t.true(test, 'should instanciate decorated class successfully')
})
