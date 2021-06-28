#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { updateClassName } from './update-class-name'

test('updateClassName()', async t => {

  class Test {}
  const NAME = 'NewTest'

  updateClassName(Test, NAME)

  t.equal(Test.name, NAME, 'should change the class name successfully')
})
