#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  bufName,
}                       from './name-helpers'

test('bufName()', async t => {

  const TEST_LIST: [[string, number, number?], string][] = [
    [
      ['test', 0, 1],
      'test_Memory_0_1',
    ],
    [
      ['demo', 3],
      'demo_Memory_3',
    ],
  ]

  for (const [args, expected] of TEST_LIST) {
    const name = bufName(...args)
    t.equal(name, expected, 'should get the expected name from bufName()')
  }
})
