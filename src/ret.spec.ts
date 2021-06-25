#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  RET_SYMBOL,
  Ret,
}                         from './ret'

test('Ret()', async t => {
  const r = Ret()
  t.equal(r, RET_SYMBOL, 'should return RET_SYMBOL by calling Ret()')
})
