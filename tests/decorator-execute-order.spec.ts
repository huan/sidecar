#!/usr/bin/env ts-node
/**
 * Huan(202106) see:
 *  http://blog.wolksoftware.com/decorators-metadata-reflection-in-typescript-from-novice-to-expert-part-4
 */
import { test } from 'tstest'

import 'reflect-metadata'

test('decorator execute order', async t => {
  const orderList = [] as string[]

  const decorateClass    = (..._: any[]) => { orderList.push('class') }
  const decorateMethod   = (..._: any[]) => { orderList.push('method') }
  const decorateParam    = (..._: any[]) => { orderList.push('param') }
  const decorateProperty = (..._: any[]) => { orderList.push('property') }

  @decorateClass
  class Test {

    @decorateProperty _: any
    @decorateProperty _2: any

    @decorateMethod method (
      @decorateParam _: any,
    ) {}

    @decorateMethod method2 (
      @decorateParam _: any,
      @decorateParam _2: any,
    ) {}

  }
  void Test

  const EXPECTED_ORDER_LIST = [
    'property',
    'property',
    'param',
    'method',
    'param',
    'param',
    'method',
    'class',
  ]
  t.deepEqual(orderList, EXPECTED_ORDER_LIST, 'should get the expected execute order of decorators')
})
