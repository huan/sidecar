#!/usr/bin/env ts-node
/**
 * Huan(202106) see:
 *  http://blog.wolksoftware.com/decorators-metadata-reflection-in-typescript-from-novice-to-expert-part-4
 */
import { test } from 'tstest'

import 'reflect-metadata'

test('decorator execute order', async t => {
  const orderList = [] as string[]

  const decorateClass    = (target: any, ..._: any[]) => { orderList.push('class:' + target.name) }
  const decorateMethod   = (_: any, key: string, ..._args: any[]) => { orderList.push('method:' + key) }
  const decorateParam    = (_: any, key: string, index: number) => { orderList.push('param:' + key + '/' + index) }
  const decorateProperty = (_: any, key: string) => { orderList.push('property:' + key) }

  @decorateClass
  class Test {

    @decorateProperty _prop1: any
    @decorateProperty _prop2: any

    @decorateMethod method1 (
      @decorateParam _arg: any,
    ) {}

    @decorateMethod method2 (
      @decorateParam _arg1: any,
      @decorateParam _arg2: any,
    ) {}

  }
  void Test

  const EXPECTED_ORDER_LIST = [
    'property:_prop1',
    'property:_prop2',
    'param:method1/0',
    'method:method1',
    'param:method2/1',
    'param:method2/0',
    'method:method2',
    'class:Test',
  ]
  t.deepEqual(orderList, EXPECTED_ORDER_LIST, 'should get the expected execute order of decorators')
})
