#!/usr/bin/env -S node --no-warnings --loader ts-node/esm
/**
 * Huan(202106) see:
 *  http://blog.wolksoftware.com/decorators-metadata-reflection-in-typescript-from-novice-to-expert-part-4
 *
 * Another great blog post with the decorator runtime order tests:
 *  https://medium.com/jspoint/anatomy-of-typescript-decorators-and-their-usage-patterns-487729b34ae6
 */
import { test } from 'tstest'

test('decorator execute order', async t => {
  const orderList = [] as string[]

  // arguments.length === 1
  const decorateClass    = (target: Function) => { orderList.push('class:' + target.name) }
  // arguments.length === 2
  const decorateProperty = (_target: Object, propertyKey: string) => { orderList.push('property:' + propertyKey) }
  // arguments.length === 3 && typeof arguments[2] === 'number'
  const decorateParam    = (_target: Object, methodKey: string, index: number) => { orderList.push('param:' + methodKey + '/' + index) }
  // arguments.length === 3 && typeof arguments[2] === 'object'
  const decorateMethod   = (_target: Object, methodKey: string, _descriptor: any) => { orderList.push('method:' + methodKey) }

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

  /**
   * Huan(202106): Decorator Evaluation
   *  There is a well defined order to how decorators applied to
   *  various declarations inside of a class are applied:
   *    https://www.typescriptlang.org/docs/handbook/decorators.html#decorator-evaluation
   */
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
  t.same(orderList, EXPECTED_ORDER_LIST, 'should get the expected execute order of decorators')
})
