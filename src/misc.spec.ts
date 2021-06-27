#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { NativeType } from './frida'

import {
  isInstance,
  toNativeTypeList,
}                 from './misc'

test('isInstance()', async t => {
  class Test {}
  const test = new Test()

  t.false(isInstance(Test), 'should identify static Class is not an instance')
  t.true(isInstance(test), 'should identify class instance to be an instance')
})

test('toNativeType()', async t => {
  const DESIGN_NATIVE_PAIR_LIST:[
    any,      // design type
    string,   // native type
    boolean,  // expected match result
  ][] = [
    [String, 'pointer', true],
    [Boolean, 'bool', true],
    [Number, 'int', true],
    [undefined, 'void', true],

    [String, 'char', false],
    [undefined, 'char', false],
    [Number, 'pointer', false],
    [Boolean, 'int', false],
  ]

  for (const [designType, nativeType, shouldMatch] of DESIGN_NATIVE_PAIR_LIST) {
    const nativeTypeList = toNativeTypeList(designType)
    const isMatch = nativeTypeList.includes(nativeType as NativeType)
    t.equal(isMatch, shouldMatch, `should ${shouldMatch ? '' : 'not'} match the native type(${nativeType}) to design type(${designType?.name})`)
  }
})
