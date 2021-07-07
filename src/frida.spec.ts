#!/usr/bin/env ts-node

import { test }       from 'tstest'
import { expectType } from 'tsd'

import {
  ScriptMessageHandler,
  FunctionTargetLink,
  NativeType,
  PointerType,
  normalizeFunctionTarget,
  FunctionTarget,
  FunctionTargetWrapper,
}                           from './frida'

test('PointerType typing', async t => {
  type EXPECTED_TYPE = 'Pointer' | 'Int' | 'Utf8String'
  type T = Extract<PointerType, EXPECTED_TYPE>
  const type: T = {} as any
  expectType<EXPECTED_TYPE>(type)
  t.pass('PointerType should be typing right')
})

test('NativeType typing', async t => {
  type EXPECTED_TYPE = 'void' | 'pointer' | 'int'
  type T = Extract<NativeType, EXPECTED_TYPE>
  const type: T = '' as any
  expectType<EXPECTED_TYPE>(type)
  t.pass('NativeType should be typing right')
})

test('TargetType typing', async t => {
  const type: FunctionTargetLink = '' as any
  expectType<number | string>(type)
  t.pass('TargetType should be typing right')
})

test('ScriptMessageHandler typing', async t => {
  const handler: Parameters<ScriptMessageHandler>[1] = {} as any
  expectType<Buffer | null>(handler)
  t.pass('ScriptMessageHandler should be typing right')
})

test('normalizeFunctionTarget()', async t => {
  const TEST_LIST: [
    FunctionTarget,
    FunctionTargetWrapper,
  ][] = [
    [
      'stringTarget',
      { target: 'stringTarget', type: 'name' },
    ],
    [
      0x42,
      { target: '0x42', type: 'address' },
    ],
    [
      { target: 'NSString', type: 'objc' },
      { target: 'NSString', type: 'objc' },
    ],
  ]

  const result    = TEST_LIST.map(pair => pair[0]).map(normalizeFunctionTarget)
  const expected  = TEST_LIST.map(pair => pair[1])

  t.deepEqual(result, expected, 'should normalize function target as expected')
})
