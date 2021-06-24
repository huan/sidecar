#!/usr/bin/env ts-node

import { test }       from 'tstest'
import { expectType } from 'tsd'

import {
  ScriptMessageHandler,
  TargetType,
  NativeType,
  PointerType,
}                       from './frida'

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
  const type: TargetType = '' as any
  expectType<number | string>(type)
  t.pass('TargetType should be typing right')
})

test('ScriptMessageHandler typing', async t => {
  const handler: Parameters<ScriptMessageHandler>[1] = {} as any
  expectType<Buffer | null>(handler)
  t.pass('ScriptMessageHandler should be typing right')
})
