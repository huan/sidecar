#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { NativeType } from '../../frida'

import {
  guardParamType,
}                         from './guard-param-type'

test('guard parame type', async t => {

  const d = (..._args: any[]) => {}

  class Test {

    @d
    method (s: string): void {
      void s
    }

  }

  const test = new Test()

  const EXPECTED_RESULTS: [
    NativeType,
    boolean,
  ][] = [
    ['int', false],
    ['pointer', true],
  ]

  for (const [nativeType, shouldMatch] of EXPECTED_RESULTS) {
    if (shouldMatch) {
      guardParamType(
        test,
        'method',
        0,
        [nativeType],
      )
      t.pass('should not throw for nativeType: ' + nativeType)
    } else {
      t.throws(() => guardParamType(
        test,
        'method',
        0,
        [nativeType],
      ), 'should throw for nativeType: ' + nativeType)
    }
  }
})
