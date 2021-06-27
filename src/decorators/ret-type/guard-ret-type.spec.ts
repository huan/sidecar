#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { NativeType } from '../../frida'

import {
  guardRetType,
}                         from './guard-ret-type'

test('guard parame type', async t => {

  const d = (..._args: any[]) => {}

  class Test {

    @d
    method (): string {
      return ''
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
      guardRetType(
        test,
        'method',
        nativeType,
      )
      t.pass('should not throw for nativeType: ' + nativeType)
    } else {
      t.throws(() => guardRetType(
        test,
        'method',
        nativeType,
      ), 'should throw for nativeType: ' + nativeType)
    }
  }
})
